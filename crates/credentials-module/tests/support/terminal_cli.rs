//! Drive a real controlling terminal for interactive CLI tests.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Wait for each prompt before sending its answer. Hidden answers also wait for
/// terminal echo to be disabled, so the harness cannot echo a value before the
/// password widget has started reading it.
pub fn run(mut command: Command, steps: &[(&str, &[u8], bool)]) -> (ExitStatus, String) {
    let (mut master_fd, mut slave_fd) = (-1, -1);
    // SAFETY: both output pointers are valid; optional arguments request defaults.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0,
        "openpty: {}",
        io::Error::last_os_error()
    );
    // SAFETY: openpty returned two distinct owned descriptors.
    let (mut master, slave) =
        unsafe { (File::from_raw_fd(master_fd), File::from_raw_fd(slave_fd)) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        // SAFETY: fd is owned by a live File.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            -1
        );
    }
    // SAFETY: master is an open blocking PTY descriptor with no other status flags.
    assert_ne!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        -1
    );
    command
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: after fork only async-signal-safe calls and nonallocating error
    // bookkeeping run. Stdin is already attached to the slave.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn terminal CLI");
    // Command retains Stdio handles after spawn; release all parent slave copies.
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut bytes = Vec::new();
    let mut step = 0;
    let mut written = 0;
    let mut prompt_start = 0;
    let mut status = None;
    loop {
        let mut buffer = [0; 4096];
        let eof = match master.read(&mut buffer) {
            Ok(0) => true,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                false
            }
            // Linux reports EIO when the last slave closes; macOS reports EOF.
            Err(error) if error.raw_os_error() == Some(libc::EIO) => true,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                false
            }
            Err(error) => panic!("read PTY: {error}"),
        };
        if status.is_none() {
            status = child.try_wait().expect("poll terminal CLI");
        }
        if status.is_some() {
            if eof {
                break;
            }
        } else if Instant::now() >= deadline {
            child.kill().expect("kill stuck terminal CLI");
            status = Some(child.wait().expect("reap stuck terminal CLI"));
        } else if let Some((prompt, answer, hidden)) = steps.get(step) {
            let seen = String::from_utf8_lossy(&bytes[prompt_start..]).contains(prompt);
            let echo_off = if *hidden {
                let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
                // SAFETY: master is open and termios points to writable storage.
                assert_eq!(
                    unsafe { libc::tcgetattr(master.as_raw_fd(), termios.as_mut_ptr()) },
                    0
                );
                // SAFETY: successful tcgetattr initialized termios.
                unsafe { termios.assume_init() }.c_lflag & libc::ECHO == 0
            } else {
                true
            };
            if seen && echo_off {
                match master.write(&answer[written..]) {
                    Ok(n) => {
                        written += n;
                        if written == answer.len() {
                            step += 1;
                            written = 0;
                            prompt_start = bytes.len();
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => panic!("write PTY: {error}"),
                }
            }
        }
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized descriptor. The timeout only
        // bounds waiting when a prompt has printed but echo has not yet changed.
        let result = unsafe { libc::poll(&mut poll, 1, 25) };
        assert!(result >= 0 || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted);
    }
    (
        child.wait().expect("reap terminal CLI"),
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}
