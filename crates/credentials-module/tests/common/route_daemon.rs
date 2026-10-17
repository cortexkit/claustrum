//! A fake subc daemon for tests that drive `ck auth`'s capability read
//! (`credential_client::get_online`) without a real daemon: it writes a connection
//! file, completes the client handshake, answers one `route.open` and one
//! `credential.get` with a canned body, and records what it was sent.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

/// A running fake daemon. Dereferences to its connection-file path; dropping it
/// stops the daemon thread and surfaces any assertion that failed inside it.
pub struct TestDaemon {
    pub connection: PathBuf,
    pub shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub join: Option<std::thread::JoinHandle<()>>,
}

impl Deref for TestDaemon {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            join.join().expect("fake daemon thread panicked");
        }
    }
}

pub fn spawn_route_daemon(
    root: &Path,
    observed: Arc<Mutex<Vec<String>>>,
    response: Value,
) -> TestDaemon {
    spawn_route_daemon_recording(root, observed, Arc::default(), response)
}

/// [`spawn_route_daemon`], additionally keeping the full `route.open` body it receives
/// in `opened`.
pub fn spawn_route_daemon_recording(
    root: &Path,
    observed: Arc<Mutex<Vec<String>>>,
    opened: Arc<Mutex<Option<Value>>>,
    response: Value,
) -> TestDaemon {
    use subc_protocol::{Flags, Frame, FrameType, Priority};
    use subc_transport::{
        authenticate_server, connection_file, read_frame, write_frame, ConnectionInfo, Endpoint,
    };

    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let key = vec![9; 32];
    let daemon_id = [4; 16];
    let conn = root.join("subc-connection.json");
    connection_file::write_atomic(
        &conn,
        &ConnectionInfo {
            schema: connection_file::SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![Endpoint {
                host: "127.0.0.1".into(),
                port,
            }],
            key: key.clone(),
            daemon_id,
            pid: std::process::id(),
            daemon_ver: "test".into(),
        },
    )
    .expect("connection file");

    let (shutdown, mut stopped) = tokio::sync::oneshot::channel();
    let join = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (mut stream, _) = tokio::select! {
                _ = &mut stopped => return,
                accepted = listener.accept() => accepted.expect("accept"),
            };
            authenticate_server(
                &mut stream,
                &key,
                &daemon_id,
                "test",
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("handshake");

            let open = read_frame(&mut stream)
                .await
                .expect("read route open")
                .expect("route frame");
            let open_body: Value = serde_json::from_slice(&open.body).expect("route open json");
            *opened.lock().expect("opened") = Some(open_body.clone());
            observed
                .lock()
                .expect("methods")
                .push(open_body["op"].as_str().unwrap_or_default().to_string());
            let route = Frame::build(
                FrameType::Response,
                Flags::new(false, Priority::Passive, false),
                0,
                0,
                open.header.corr,
                serde_json::to_vec(&json!({"route_channel": 7, "route_epoch": 3})).unwrap(),
            )
            .unwrap();
            write_frame(&mut stream, &route)
                .await
                .expect("write route open");

            let get = read_frame(&mut stream)
                .await
                .expect("read credential get")
                .expect("get frame");
            let get_body: Value = serde_json::from_slice(&get.body).expect("credential get json");
            observed
                .lock()
                .expect("methods")
                .push(get_body["method"].as_str().unwrap_or_default().to_string());
            assert_eq!(get_body["method"], "credential.get");
            assert_eq!(get_body["params"]["handle"], "ckh_owned_capability");
            assert_eq!(get_body["params"]["force_refresh"], false);
            assert_eq!(get_body["params"]["min_ttl_ms"], 0);
            let reply = Frame::build(
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                7,
                3,
                get.header.corr,
                serde_json::to_vec(&response).unwrap(),
            )
            .unwrap();
            write_frame(&mut stream, &reply)
                .await
                .expect("write get response");
        });
    });
    TestDaemon {
        connection: conn,
        shutdown: Some(shutdown),
        join: Some(join),
    }
}
