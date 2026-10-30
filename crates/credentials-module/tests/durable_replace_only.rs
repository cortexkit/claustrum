#![forbid(unsafe_code)]
//! No shipped Rust source in this workspace calls `fs::rename(` except the lines in
//! [`ALLOWED`].
//!
//! Every "write a temp file, then rename it over the destination" publish must go
//! through `cortexkit_lease::durable_replace`. A plain rename is atomic but not durable
//! on Windows: a power loss after it returns can lose the new directory entry, and
//! Windows has no directory fsync to close that gap. `durable_replace` uses MoveFileExW
//! with write-through there, and rename plus a directory fsync on Unix. A new bare
//! rename compiles and passes every functional test, so only a source scan catches it.
//!
//! The scan is deliberately line-based, like `no_shipped_source_reads_the_launch_nonce_directly`
//! in `src/main.rs`: each line of every `crates/*/src` tree is cut at `//` and the code
//! part is checked. Test code that lives under `src/` is listed in [`ALLOWED`] rather
//! than parsed out, so the scanner stays simple enough to trust by reading.

/// Lines allowed to call `fs::rename(`, as (workspace-relative file, exact trimmed
/// line). Each entry must match exactly one line, so a moved or removed site makes the
/// list fail instead of quietly allowing a new rename elsewhere.
const ALLOWED: &[(&str, &str)] = &[
    // Test code (a #[cfg(test)] module file): moves a fixture file aside on purpose.
    (
        "crates/credentials-module/src/account_token_tests.rs",
        "std::fs::rename(&path, rig.root.join(\"real.json\")).unwrap();",
    ),
];

/// The trimmed code part of each line of `text` that calls `fs::rename(`.
fn offending(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let code = line.split("//").next().unwrap_or("");
            code.contains("fs::rename(")
        })
        .map(|line| line.trim().to_string())
        .collect()
}

#[test]
fn shipped_code_replaces_files_only_through_durable_replace() {
    // Positive control: the scanner must be able to say yes, or a clean result means
    // nothing. A commented-out call is not a call.
    assert_eq!(offending("std::fs::rename(&a, &b);").len(), 1);
    assert_eq!(offending("let r = fs::rename(x, y);").len(), 1);
    assert!(offending("// std::fs::rename(&a, &b);").is_empty());
    assert!(offending("let ok = true; // fs::rename(x, y)").is_empty());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut stack = Vec::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates directory") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            stack.push(src);
        }
    }
    let mut scanned = 0usize;
    let mut found = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                scanned += 1;
                let text = std::fs::read_to_string(&path).expect("read source");
                let relative = path
                    .strip_prefix(&root)
                    .expect("source under the workspace root")
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                found.extend(offending(&text).into_iter().map(|l| (relative.clone(), l)));
            }
        }
    }
    assert!(
        scanned > 50,
        "the scan must actually visit the source trees (visited {scanned})"
    );

    let unexpected: Vec<String> = found
        .iter()
        .filter(|(file, line)| !ALLOWED.iter().any(|(f, l)| f == file && l == line))
        .map(|(file, line)| format!("{file}: {line}"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "replace a file with cortexkit_lease::durable_replace(temp, dest), not a bare \
         rename, so the replace survives a power loss on Windows too. If this is not a \
         file publish (like the manifest lock's directory renames), add it to ALLOWED \
         with the reason:\n{}",
        unexpected.join("\n")
    );
    for (file, line) in ALLOWED {
        let hits = found.iter().filter(|(f, l)| f == file && l == line).count();
        assert_eq!(
            hits, 1,
            "ALLOWED entry {file}: {line} must match exactly one line; update ALLOWED when \
             that code moves or goes away"
        );
    }
}
