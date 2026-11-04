use std::sync::atomic::{AtomicU64, Ordering};

/// Put dummy test material in a file so CLI tests use the same input as scripts.
pub fn payload_file(value: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "payload-{}-{}.txt",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, value).expect("write dummy CLI payload");
    path.to_str().expect("UTF-8 test path").to_owned()
}
