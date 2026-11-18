use crate::Secret;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct Request<P> {
    pub(super) method: &'static str,
    pub(super) params: P,
}

pub(super) fn encode_request(
    method: &'static str,
    params: impl Serialize,
) -> serde_json::Result<Secret<Vec<u8>>> {
    struct Size(usize);
    impl std::io::Write for Size {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let request = Request { method, params };
    // Size first so the serialized buffer never reallocates and leaves a copy
    // of secret data in the old allocation.
    let mut size = Size(0);
    serde_json::to_writer(&mut size, &request)?;
    let mut bytes = Secret::new(Vec::with_capacity(size.0));
    serde_json::to_writer(bytes.expose_mut(), &request)?;
    Ok(bytes)
}
