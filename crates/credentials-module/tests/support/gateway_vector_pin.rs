fn pin_gateway_vectors(produced: &[(&str, Vec<u8>)]) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let digest = |bytes: &[u8]| -> String {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    let owned = |entry: &str| {
        produced
            .iter()
            .any(|(name, _)| entry.ends_with(&format!("  {name}")))
    };
    let mut lines: Vec<String> = produced
        .iter()
        .map(|(name, bytes)| format!("{}  {name}", digest(bytes)))
        .collect();
    lines.sort_by(|a, b| a.split_once("  ").unwrap().1.cmp(b.split_once("  ").unwrap().1));
    let sums_path = directory.join("SHA256SUMS");
    let sums = std::fs::read_to_string(&sums_path).expect("pinned vector hashes");
    if std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1") {
        for (name, bytes) in produced {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        // Each generator owns only its files' entries; preserve other producers' hashes.
        let mut all: Vec<_> = sums
            .lines()
            .filter(|entry| !owned(entry))
            .map(str::to_owned)
            .chain(lines)
            .collect();
        all.sort_by(|a, b| a.split_once("  ").unwrap().1.cmp(b.split_once("  ").unwrap().1));
        std::fs::write(sums_path, format!("{}\n", all.join("\n"))).unwrap();
    } else {
        for (name, bytes) in produced {
            assert_eq!(
                bytes,
                &std::fs::read(directory.join(name)).expect("pinned gateway vector"),
                "gateway wire bytes changed: {name}"
            );
        }
        assert_eq!(
            sums.lines().filter(|entry| owned(entry)).collect::<Vec<_>>(),
            lines,
            "SHA256SUMS must list each produced file exactly once with its hash"
        );
    }
    for line in produced.iter().map(|(name, bytes)| format!("{}  {name}", digest(bytes))) {
        println!("{line}");
    }
}
