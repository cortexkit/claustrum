#![forbid(unsafe_code)]
//! No shipped Rust source in this workspace calls `std::fs::rename` directly, except the
//! OpenCode manifest lock protocol's directory renames listed in [`ALLOWED`].
//!
//! Every "write a temp file, then rename it over the destination" publish must go
//! through `cortexkit_lease::durable_replace`. A plain rename is atomic but not durable
//! on Windows: a power loss after it returns can lose the new directory entry, and
//! Windows has no directory fsync to close that gap. `durable_replace` uses MoveFileExW
//! with write-through there, and rename plus a directory fsync on Unix. A new bare
//! rename compiles and passes every functional test, so only a source scan catches it.
//!
//! The lock protocol renames are different: they move the lock DIRECTORY aside to claim
//! or release it, and must fail when the target exists, which a replace would not.
//!
//! Scope: every `crates/*/src` tree. `tests/` directories are not scanned, and neither
//! is code gated on `#[cfg(test)]` or `#[cfg(all(test, ...))]`, nor any source file that
//! is only reachable through such a gated `mod` declaration. Comments and string
//! literals are ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Shipped renames that are not file publishes, as (workspace-relative file, exact
/// trimmed source line). Each entry must match exactly one line, so a removed or
/// edited site makes this list fail rather than silently allow a new rename.
const ALLOWED: &[(&str, &str)] = &[
    // Releasing the manifest lock: move our lock directory aside before removing it,
    // and put it back if it turned out not to be ours.
    (
        "crates/credentials-module/src/bin/cli_support/opencode_files.rs",
        "if fs::rename(lock, &release).is_err() {",
    ),
    (
        "crates/credentials-module/src/bin/cli_support/opencode_files.rs",
        "let _ = fs::rename(&release, lock);",
    ),
    // Evicting a stale manifest lock: move it to a quarantine name, and put it back if
    // a different owner was moved by mistake.
    (
        "crates/credentials-module/src/bin/cli_support/opencode_files.rs",
        "let rename_result = fs::rename(&lock, &stale);",
    ),
    (
        "crates/credentials-module/src/bin/cli_support/opencode_files.rs",
        "let _ = fs::rename(&stale, &lock);",
    ),
];

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

fn blank(bytes: &mut [u8]) {
    for byte in bytes {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// End (exclusive) of a raw string literal (`r"..."`, `r#"..."#`, `br#"..."#`) that
/// starts at `start`, or `None` if none starts there.
fn raw_string_end(source: &[u8], start: usize) -> Option<usize> {
    if start > 0 && is_ident(source[start - 1]) {
        return None;
    }
    let mut at = start;
    if matches!(source.get(at), Some(b'b' | b'c')) {
        at += 1;
    }
    if source.get(at) != Some(&b'r') {
        return None;
    }
    at += 1;
    let hashes = source[at..]
        .iter()
        .take_while(|&&byte| byte == b'#')
        .count();
    at += hashes;
    if source.get(at) != Some(&b'"') {
        return None;
    }
    let mut closing = vec![b'"'];
    closing.extend(std::iter::repeat_n(b'#', hashes));
    find(source, &closing, at + 1).map(|position| position + closing.len())
}

/// End (exclusive) of a char literal starting at the quote at `start`, or `None`
/// when the quote begins a lifetime such as `'a`.
fn char_literal_end(source: &[u8], start: usize) -> Option<usize> {
    if source.get(start + 1) == Some(&b'\\') {
        // An escape: the closing quote is the first one after the escaped character.
        return find(source, b"'", start + 3).map(|position| position + 1);
    }
    let lead = *source.get(start + 1)?;
    let width = match lead {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (source.get(start + 1 + width) == Some(&b'\'')).then_some(start + 2 + width)
}

/// A copy of `source` with comments, string literals and char literals replaced by
/// spaces. Newlines and byte offsets are kept, so offsets and line numbers in the copy
/// point at the same place in the original.
fn code_only(source: &str) -> Vec<u8> {
    let source = source.as_bytes();
    let mut code = source.to_vec();
    let mut at = 0;
    while at < source.len() {
        let rest = &source[at..];
        let end = if rest.starts_with(b"//") {
            find(source, b"\n", at).unwrap_or(source.len())
        } else if rest.starts_with(b"/*") {
            // Block comments nest in Rust.
            let mut depth = 0;
            let mut cursor = at;
            while cursor < source.len() {
                if source[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if source[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    cursor += 1;
                }
            }
            cursor
        } else if let Some(end) = raw_string_end(source, at) {
            end
        } else if source[at] == b'"' {
            let mut cursor = at + 1;
            while cursor < source.len() && source[cursor] != b'"' {
                cursor += if source[cursor] == b'\\' { 2 } else { 1 };
            }
            (cursor + 1).min(source.len())
        } else if source[at] == b'\'' {
            match char_literal_end(source, at) {
                Some(end) => end,
                None => {
                    at += 1;
                    continue;
                }
            }
        } else {
            at += 1;
            continue;
        };
        blank(&mut code[at..end]);
        at = end;
    }
    code
}

/// Index of the bracket that closes the one at `open`.
fn matching_close(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (index, &byte) in code.iter().enumerate().skip(open) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// End (exclusive) of the item, statement, field or match arm that starts at `from`:
/// the first `;` or `,` outside brackets, the `}` that closes its first brace block,
/// or the end of the enclosing block. Stopping early at a comma (such as one in a
/// generic parameter list) only means more test code is scanned, never less shipped
/// code.
fn item_end(code: &[u8], from: usize) -> usize {
    let mut depth = 0i32;
    for (index, &byte) in code.iter().enumerate().skip(from) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => {
                depth -= 1;
                if depth < 0 {
                    return index;
                }
            }
            b'}' => {
                depth -= 1;
                if depth < 0 {
                    return index;
                }
                if depth == 0 {
                    return index + 1;
                }
            }
            b';' | b',' if depth == 0 => return index + 1,
            _ => {}
        }
    }
    code.len()
}

/// Byte ranges covered by a `#[cfg(test)]` or `#[cfg(all(test, ...))]` attribute: the
/// attribute itself through the end of the item it gates. `cfg(any(test, ...))` is
/// not test-only (a feature can enable it), so it stays in scope.
fn test_only_regions(code: &[u8]) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut at = 0;
    while let Some(start) = find(code, b"#[", at) {
        let Some(close) = matching_close(code, start + 1) else {
            break;
        };
        let attribute: String = code[start + 2..close]
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|&byte| byte as char)
            .collect();
        if attribute == "cfg(test)" || attribute.starts_with("cfg(all(test,") {
            let end = item_end(code, close + 1);
            regions.push((start, end));
            at = end;
        } else {
            at = close + 1;
        }
    }
    regions
}

/// The `#[path = "..."]` value among the attributes written just before `offset`
/// (a `mod` keyword), skipping any visibility such as `pub(crate)`.
fn path_attribute(source: &str, code: &[u8], offset: usize) -> Option<String> {
    let mut end = offset;
    let skip_space = |end: &mut usize| {
        while *end > 0 && code[*end - 1].is_ascii_whitespace() {
            *end -= 1;
        }
    };
    skip_space(&mut end);
    if end > 0 && code[end - 1] == b')' {
        let open = code[..end].iter().rposition(|&byte| byte == b'(')?;
        if code[..open].ends_with(b"pub") {
            end = open - 3;
        }
    } else if code[..end].ends_with(b"pub") {
        end -= 3;
    }
    skip_space(&mut end);
    let mut found = None;
    while end > 0 && code[end - 1] == b']' {
        let open = code[..end].iter().rposition(|&byte| byte == b'[')?;
        let text = &source[open + 1..end - 1];
        if let Some(value) = text.trim().strip_prefix("path") {
            let value = value.trim_start().strip_prefix('=')?.trim();
            found = Some(value.trim_matches('"').to_string());
        }
        end = open.checked_sub(1)?; // the `#`
        skip_space(&mut end);
    }
    found
}

/// Every out-of-line `mod NAME;` declaration in `code[from..to]`, with its
/// `#[path]` value if it has one.
fn module_declarations(
    source: &str,
    code: &[u8],
    from: usize,
    to: usize,
) -> Vec<(String, Option<String>)> {
    let mut declarations = Vec::new();
    let mut at = from;
    while let Some(offset) = find(&code[..to], b"mod", at) {
        at = offset + 3;
        if offset > 0 && is_ident(code[offset - 1]) {
            continue;
        }
        let rest = &code[at..to];
        let name_start = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if name_start == 0 {
            continue;
        }
        let name_len = rest[name_start..]
            .iter()
            .take_while(|&&b| is_ident(b))
            .count();
        let after = &rest[name_start + name_len..];
        let gap = after.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if name_len == 0 || after.get(gap) != Some(&b';') {
            continue;
        }
        let name = String::from_utf8_lossy(&rest[name_start..name_start + name_len]).into_owned();
        declarations.push((name, path_attribute(source, code, offset)));
    }
    declarations
}

/// The file a `mod` declaration in `declaring` loads. Panics if that file does not
/// exist, so a declaration the scanner cannot place is reported instead of being
/// silently scanned or skipped.
fn module_file(declaring: &Path, name: &str, path: Option<&str>) -> PathBuf {
    let directory = declaring.parent().expect("source file has a directory");
    let resolved = if let Some(path) = path {
        directory.join(path)
    } else {
        let file = declaring.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let crate_root_or_mod_rs = matches!(file, "lib.rs" | "main.rs" | "mod.rs")
            || directory.file_name().is_some_and(|d| d == "bin");
        let base = if crate_root_or_mod_rs {
            directory.to_path_buf()
        } else {
            directory.join(declaring.file_stem().expect("source file has a stem"))
        };
        let flat = base.join(format!("{name}.rs"));
        if flat.exists() {
            flat
        } else {
            base.join(name).join("mod.rs")
        }
    };
    assert!(
        resolved.exists(),
        "cannot place `mod {name};` declared in {} (looked for {}); teach this scanner \
         the module layout rather than letting the file go unclassified",
        declaring.display(),
        resolved.display()
    );
    resolved
}

/// Source files compiled only for tests: those declared by a test-gated `mod` and
/// every module declared inside them.
fn test_only_files(sources: &BTreeMap<PathBuf, String>) -> BTreeSet<PathBuf> {
    let mut excluded = BTreeSet::new();
    let mut pending = Vec::new();
    for (file, text) in sources {
        let code = code_only(text);
        for (from, to) in test_only_regions(&code) {
            for (name, path) in module_declarations(text, &code, from, to) {
                pending.push(module_file(file, &name, path.as_deref()));
            }
        }
    }
    while let Some(file) = pending.pop() {
        if !excluded.insert(file.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read test-only source");
        let code = code_only(&text);
        for (name, path) in module_declarations(&text, &code, 0, code.len()) {
            pending.push(module_file(&file, &name, path.as_deref()));
        }
    }
    excluded
}

/// 1-based line numbers of shipped code in `source` that renames through `fs::rename`
/// (`std::fs::rename`, `tokio::fs::rename`, ...) or imports `rename` from an `fs`
/// module.
fn bare_rename_lines(source: &str) -> BTreeSet<usize> {
    let mut code = code_only(source);
    for (from, to) in test_only_regions(&code) {
        blank(&mut code[from..to]);
    }
    let line_of = |offset: usize| code[..offset].iter().filter(|&&b| b == b'\n').count() + 1;
    let mut lines = BTreeSet::new();
    let mut at = 0;
    while let Some(offset) = find(&code, b"fs::rename", at) {
        at = offset + b"fs::rename".len();
        let starts_token = offset == 0 || !is_ident(code[offset - 1]);
        let ends_token = code.get(at).is_none_or(|&byte| !is_ident(byte));
        if starts_token && ends_token {
            lines.insert(line_of(offset));
        }
    }
    let mut at = 0;
    while let Some(offset) = find(&code, b"use", at) {
        at = offset + 3;
        if (offset > 0 && is_ident(code[offset - 1]))
            || code.get(at).is_some_and(|&byte| is_ident(byte))
        {
            continue;
        }
        let end = find(&code, b";", at).unwrap_or(code.len());
        let tokens: Vec<&[u8]> = code[at..end]
            .split(|&byte| !is_ident(byte))
            .filter(|token| !token.is_empty())
            .collect();
        if tokens.contains(&&b"fs"[..]) && tokens.contains(&&b"rename"[..]) {
            lines.insert(line_of(offset));
        }
    }
    lines
}

fn rust_files(directory: &Path, into: &mut BTreeMap<PathBuf, String>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).expect("read source");
            into.insert(path, text);
        }
    }
}

/// The scanner itself must be able to say yes, and must not say yes to text that is
/// not shipped code; otherwise a clean workspace result proves nothing.
#[test]
fn the_rename_scanner_flags_shipped_renames_and_nothing_else() {
    let count = |source: &str| bare_rename_lines(source).len();
    assert_eq!(count("fn f() { std::fs::rename(a, b).unwrap(); }"), 1);
    assert_eq!(count("fn f() -> R { fs::rename(a, b)?; Ok(()) }"), 1);
    assert_eq!(count("fn f() { tokio::fs::rename(a, b).await; }"), 1);
    assert_eq!(count("use std::fs::{self, rename};"), 1);
    assert_eq!(count("use std::fs::rename as mv;"), 1);
    assert_eq!(count("fn f<'a>(x: &'a Path) { fs::rename(x, x); }"), 1);

    // Comments, strings, and names that merely contain the text are not calls.
    assert_eq!(count("// fs::rename(a, b)\n/* fs::rename(a, b) */"), 0);
    assert_eq!(count("let s = \"fs::rename(a, b)\";"), 0);
    assert_eq!(count("let s = r#\"fs::rename(a, b)\"#;"), 0);
    assert_eq!(count("fn f() { xfs::rename_all(a); fs::renamed(b); }"), 0);
    assert_eq!(count("use std::fs::File; fn rename() {}"), 0);
    assert_eq!(
        count("fn f() { cortexkit_lease::durable_replace(a, b)?; }"),
        0
    );

    // Test-gated code is skipped, and the scan resumes after it: the shipped call on
    // the line after each gated item must still be found.
    let gated = [
        "#[cfg(test)]\nmod t { fn f() { std::fs::rename(a, b); } }\nfn g() { fs::rename(c, d); }",
        "#[cfg(all(test, unix))]\nfn h() { fs::rename(a, b); }\nfn g() { fs::rename(c, d); }",
        "#[cfg(test)]\nuse std::fs::rename;\nfn g() { fs::rename(c, d); }",
        "fn g() {\n#[cfg(test)]\nif x { fs::rename(a, b); }\nfs::rename(c, d); }",
        "#[cfg(test)]\nfn h() { let c = '{'; fs::rename(a, b); }\nfn g() { fs::rename(c, d); }",
        "const J: &str = r#\"{\"#;\n#[cfg(test)]\nmod t { fn f() { fs::rename(a, b); } }\nfs::rename(c, d);",
    ];
    for source in gated {
        let lines = bare_rename_lines(source);
        assert_eq!(
            lines,
            BTreeSet::from([source.lines().count()]),
            "only the shipped call on the last line counts in:\n{source}"
        );
    }
    // A feature can enable `any(test, ...)` in a shipped build, so it is still scanned.
    assert_eq!(
        count("#[cfg(any(test, feature = \"x\"))]\nfn h() { fs::rename(a, b); }"),
        1
    );
}

#[test]
fn shipped_code_replaces_files_only_through_durable_replace() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut sources = BTreeMap::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates directory") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut sources);
        }
    }
    assert!(
        sources.len() > 50,
        "the scan must actually visit the source trees (visited {})",
        sources.len()
    );

    let excluded = test_only_files(&sources);
    // A known test-only file that does rename: proves the exclusion resolved real
    // module declarations rather than excluding nothing (or everything).
    let known_test_file = root.join("crates/credentials-module/src/account_token_tests.rs");
    assert!(
        excluded.contains(&known_test_file),
        "account_token_tests.rs is declared under #[cfg(test)] and must be classified as \
         test-only; excluded: {excluded:#?}"
    );
    assert!(
        excluded.len() < sources.len() / 2,
        "most source files are shipped code; {} of {} were classified test-only",
        excluded.len(),
        sources.len()
    );

    let mut found = Vec::new();
    for (file, text) in &sources {
        if excluded.contains(file) {
            continue;
        }
        let relative = file
            .strip_prefix(&root)
            .expect("source under the workspace root")
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let lines: Vec<&str> = text.lines().collect();
        for line in bare_rename_lines(text) {
            found.push((relative.clone(), line, lines[line - 1].trim().to_string()));
        }
    }

    let mut unexpected = Vec::new();
    let mut allowed_hits: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (file, line, text) in &found {
        match ALLOWED
            .iter()
            .find(|(path, allowed)| path == file && allowed == text)
        {
            Some(&entry) => *allowed_hits.entry(entry).or_default() += 1,
            None => unexpected.push(format!("{file}:{line}: {text}")),
        }
    }
    assert!(
        unexpected.is_empty(),
        "replace a file with cortexkit_lease::durable_replace(temp, dest), not a bare \
         rename, so the replace survives a power loss on Windows too. If this is not a \
         file publish (like the manifest lock's directory renames), add it to ALLOWED \
         with the reason:\n{}",
        unexpected.join("\n")
    );
    for entry in ALLOWED {
        assert_eq!(
            allowed_hits.get(entry).copied().unwrap_or(0),
            1,
            "allow-list entry {entry:?} must match exactly one shipped line; update ALLOWED \
             when that code moves or goes away"
        );
    }
}
