#![allow(dead_code)]
//! Shared rig helpers for the crash-safety seam suites.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// Pay macOS Gatekeeper's first-exec cost for a helper binary, and return its path.
///
/// A FRESHLY LINKED UNSIGNED BINARY DOES NOT START PROMPTLY ON macOS. `syspolicyd`
/// evaluates it on first execution, which can take tens of seconds, and until that
/// finishes the process has not run a single instruction. Every seam suite here spawns
/// a helper and then waits on a readiness marker under a 30s deadline, so a cold helper
/// blows the deadline having created nothing at all.
///
/// MEASURED 2026-08-25, and the margin is what makes the diagnosis certain: after a
/// sibling path dependency (`cortexkit-store`) recompiled and relinked
/// `rotate_cut_helper`, all five rotation cuts timed out together at 30s with
/// `store.db exists: false, key slots present: 0`. One manual execution later, the same
/// five passed in 0.69s. A 43x margin when warm — the helper is not slow, it is not
/// EXECUTING yet.
///
/// THAT FAILURE READS EXACTLY LIKE A CRASH-SAFETY DEFECT AND IS NOT ONE, which is why
/// this lives in a shared module rather than as a line copied into each suite. The fix
/// was applied to the kill-9 suite alone this morning and the identical defect sat in
/// three sibling files; taking the named instance and leaving its twins is the failure
/// this module exists to make impossible.
///
/// Running the helper with no arguments makes it exit immediately (each requires
/// arguments), which is enough to pay the evaluation outside any measured window.
///
/// Warms once per binary per test process: the suites run their cuts in parallel and a
/// repeated warm would serialise them behind a spawn each.
pub fn warmed(helper: &'static str) -> &'static str {
    static WARMED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = WARMED.get_or_init(|| Mutex::new(HashSet::new()));
    let first = {
        let mut guard = set.lock().expect("warm set");
        guard.insert(helper)
    };
    if first {
        let _ = std::process::Command::new(helper)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    helper
}
