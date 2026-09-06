#![no_main]

//! The suppression parser consumes arbitrary source-file bytes. It must
//! accept anything without panicking, and its bookkeeping must stay
//! consistent (no negative counts, closed range accounting).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let mut manager = aegis_core::suppression::SuppressionManager::new();
    manager.parse_content(content);

    // Invariants that must hold for any input.
    let _ = manager.is_file_suppressed();
    let _ = manager.ranges();
    let _ = manager.suppressed_count();
    let _ = manager.is_suppressed("probe-pattern", 1);
});
