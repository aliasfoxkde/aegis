#![no_main]

//! Baseline files may come from untrusted or hand-edited sources. Parsing
//! arbitrary content must produce either a fingerprint set or an error,
//! never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => return,
    };
    let path = temp.path().join("baseline.json");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let _ = aegis_core::scanner::load_baseline_fingerprints(&path);
});
