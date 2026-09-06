#![no_main]

//! Ignore-rule compilation takes untrusted globs from `.gitignore` /
//! `.aegisignore` files. Compilation must never panic; at worst a rule is
//! rejected.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let manager = aegis_core::ignore::IgnoreManager::new();
    for line in content.lines() {
        // Errors are expected for malformed globs and must be ordinary
        // `Result`s, never panics.
        let _ = manager.add_pattern(line);
    }
    manager.clear();
});
