#![no_main]

//! `.aegis.yml` is authored by users and parsed eagerly at scan start.
//! Arbitrary content must produce either validated pattern definitions or a
//! fail-loud error naming the problem — never a panic, and never a silently
//! accepted malformed rule.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let path = std::path::Path::new(".aegis.yml");
    match aegis_core::user_patterns::parse_user_pattern_content(content, path) {
        Ok(definitions) => {
            // Every accepted definition must carry a non-empty name, a
            // compiled-able regex, and a parseable severity: those are the
            // invariants the validation layer promises the registry.
            assert!(!definitions.is_empty());
            for definition in definitions {
                assert!(!definition.name.trim().is_empty());
                assert!(regex::Regex::new(&definition.match_pattern).is_ok());
            }
        }
        Err(err) => {
            // Fail-loud contract: the message always names the config file.
            let message = err.to_string();
            assert!(message.contains(".aegis.yml"), "{message}");
        }
    }
});
