//! Negative corpus: code-injection-request false-positive regression.
//!
//! Regression entry for the 2026-09-22 false-positive audit (commit
//! e0abd61): the rule matched verbs and threat nouns as bare substrings,
//! so "resource" and "source" (both contain "rce") plus inflected forms
//! such as "payloads" or "showed" turned ordinary I/O and logging code
//! into requests for exploit guidance. The corrected rule requires the
//! standalone verb and the standalone threat word; every line below
//! fired under the old regex and must stay silent under the current
//! one.

// aegis:expect-none code-injection-request

use std::io::Write;

/// Serialize the audit record and persist it for the compliance trail.
fn persist_record(path: &str, record: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    // The old regex scored this write to the resource file as a request
    // for exploit guidance: "resource" carries "rce" as a substring.
    file.write_all(&resource_bytes(record))?;
    Ok(())
}

fn resource_bytes(record: &[u8]) -> &[u8] {
    record
}

/// Show the checksum of the artifact next to its size.
pub fn describe(artifact: &str, size: u64) -> String {
    // "show the source" satisfied the old pattern; the corrected rule
    // needs a threat word by itself, and a source mirror is not one.
    // Inflected plurals such as "payloads" no longer match either.
    format!("{artifact}: {size} bytes from a source mirror")
}
