//! Compatibility tests between the bundler's YAML/JSON schema and the
//! core scanner's `PatternDefinition`.
//!
//! The bundler serializes `match_pattern` as `"match"` and carries the
//! exclude/extensions scoping fields; the core registry must accept every
//! bundle the bundler produces, or YAML-contributed patterns silently
//! lose their scoping (or fail to load entirely).

use aegis_bundler::{create_bundle, read_patterns_from_dir, Pattern};

fn yaml_pattern() -> Pattern {
    Pattern {
        name: "yaml-contributed-rule".to_string(),
        category: "secrets".to_string(),
        match_pattern: r#"(?i)myapi[_-]?key\s*[:=]\s*['"][A-Za-z0-9]{16,}"#.to_string(),
        enabled: true,
        severity: "high".to_string(),
        confidence: "high".to_string(),
        min_entropy: Some(3.5),
        description: "MyAPI key detected".to_string(),
        reference: Some("https://example.com/docs".to_string()),
        tags: vec!["secrets".to_string(), "api-key".to_string()],
        env_var: false,
        binary: false,
        exclude: Some(r"(?i)example|placeholder".to_string()),
        file_extensions: vec!["js".to_string(), "ts".to_string()],
    }
}

/// A bundle produced by the bundler must deserialize into the core's
/// PatternDefinition with every field intact.
#[test]
fn bundler_bundle_loads_into_core_registry() {
    let bundle = create_bundle(vec![yaml_pattern()]);
    let json = serde_json::to_string(&bundle).expect("bundle must serialize");

    let core_bundle: aegis_core::bundle::Bundle =
        serde_json::from_str(&json).expect("core must deserialize a bundler-produced bundle");
    assert_eq!(core_bundle.patterns.len(), 1);

    let def = &core_bundle.patterns[0];
    assert_eq!(def.name, "yaml-contributed-rule");
    assert_eq!(def.match_pattern, yaml_pattern().match_pattern);
    assert_eq!(
        def.exclude_pattern.as_deref(),
        Some(r"(?i)example|placeholder")
    );
    assert_eq!(def.file_extensions, vec!["js", "ts"]);

    // And the registry must accept it end-to-end.
    aegis_core::PatternRegistry::from_definitions(core_bundle.patterns)
        .expect("registry must accept bundler-produced patterns");
}

/// YAML input carrying exclude/extensions must survive the directory read.
#[test]
fn yaml_scoping_fields_survive_dir_read() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("my-rule.yaml");
    std::fs::write(
        &file,
        r#"
- name: yaml-contributed-rule
  category: secrets
  match: '(?i)myapi[_-]?key\s*[:=]\s*[''"][A-Za-z0-9]{16,}'
  enabled: true
  severity: high
  confidence: high
  minEntropy: 3.5
  description: MyAPI key detected
  exclude: '(?i)example|placeholder'
  fileExtensions: [js, ts]
"#,
    )
    .unwrap();

    let patterns = read_patterns_from_dir(dir.path()).expect("valid YAML must load");
    assert_eq!(patterns.len(), 1);
    assert_eq!(
        patterns[0].exclude.as_deref(),
        Some("(?i)example|placeholder")
    );
    assert_eq!(patterns[0].file_extensions, vec!["js", "ts"]);
}

/// A YAML pattern with a broken regex must abort the bundle build instead
/// of silently shrinking the pattern set.
#[test]
fn invalid_regex_fails_the_bundle_build() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("broken.yaml"),
        r#"
- name: broken-rule
  category: secrets
  match: "([unbalanced"
  enabled: true
  severity: high
  confidence: high
  description: broken regex must fail loudly
"#,
    )
    .unwrap();

    let err = read_patterns_from_dir(dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("broken-rule"),
        "error must name the offending pattern: {err}"
    );
}
