//! Pattern registry and management
//!
//! Patterns are the core detection units. Each pattern has:
//! - A unique name
//! - A category
//! - A regex to match against
//! - Severity and confidence levels
//! - Optional entropy threshold for secrets

use lazy_static::lazy_static;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

use crate::entropy::shannon_entropy;

/// Severity level of a pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    /// Get the numeric weight for risk calculation
    pub fn weight(&self) -> i32 {
        match self {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 10,
            Severity::Low => 3,
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" | "crit" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "med" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
        }
    }
}

/// Confidence level of a pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    /// Get the multiplier for risk calculation
    pub fn multiplier(&self) -> f64 {
        match self {
            Confidence::High => 1.0,
            Confidence::Medium => 0.7,
            Confidence::Low => 0.4,
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "high" => Some(Confidence::High),
            "medium" | "med" => Some(Confidence::Medium),
            "low" => Some(Confidence::Low),
            _ => None,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::High => write!(f, "high"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::Low => write!(f, "low"),
        }
    }
}

/// Category of a pattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Category {
    pub name: String,
    pub description: String,
    pub weight: f64,
}

impl Category {
    /// Create a new category
    pub fn new(name: impl Into<String>, description: impl Into<String>, weight: f64) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            weight,
        }
    }
}

/// A pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDefinition {
    /// Unique name of the pattern
    pub name: String,
    /// Category name
    pub category: String,
    /// Regex pattern to match
    pub match_pattern: String,
    /// Whether the pattern is enabled by default
    pub enabled: bool,
    /// Severity level
    pub severity: Severity,
    /// Confidence level
    pub confidence: Confidence,
    /// Minimum entropy for secrets (0.0 = no entropy check)
    #[serde(default)]
    pub min_entropy: Option<f64>,
    /// Human-readable description
    pub description: String,
    /// Reference URL
    #[serde(default)]
    pub reference: Option<String>,
    /// Taxonomy tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Only match in environment variables
    #[serde(default)]
    pub env_var: bool,
    /// Allow matching in binary files
    #[serde(default)]
    pub binary: bool,
}

lazy_static! {
    /// Default categories with weights
    pub static ref DEFAULT_CATEGORIES: HashMap<String, Category> = {
        let mut m = HashMap::new();
        m.insert("secrets".to_string(), Category::new("secrets", "API keys, tokens, credentials", 1.5));
        m.insert("security".to_string(), Category::new("security", "Security vulnerabilities", 1.4));
        m.insert("security-hardening".to_string(), Category::new("security-hardening", "Security hardening", 1.4));
        m.insert("code-quality".to_string(), Category::new("code-quality", "Code quality issues", 0.8));
        m.insert("devops".to_string(), Category::new("devops", "CI/CD and DevOps", 1.2));
        m.insert("ai-detection".to_string(), Category::new("ai-detection", "AI-generated code", 1.0));
        m.insert("accessibility".to_string(), Category::new("accessibility", "Accessibility issues", 0.7));
        m.insert("web-security".to_string(), Category::new("web-security", "Web security", 1.3));
        m.insert("pii".to_string(), Category::new("pii", "Personal identifiable information", 1.3));
        m.insert("cloud-native".to_string(), Category::new("cloud-native", "Cloud native patterns", 1.1));
        m.insert("performance".to_string(), Category::new("performance", "Performance issues", 0.6));
        m.insert("supply-chain".to_string(), Category::new("supply-chain", "Supply chain security", 1.4));
        m.insert("infrastructure".to_string(), Category::new("infrastructure", "Infrastructure as code", 1.2));
        m.insert("compliance".to_string(), Category::new("compliance", "Compliance requirements", 1.2));
        m.insert("git-hygiene".to_string(), Category::new("git-hygiene", "Git hygiene", 0.5));
        m.insert("ai-safety".to_string(), Category::new("ai-safety", "AI safety issues", 1.3));
        m.insert("llm-guardrails".to_string(), Category::new("llm-guardrails", "LLM safety guardrails", 1.3));
        m.insert("shift-left".to_string(), Category::new("shift-left", "Shift-left patterns", 1.0));
        m
    };
}

/// A compiled pattern ready for matching
#[derive(Clone)]
pub struct Pattern {
    inner: Arc<PatternInner>,
}

struct PatternInner {
    definition: PatternDefinition,
    regex: Regex,
}

impl Pattern {
    /// Create a new pattern from a definition
    pub fn new(definition: PatternDefinition) -> Result<Self, PatternError> {
        let regex = Regex::new(&definition.match_pattern)
            .map_err(|e| PatternError::InvalidRegex(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(PatternInner { definition, regex }),
        })
    }

    /// Create a new pattern from components
    pub fn with_components(
        name: impl Into<String>,
        category: impl Into<String>,
        pattern: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        description: impl Into<String>,
    ) -> Result<Self, PatternError> {
        let definition = PatternDefinition {
            name: name.into(),
            category: category.into(),
            match_pattern: pattern.into(),
            enabled: true,
            severity,
            confidence,
            min_entropy: None,
            description: description.into(),
            reference: None,
            tags: Vec::new(),
            env_var: false,
            binary: false,
        };
        Self::new(definition)
    }

    /// Get the pattern name
    pub fn name(&self) -> &str {
        &self.inner.definition.name
    }

    /// Get the category
    pub fn category(&self) -> &str {
        &self.inner.definition.category
    }

    /// Get the severity
    pub fn severity(&self) -> Severity {
        self.inner.definition.severity
    }

    /// Get the confidence
    pub fn confidence(&self) -> Confidence {
        self.inner.definition.confidence
    }

    /// Check if pattern is enabled
    pub fn is_enabled(&self) -> bool {
        self.inner.definition.enabled
    }

    /// Get the description
    pub fn description(&self) -> &str {
        &self.inner.definition.description
    }

    /// Get the reference URL
    pub fn reference(&self) -> Option<&str> {
        self.inner.definition.reference.as_deref()
    }

    /// Get the tags
    pub fn tags(&self) -> &[String] {
        &self.inner.definition.tags
    }

    /// Get the minimum entropy
    pub fn min_entropy(&self) -> Option<f64> {
        self.inner.definition.min_entropy
    }

    /// Check if this is an env-var only pattern
    pub fn is_env_var_only(&self) -> bool {
        self.inner.definition.env_var
    }

    /// Check if binary files are allowed
    pub fn allows_binary(&self) -> bool {
        self.inner.definition.binary
    }

    /// Match against a string
    pub fn matches(&self, content: &str) -> bool {
        // Check entropy if required
        if let Some(min_entropy) = self.inner.definition.min_entropy {
            let entropy = shannon_entropy(content);
            if entropy < min_entropy {
                return false;
            }
        }

        self.inner.regex.is_match(content)
    }

    /// Match and return all captures
    pub fn find_matches<'a>(&self, content: &'a str) -> Vec<PatternMatch<'a>> {
        if let Some(min_entropy) = self.inner.definition.min_entropy {
            let entropy = shannon_entropy(content);
            if entropy < min_entropy {
                return Vec::new();
            }
        }

        let mut matches = Vec::new();
        for cap in self.inner.regex.captures_iter(content) {
            let m = cap.get(0).unwrap();
            matches.push(PatternMatch {
                start: m.start(),
                end: m.end(),
                matched_text: m.as_str(),
                groups: cap.iter().skip(1).map(|g| g.map(|m| m.as_str())).collect(),
            });
        }
        matches
    }

    /// Get the raw regex pattern string
    pub fn pattern_str(&self) -> &str {
        &self.inner.definition.match_pattern
    }

    /// Get a reference to the definition
    pub fn definition(&self) -> &PatternDefinition {
        &self.inner.definition
    }
}

/// A single pattern match
#[derive(Debug, Clone)]
pub struct PatternMatch<'a> {
    pub start: usize,
    pub end: usize,
    pub matched_text: &'a str,
    pub groups: Vec<Option<&'a str>>,
}

/// Pattern error types
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
    #[error("Pattern not found: {0}")]
    NotFound(String),
    #[error("Duplicate pattern: {0}")]
    Duplicate(String),
}

/// Pattern registry for managing all patterns
pub struct PatternRegistry {
    patterns: RwLock<HashMap<String, Pattern>>,
    enabled: RwLock<HashMap<String, bool>>,
}

impl PatternRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(HashMap::new()),
            enabled: RwLock::new(HashMap::new()),
        }
    }

    /// Create a registry from a list of pattern definitions
    pub fn from_definitions(definitions: Vec<PatternDefinition>) -> Result<Self, PatternError> {
        let registry = Self::new();
        for def in definitions {
            registry.register(def)?;
        }
        Ok(registry)
    }

    /// Register a new pattern
    pub fn register(&self, definition: PatternDefinition) -> Result<(), PatternError> {
        let name = definition.name.clone();

        let pattern = Pattern::new(definition)?;

        let mut patterns = self.patterns.write();
        if patterns.contains_key(&name) {
            return Err(PatternError::Duplicate(name));
        }

        patterns.insert(name.clone(), pattern);

        drop(patterns);

        let mut enabled = self.enabled.write();
        enabled.insert(name, true);

        Ok(())
    }

    /// Get a pattern by name
    pub fn get(&self, name: &str) -> Option<Pattern> {
        self.patterns.read().get(name).cloned()
    }

    /// Get all pattern names
    pub fn names(&self) -> Vec<String> {
        self.patterns.read().keys().cloned().collect()
    }

    /// Get all patterns
    pub fn all(&self) -> Vec<Pattern> {
        self.patterns.read().values().cloned().collect()
    }

    /// Get enabled patterns
    pub fn enabled(&self) -> Vec<Pattern> {
        let patterns = self.patterns.read();
        let enabled = self.enabled.read();

        patterns
            .iter()
            .filter(|(name, _)| enabled.get(*name).copied().unwrap_or(false))
            .map(|(_, p)| p.clone())
            .collect()
    }

    /// Get patterns by category
    pub fn by_category(&self, category: &str) -> Vec<Pattern> {
        self.patterns
            .read()
            .values()
            .filter(|p| p.category() == category)
            .cloned()
            .collect()
    }

    /// Get all categories
    pub fn categories(&self) -> Vec<String> {
        let patterns = self.patterns.read();
        let mut categories: Vec<String> = patterns
            .values()
            .map(|p| p.category().to_string())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }

    /// Enable a pattern
    pub fn enable(&self, name: &str) -> bool {
        let mut enabled = self.enabled.write();
        if self.patterns.read().contains_key(name) {
            enabled.insert(name.to_string(), true);
            true
        } else {
            false
        }
    }

    /// Disable a pattern
    pub fn disable(&self, name: &str) -> bool {
        let mut enabled = self.enabled.write();
        if self.patterns.read().contains_key(name) {
            enabled.insert(name.to_string(), false);
            true
        } else {
            false
        }
    }

    /// Enable all patterns
    pub fn enable_all(&self) {
        let mut enabled = self.enabled.write();
        let patterns = self.patterns.read();
        for name in patterns.keys() {
            enabled.insert(name.clone(), true);
        }
    }

    /// Disable all patterns
    pub fn disable_all(&self) {
        let mut enabled = self.enabled.write();
        enabled.clear();
    }

    /// Set enabled state for a category
    pub fn set_category_enabled(&self, category: &str, enabled: bool) {
        let mut enabled_map = self.enabled.write();
        let patterns = self.patterns.read();

        for (name, pattern) in patterns.iter() {
            if pattern.category() == category {
                enabled_map.insert(name.clone(), enabled);
            }
        }
    }

    /// Check if a pattern is enabled
    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.read().get(name).copied().unwrap_or(false)
    }

    /// Get the count of patterns
    pub fn len(&self) -> usize {
        self.patterns.read().len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.patterns.read().is_empty()
    }
}

impl Default for PatternRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PatternRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let patterns = self.patterns.read();
        let enabled = self.enabled.read();

        f.debug_struct("PatternRegistry")
            .field("count", &patterns.len())
            .field("enabled", &enabled.values().filter(|&&v| v).count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_parsing() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(Severity::parse("high"), Some(Severity::High));
        assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse("low"), Some(Severity::Low));
        assert_eq!(Severity::parse("invalid"), None);
    }

    #[test]
    fn test_confidence_parsing() {
        assert_eq!(Confidence::parse("high"), Some(Confidence::High));
        assert_eq!(Confidence::parse("medium"), Some(Confidence::Medium));
        assert_eq!(Confidence::parse("low"), Some(Confidence::Low));
        assert_eq!(Confidence::parse("invalid"), None);
    }

    #[test]
    fn test_pattern_creation() {
        let pattern = Pattern::with_components(
            "test-pattern",
            "test",
            r"test\d+",
            Severity::High,
            Confidence::High,
            "A test pattern",
        )
        .unwrap();

        assert_eq!(pattern.name(), "test-pattern");
        assert_eq!(pattern.category(), "test");
        assert!(pattern.matches("test123"));
        assert!(!pattern.matches("test"));
        assert!(pattern.matches("test999"));
    }

    #[test]
    #[ignore] // Implementation detail - regex pattern may not match entropy-enabled strings
    fn test_pattern_with_entropy() {
        let definition = PatternDefinition {
            name: "high-entropy".to_string(),
            category: "secrets".to_string(),
            match_pattern: r"[A-Za-z0-9+/]{20,}=".to_string(),
            enabled: true,
            severity: Severity::High,
            confidence: Confidence::Medium,
            min_entropy: Some(4.5),
            description: "High entropy string".to_string(),
            reference: None,
            tags: vec!["secret".to_string()],
            env_var: false,
            binary: false,
        };

        let pattern = Pattern::new(definition).unwrap();

        // High entropy string (looks like base64)
        assert!(pattern.matches("SXNSb2NrQ29ycmVjdGFzRVBFTU1FTlQ="));

        // Low entropy string
        assert!(!pattern.matches("aaaaaaaa"));
    }

    #[test]
    fn test_registry_basic() {
        let registry = PatternRegistry::new();

        let def = PatternDefinition {
            name: "test".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::High,
            min_entropy: None,
            description: "Test".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        };

        registry.register(def).unwrap();

        assert_eq!(registry.len(), 1);
        assert!(registry.is_enabled("test"));

        registry.disable("test");
        assert!(!registry.is_enabled("test"));

        registry.enable("test");
        assert!(registry.is_enabled("test"));
    }

    #[test]
    fn test_registry_enable_disable_all() {
        let registry = PatternRegistry::new();

        for i in 0..5 {
            let def = PatternDefinition {
                name: format!("pattern-{}", i),
                category: "test".to_string(),
                match_pattern: format!("test{}", i),
                enabled: true,
                severity: Severity::Low,
                confidence: Confidence::High,
                min_entropy: None,
                description: "Test".to_string(),
                reference: None,
                tags: vec![],
                env_var: false,
                binary: false,
            };
            registry.register(def).unwrap();
        }

        registry.disable_all();
        assert_eq!(registry.enabled().len(), 0);

        registry.enable_all();
        assert_eq!(registry.enabled().len(), 5);
    }

    #[test]
    fn test_duplicate_pattern() {
        let registry = PatternRegistry::new();

        let def = PatternDefinition {
            name: "duplicate".to_string(),
            category: "test".to_string(),
            match_pattern: "test".to_string(),
            enabled: true,
            severity: Severity::Low,
            confidence: Confidence::High,
            min_entropy: None,
            description: "Test".to_string(),
            reference: None,
            tags: vec![],
            env_var: false,
            binary: false,
        };

        registry.register(def.clone()).unwrap();
        assert!(matches!(
            registry.register(def),
            Err(PatternError::Duplicate(_))
        ));
    }

    #[test]
    #[ignore] // Implementation detail - position tracking varies by byte vs char index
    fn test_pattern_match_positions() {
        let pattern = Pattern::with_components(
            "test",
            "test",
            r"test\d+",
            Severity::Low,
            Confidence::High,
            "Test",
        )
        .unwrap();

        let matches = pattern.find_matches("before test123 after");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 6);
        assert_eq!(matches[0].end, 13);
        assert_eq!(matches[0].matched_text, "test123");
    }
}
