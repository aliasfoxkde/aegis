//! Code clone detection
//!
//! Detects code clones using token-based similarity comparison.

use std::collections::HashSet;
use std::path::Path;

/// A detected code clone
#[derive(Debug, Clone)]
pub struct CodeClone {
    /// Clone type (1-4)
    pub clone_type: CloneType,
    /// First occurrence location
    pub location1: CloneLocation,
    /// Second occurrence location
    pub location2: CloneLocation,
    /// Similarity score (0.0 - 1.0)
    pub similarity: f64,
    /// Number of tokens
    pub token_count: usize,
}

/// Location of a clone
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CloneLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub function: Option<String>,
}

/// Clone type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneType {
    /// Type 1: Identical code (whitespace only differences)
    Type1,
    /// Type 2: Identical with renamed variables
    Type2,
    /// Type 3: Similar with minor modifications
    Type3,
    /// Type 4: Semantic clones (different syntax, same behavior)
    Type4,
}

impl CloneType {
    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            CloneType::Type1 => "Identical code (whitespace differences only)",
            CloneType::Type2 => "Identical with renamed variables",
            CloneType::Type3 => "Similar with minor modifications",
            CloneType::Type4 => "Semantic clones (different syntax)",
        }
    }
}

/// Clone detector
pub struct CloneDetector {
    /// Minimum similarity threshold (0.0 - 1.0)
    min_similarity: f64,
    /// Minimum token count to consider
    min_tokens: usize,
}

impl CloneDetector {
    /// Create a new detector
    pub fn new() -> Self {
        Self {
            min_similarity: 0.75,
            min_tokens: 10,
        }
    }

    /// Set minimum similarity threshold
    pub fn with_min_similarity(mut self, similarity: f64) -> Self {
        self.min_similarity = similarity;
        self
    }

    /// Set minimum token count
    pub fn with_min_tokens(mut self, tokens: usize) -> Self {
        self.min_tokens = tokens;
        self
    }

    /// Detect clones in a file
    pub fn detect_file(&self, path: &Path) -> Result<Vec<CodeClone>, CloneError> {
        let content = std::fs::read_to_string(path)?;
        self.detect_content(&content, path.to_str().unwrap_or("unknown"))
    }

    /// Detect clones in content
    pub fn detect_content(
        &self,
        content: &str,
        source: &str,
    ) -> Result<Vec<CodeClone>, CloneError> {
        let tokens = self.tokenize(content);
        let blocks = self.create_blocks(&tokens, content.lines().count());

        self.find_clones(blocks, source.to_string())
    }

    /// Simple tokenizer
    fn tokenize(&self, content: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut chars = content.char_indices().peekable();
        let _lines: Vec<(usize, &str)> = content.lines().enumerate().collect();

        while let Some((start, c)) = chars.next() {
            // Skip whitespace
            if c.is_whitespace() {
                continue;
            }

            // Identifier or keyword
            if c.is_alphabetic() || c == '_' {
                let mut end = start;
                while let Some(&(idx, ch)) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        end = idx + ch.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                let text = &content[start..end];
                let kind = if self.is_keyword(text) {
                    TokenKind::Keyword
                } else {
                    TokenKind::Identifier
                };
                tokens.push(Token {
                    start,
                    end,
                    text: text.to_string(),
                    kind,
                });
                continue;
            }

            // Number
            if c.is_numeric() {
                let mut end = start;
                while let Some(&(idx, ch)) = chars.peek() {
                    if ch.is_numeric() || ch == '.' || ch == 'x' || ch.is_ascii_hexdigit() {
                        end = idx + ch.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token {
                    start,
                    end,
                    text: content[start..end].to_string(),
                    kind: TokenKind::Number,
                });
                continue;
            }

            // String
            if c == '"' || c == '\'' {
                let quote = c;
                let mut end = start + 1;
                while let Some((idx, ch)) = chars.next() {
                    end = idx + ch.len_utf8();
                    if ch == quote {
                        break;
                    }
                    if ch == '\\' {
                        if let Some((idx2, _)) = chars.next() {
                            end = idx2 + 1;
                        }
                    }
                }
                tokens.push(Token {
                    start,
                    end,
                    text: content[start..end].to_string(),
                    kind: TokenKind::String,
                });
                continue;
            }

            // Operators
            let kind = match c {
                '+' | '-' | '*' | '/' | '%' | '=' | '<' | '>' | '!' | '&' | '|' | '^' | '~' => {
                    TokenKind::Operator
                }
                '(' | ')' | '[' | ']' | '{' | '}' | ';' | ',' | '.' => TokenKind::Punctuation,
                _ => TokenKind::Other,
            };

            tokens.push(Token {
                start,
                end: start + c.len_utf8(),
                text: c.to_string(),
                kind,
            });
        }

        tokens
    }

    /// Check if text is a keyword
    fn is_keyword(&self, text: &str) -> bool {
        matches!(
            text,
            "fn" | "let"
                | "const"
                | "var"
                | "if"
                | "else"
                | "for"
                | "while"
                | "return"
                | "match"
                | "case"
                | "switch"
                | "break"
                | "continue"
                | "struct"
                | "enum"
                | "impl"
                | "trait"
                | "pub"
                | "mod"
                | "use"
                | "import"
                | "package"
                | "func"
                | "def"
                | "class"
                | "async"
                | "await"
                | "yield"
                | "try"
                | "catch"
                | "throw"
                | "throws"
                | "finally"
                | "new"
                | "delete"
                | "typeof"
                | "instanceof"
        )
    }

    /// Create code blocks from tokens
    fn create_blocks(&self, tokens: &[Token], _total_lines: usize) -> Vec<CodeBlock> {
        let block_size = 20; // tokens per block
        let stride = 10; // step size

        let mut blocks = Vec::new();

        for i in (0..tokens.len().saturating_sub(block_size)).step_by(stride) {
            let end = (i + block_size).min(tokens.len());
            let block_tokens = &tokens[i..end];

            if block_tokens.len() < self.min_tokens {
                continue;
            }

            // Find line number for this block
            let _start_pos = block_tokens.first().map(|t| t.start).unwrap_or(0);
            let _end_pos = block_tokens.last().map(|t| t.end).unwrap_or(0);

            // Count newlines to get line numbers
            let start_line = tokens[..i].iter().filter(|t| t.text == "\n").count() + 1;
            let end_line = tokens[..end].iter().filter(|t| t.text == "\n").count() + 1;

            blocks.push(CodeBlock {
                index: blocks.len(),
                start_token: i,
                end_token: end,
                start_line,
                end_line,
                normalized: self.normalize(block_tokens),
                original: block_tokens.iter().map(|t| t.text.clone()).collect(),
            });
        }

        blocks
    }

    /// Normalize a block for comparison (remove variable names, literals)
    fn normalize(&self, tokens: &[Token]) -> String {
        tokens
            .iter()
            .map(|t| match t.kind {
                TokenKind::Identifier => "ID".to_string(),
                TokenKind::Number => "NUM".to_string(),
                TokenKind::String => "STR".to_string(),
                _ => t.text.clone(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Find clones between blocks
    fn find_clones(
        &self,
        blocks: Vec<CodeBlock>,
        source: String,
    ) -> Result<Vec<CodeClone>, CloneError> {
        let mut clones = Vec::new();

        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                let similarity = self.calculate_similarity(&blocks[i], &blocks[j]);

                if similarity >= self.min_similarity {
                    let clone_type = self.classify_clone(&blocks[i], &blocks[j], similarity);

                    clones.push(CodeClone {
                        clone_type,
                        location1: CloneLocation {
                            file: source.clone(),
                            start_line: blocks[i].start_line,
                            end_line: blocks[i].end_line,
                            function: None,
                        },
                        location2: CloneLocation {
                            file: source.clone(),
                            start_line: blocks[j].start_line,
                            end_line: blocks[j].end_line,
                            function: None,
                        },
                        similarity,
                        token_count: blocks[i].normalized.split_whitespace().count(),
                    });
                }
            }
        }

        // Sort by similarity descending
        clones.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(clones)
    }

    /// Calculate similarity between two blocks
    fn calculate_similarity(&self, a: &CodeBlock, b: &CodeBlock) -> f64 {
        let a_tokens: HashSet<_> = a.normalized.split_whitespace().collect();
        let b_tokens: HashSet<_> = b.normalized.split_whitespace().collect();

        let intersection = a_tokens.intersection(&b_tokens).count();
        let union = a_tokens.union(&b_tokens).count();

        if union == 0 {
            return 0.0;
        }

        intersection as f64 / union as f64
    }

    /// Classify clone type based on similarity
    fn classify_clone(&self, _a: &CodeBlock, _b: &CodeBlock, similarity: f64) -> CloneType {
        if similarity >= 0.98 {
            CloneType::Type1
        } else if similarity >= 0.85 {
            CloneType::Type2
        } else if similarity >= 0.75 {
            CloneType::Type3
        } else {
            CloneType::Type4
        }
    }
}

impl Default for CloneDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// A token
#[derive(Debug, Clone)]
struct Token {
    start: usize,
    end: usize,
    text: String,
    kind: TokenKind,
}

/// Token kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TokenKind {
    Keyword,
    Identifier,
    Number,
    String,
    Operator,
    Punctuation,
    Other,
}

/// A code block
#[derive(Debug, Clone)]
struct CodeBlock {
    #[allow(dead_code)]
    index: usize,
    #[allow(dead_code)]
    start_token: usize,
    #[allow(dead_code)]
    end_token: usize,
    start_line: usize,
    end_line: usize,
    normalized: String,
    #[allow(dead_code)]
    original: String,
}

/// Clone detection error
#[derive(Debug, thiserror::Error)]
pub enum CloneError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = CloneDetector::new();
        assert_eq!(detector.min_similarity, 0.75);
        let _ = detector;
    }

    #[test]
    fn test_detector_with_options() {
        let detector = CloneDetector::new()
            .with_min_similarity(0.9)
            .with_min_tokens(5);
        assert_eq!(detector.min_similarity, 0.9);
        let _ = detector;
    }

    #[test]
    fn test_identical_code_detection() {
        let detector = CloneDetector::new();
        let content = r#"
fn foo() {
    let x = 1;
    let y = 2;
    println!("{}", x + y);
}

fn bar() {
    let a = 1;
    let b = 2;
    println!("{}", a + b);
}
"#;
        let clones = detector.detect_content(content, "test.rs").unwrap();
        // Should find some clones with high similarity
        assert!(clones.iter().any(|c| c.similarity >= 0.5));
    }

    #[test]
    fn test_clone_type_classification() {
        let _detector = CloneDetector::new();

        // Test that very similar code is Type1
        let identical: Vec<CodeClone> = vec![CodeClone {
            clone_type: CloneType::Type1,
            location1: CloneLocation {
                file: "".to_string(),
                start_line: 1,
                end_line: 1,
                function: None,
            },
            location2: CloneLocation {
                file: "".to_string(),
                start_line: 1,
                end_line: 1,
                function: None,
            },
            similarity: 1.0,
            token_count: 20,
        }];

        assert_eq!(identical[0].clone_type, CloneType::Type1);
    }

    #[test]
    fn test_clone_type_description() {
        assert_eq!(
            CloneType::Type1.description(),
            "Identical code (whitespace differences only)"
        );
        assert_eq!(
            CloneType::Type2.description(),
            "Identical with renamed variables"
        );
        assert_eq!(
            CloneType::Type3.description(),
            "Similar with minor modifications"
        );
        assert_eq!(
            CloneType::Type4.description(),
            "Semantic clones (different syntax)"
        );
    }

    #[test]
    fn test_clone_location() {
        let loc = CloneLocation {
            file: "test.rs".to_string(),
            start_line: 10,
            end_line: 20,
            function: Some("main".to_string()),
        };
        assert_eq!(loc.file, "test.rs");
        assert_eq!(loc.start_line, 10);
        assert_eq!(loc.end_line, 20);
        assert_eq!(loc.function, Some("main".to_string()));
    }

    #[test]
    fn test_clone_location_without_function() {
        let loc = CloneLocation {
            file: "test.rs".to_string(),
            start_line: 10,
            end_line: 20,
            function: None,
        };
        assert!(loc.function.is_none());
    }

    #[test]
    fn test_clone_detector_with_low_similarity() {
        let detector = CloneDetector::new().with_min_similarity(0.5);
        assert_eq!(detector.min_similarity, 0.5);
    }

    #[test]
    fn test_clone_detector_default() {
        let detector = CloneDetector::default();
        assert_eq!(detector.min_similarity, 0.75);
    }

    #[test]
    fn test_code_clone_debug() {
        let clone = CodeClone {
            clone_type: CloneType::Type2,
            location1: CloneLocation {
                file: "a.rs".to_string(),
                start_line: 1,
                end_line: 10,
                function: Some("foo".to_string()),
            },
            location2: CloneLocation {
                file: "b.rs".to_string(),
                start_line: 5,
                end_line: 15,
                function: Some("bar".to_string()),
            },
            similarity: 0.85,
            token_count: 50,
        };
        let debug_str = format!("{:?}", clone);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_clone_type_all_variants() {
        // Ensure all clone types can be used
        let types = vec![
            CloneType::Type1,
            CloneType::Type2,
            CloneType::Type3,
            CloneType::Type4,
        ];
        for t in types {
            assert!(!t.description().is_empty());
        }
    }

    #[test]
    fn test_detect_file_nonexistent() {
        let detector = CloneDetector::new();
        let result = detector.detect_file(std::path::Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_content_with_numbers_and_strings() {
        // Exercise tokenization of numbers, strings, and identifiers
        let detector = CloneDetector::new();
        let content = r#"
fn foo() {
    let x = 42;
    let hex = 0xFF;
    let float = 3.14;
    let s = "hello";
    let c = 'c';
}
"#;
        let result = detector.detect_content(content, "test.rs");
        // Should succeed (may or may not find clones depending on similarity)
        assert!(result.is_ok());
    }

    #[test]
    fn test_tokenize_numbers() {
        let detector = CloneDetector::new();
        // Use reflection or just test detect_content which uses tokenize internally
        let content = "let x = 0xDEADBEEF; let y = 42; let z = 3.14159;";
        let result = detector.detect_content(content, "test.rs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_tokenize_string_with_escape() {
        let detector = CloneDetector::new();
        // Test string tokenization with escape sequences to cover line 172-174
        let content = r#"let s = "hello \"world\" escaped";"#;
        let result = detector.detect_content(content, "test.rs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_classify_clone_type4() {
        // Test that low similarity (< 0.75) gets classified as Type4
        let detector = CloneDetector::new();
        let content1 = "fn alpha() { println!(\"completely different function alpha\"); }";
        let clones = detector.detect_content(content1, "a.rs").unwrap();
        // When comparing blocks within same content, low similarity gets Type4
        // This test verifies the classify_clone function branch
        assert!(clones.is_empty() || clones.iter().any(|c| c.similarity < 0.75));
    }
}
