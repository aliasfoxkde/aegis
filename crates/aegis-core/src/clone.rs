//! Code clone detection
//!
//! Detects code clones using token-based similarity comparison, including
//! Type-3 "near-miss" clones: copy-paste with a modification such as
//! reordered statements, an inserted or removed statement, or a swapped
//! operator.
//!
//! # Algorithm
//!
//! 1. `CloneDetector::tokenize` splits the source into tokens.
//! 2. `CloneDetector::create_blocks` slices the token stream into
//!    `BLOCK_SIZE`-token windows whose starts advance `BLOCK_STRIDE`
//!    tokens at a time.
//! 3. `CloneDetector::find_clones` scores every block pair and reports the
//!    pairs whose similarity reaches `CloneDetector::min_similarity`.
//!
//! Similarity is **sequence aware**: it is the longest-common-subsequence
//! (LCS) ratio `2 * matched / (len_a + len_b)` over the two blocks' token
//! sequences, with identifiers and literals compared by role rather than by
//! text (`CloneDetector::tokens_match`). Order and multiplicity both count,
//! which is what makes the Type-3 band mean "structurally close, with a real
//! modification". The previous bag-of-tokens score (a set intersection over
//! normalized token strings) ignored both, and rated two unrelated functions
//! of the same shape as a Type-1 clone at similarity 1.0.
//!
//! # Known limits
//!
//! * A file (or a region) shorter than `BLOCK_SIZE` tokens produces no
//!   blocks and is never reported. That is a deliberate trade: at the
//!   previous 20-token span, one and a half statements of role-normalized
//!   code agreed with almost any other window in the file.
//! * A block is never compared with a block it overlaps, so a tandem repeat
//!   shorter than `BLOCK_SIZE` tokens is not reported.
//! * A file yielding more than `MAX_BLOCKS` windows has its grid thinned
//!   evenly, so very large files are sampled rather than paired in full.
//! * Blocks cover the stream up to the last full `BLOCK_SIZE`-token window;
//!   a trailing partial window is not compared.
//! * Of the `BLOCK_STRIDE` window alignments a pair admits, only the one
//!   with the most exactly aligned tokens is scored, and a pair with no
//!   exactly aligned token at any phase is not scored at all. A copy whose
//!   only resemblance is a shifted subsequence is therefore missed rather
//!   than mispriced.
//! * Detection is intra-file: [`CloneDetector::detect_content`] compares a
//!   source against itself. Cross-file clones need a caller-level pairing.
//!
//! # Complexity
//!
//! Block pairing is `O(B^2)` for `B` blocks, `B = tokens / BLOCK_STRIDE`, so
//! a file costs `O(B^2 * BLOCK_STRIDE * BLOCK_SIZE^2)` — quadratic in block
//! count, the same shape the detector had before near-miss detection, at an
//! `O(BLOCK_STRIDE * BLOCK_SIZE)` alignment search and a `BLOCK_SIZE^2`
//! constant per comparison. Because the grid is thinned past
//! `MAX_BLOCKS`, `B` is capped and the worst case is a constant, not a
//! function of file size. Sound bounds cut that constant in
//! `CloneDetector::pair_similarity` and `CloneDetector::range_similarity`: a
//! length bound and a label-multiset bound that reject a pair without
//! running the LCS, and a row cutoff inside the LCS that abandons the scan
//! once the threshold can no longer be reached. Line numbers are resolved
//! from a precomputed line-start index, `O(log lines)` per block.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Similarity at or above which a pair is reported as a Type-1 clone.
///
/// Blocks are equal-width windows, so with the LCS ratio a pair reaches this
/// band only when its normalized token sequences match end to end. Because
/// normalization compares identifiers by role, a copy whose *only* difference
/// is renamed identifiers also lands here; that is the classification the
/// detector has always produced for renames and it is preserved.
const TYPE1_SIMILARITY: f64 = 0.98;

/// Similarity at or above which a pair is reported as a Type-2 clone.
const TYPE2_SIMILARITY: f64 = 0.85;

/// Similarity at or above which a pair is reported as a Type-3 clone.
///
/// This is the near-miss floor and the default value of
/// `CloneDetector::min_similarity`, so by default a reported pair is never
/// worse than a near-miss. Below it, a pair only reaches the output when the
/// caller lowers `min_similarity`, and is then labelled Type-4.
const TYPE3_SIMILARITY: f64 = 0.75;

/// Number of tokens in a comparison block.
///
/// The span is deliberately wide. A near-miss claim has to rest on more than
/// a statement and a half: with identifiers normalized to a single role, two
/// 20-token windows from unrelated functions of the same style routinely
/// agree on three quarters of their tokens, which is exactly the Type-3 band.
/// At 40 tokens (roughly three statements) that baseline falls below the
/// near-miss floor while real copy-paste regions still clear it. The price is
/// recall on very short duplicated regions, which is recorded in the module
/// docs.
const BLOCK_SIZE: usize = 40;

/// Distance between the starts of consecutive comparison blocks.
///
/// Blocks therefore overlap heavily, and a block is never compared with a
/// block it overlaps: such a pair samples the same code twice rather than
/// twice-written code.
const BLOCK_STRIDE: usize = 10;

/// Most blocks one detection run pairs.
///
/// Pairing is quadratic in block count, so a file whose token stream yields
/// more blocks than this has its grid thinned evenly instead of paired in
/// full: a very large file is *sampled* rather than scanned window by window.
/// Thinning trades recall on the windows it drops for a hard bound on work,
/// and it is the reason the bound below is a named constant rather than an
/// accident of input size.
const MAX_BLOCKS: usize = 256;

/// Most clone pairs reported for a single file.
///
/// On a pathological input — a minified bundle, a generated dump — nearly
/// every surviving window pair can clear the similarity floor, so collecting
/// without a cap would let one file flood the report and pay for the full
/// `O(B²)` pairing behind it. Pairing stops at this cap: the work and the
/// output stay bounded at the same `MAX_BLOCKS`-scale constant, and the
/// bound is deterministic because pairs are collected in grid order. A file
/// that reaches the cap is, at minimum, not meant to be read by hand.
const MAX_REPORTED_CLONES: usize = 256;

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
    /// Source label for the block, taken verbatim from the `source` argument
    /// passed to [`CloneDetector::detect_content`] (the file path for
    /// [`CloneDetector::detect_file`]).
    pub file: String,
    /// First line of the cloned block, 1-indexed and inclusive.
    pub start_line: usize,
    /// Last line of the cloned block, 1-indexed and inclusive.
    pub end_line: usize,
    /// Enclosing function name when known; [`CloneDetector`] currently leaves
    /// this unset because detection works on token blocks, not symbol bounds.
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
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            CloneType::Type1 => "Identical code (whitespace differences only)",
            CloneType::Type2 => "Identical with renamed variables",
            CloneType::Type3 => "Similar with minor modifications",
            CloneType::Type4 => "Semantic clones (different syntax)",
        }
    }

    /// Stable wire name for this clone kind (`"type-1"` through `"type-4"`),
    /// as used by [`CloneReport::kind`] in JSON output.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            CloneType::Type1 => "type-1",
            CloneType::Type2 => "type-2",
            CloneType::Type3 => "type-3",
            CloneType::Type4 => "type-4",
        }
    }
}

/// One of the two occurrences in a [`CloneReport`]: the wire/report form of
/// a [`CloneLocation`], carrying only what survives serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneLocationReport {
    /// Source label, verbatim from the `source` argument of the detection
    /// call (the file path when scanning from disk).
    pub file: String,
    /// First line of the cloned block, 1-indexed and inclusive.
    pub start_line: usize,
    /// Last line of the cloned block, 1-indexed and inclusive.
    pub end_line: usize,
}

impl CloneLocationReport {
    fn from_location(location: &CloneLocation) -> Self {
        Self {
            file: location.file.clone(),
            start_line: location.start_line,
            end_line: location.end_line,
        }
    }
}

/// A clone pair in the wire/report format that travels in
/// [`crate::finding::ScanStats::clones`] and lands in `--format json`
/// output.
///
/// The detector's native [`CodeClone`] keeps the typed [`CloneType`] and the
/// exact `f64` similarity; this shape fixes the report contract instead —
/// the kind as its stable [`CloneType::kind_name`] string, and similarity
/// rounded to four decimal places so output does not drift across platforms
/// and runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloneReport {
    /// Clone kind: `"type-1"` through `"type-4"`.
    pub kind: String,
    /// Human-readable description of the clone kind.
    pub description: String,
    /// Similarity score (0.0 - 1.0), rounded to four decimal places.
    pub similarity: f64,
    /// Number of tokens in each compared block.
    pub token_count: usize,
    /// The two occurrences, in detector order. Always exactly two entries.
    pub locations: Vec<CloneLocationReport>,
}

impl CloneReport {
    /// Convert a detector result into the wire/report shape.
    #[must_use]
    pub fn from_code_clone(clone: &CodeClone) -> Self {
        Self {
            kind: clone.clone_type.kind_name().to_string(),
            description: clone.clone_type.description().to_string(),
            similarity: (clone.similarity * 10_000.0).round() / 10_000.0,
            token_count: clone.token_count,
            locations: vec![
                CloneLocationReport::from_location(&clone.location1),
                CloneLocationReport::from_location(&clone.location2),
            ],
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
    ///
    /// The default similarity floor is `TYPE3_SIMILARITY` (0.75), so a
    /// detector built with [`CloneDetector::new`] reports exact clones,
    /// renamed clones, and near-miss clones, and nothing looser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_similarity: TYPE3_SIMILARITY,
            min_tokens: 10,
        }
    }

    /// Set minimum similarity threshold
    ///
    /// This is the single knob separating near-miss clones from noise: a pair
    /// is reported only when its similarity reaches the threshold, and the
    /// reported band then follows `CloneDetector::classify_clone`. Raising it
    /// above `TYPE2_SIMILARITY` (0.85) suppresses Type-3 output entirely;
    /// lowering it below `TYPE3_SIMILARITY` admits Type-4 pairs.
    #[must_use]
    pub fn with_min_similarity(mut self, similarity: f64) -> Self {
        self.min_similarity = similarity;
        self
    }

    /// Set minimum token count
    ///
    /// Blocks are exactly `BLOCK_SIZE` tokens, so a floor at or below
    /// `BLOCK_SIZE` makes no difference to the block grid and a floor above
    /// it suppresses detection entirely. The knob is a coarse switch, not a
    /// graduated one.
    #[must_use]
    pub fn with_min_tokens(mut self, tokens: usize) -> Self {
        self.min_tokens = tokens;
        self
    }

    /// Detect clones in a file
    ///
    /// # Errors
    ///
    /// Returns [`CloneError::IoError`] if the file cannot be read.
    pub fn detect_file(&self, path: &Path) -> Result<Vec<CodeClone>, CloneError> {
        let content = std::fs::read_to_string(path)?;
        self.detect_content(&content, path.to_str().unwrap_or("unknown"))
    }

    /// Detect clones in content
    ///
    /// # Errors
    ///
    /// Never returns `Err` today: detection over in-memory content cannot
    /// fail. The `Result` keeps parity with [`CloneDetector::detect_file`].
    pub fn detect_content(
        &self,
        content: &str,
        source: &str,
    ) -> Result<Vec<CodeClone>, CloneError> {
        let tokens = Self::tokenize(content);
        let line_starts = line_starts(content);
        let blocks = self.create_blocks(&tokens, &line_starts);

        Ok(self.find_clones(&tokens, &blocks, source))
    }

    /// Simple tokenizer
    fn tokenize(content: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut chars = content.char_indices().peekable();

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
                let kind = if Self::is_keyword(text) {
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
                        // Advance past the escaped code point by its full
                        // UTF-8 width; `idx2 + 1` would split multibyte
                        // escapes and panic the `content[start..end]` slice.
                        if let Some((idx2, escaped)) = chars.next() {
                            end = idx2 + escaped.len_utf8();
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
    fn is_keyword(text: &str) -> bool {
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
    ///
    /// Blocks are `BLOCK_SIZE`-token windows whose starts advance
    /// `BLOCK_STRIDE` tokens at a time, so a duplicated region of any length
    /// is covered by a run of overlapping windows. Overlapping windows are
    /// never compared with each other — [`Self::pair_similarity`] skips a pair
    /// whose ranges intersect — so a duplicated region is reported against the
    /// region it was copied from, not against its own next window. Blocks
    /// shorter than `min_tokens` are dropped, and the stream is covered up to
    /// its last full `BLOCK_SIZE`-token window.
    ///
    /// A grid larger than `MAX_BLOCKS` is thinned by keeping every `step`-th
    /// window, so the pairing cost below is bounded no matter how large the
    /// file is.
    ///
    /// Cost: `O(tokens / BLOCK_STRIDE)` candidates, each resolving its line
    /// span with a binary search over the line-start index; at most
    /// `MAX_BLOCKS` of them survive.
    fn create_blocks(&self, tokens: &[Token], line_starts: &[usize]) -> Vec<CodeBlock> {
        let last_start = tokens.len().saturating_sub(BLOCK_SIZE);
        let candidates = last_start.div_ceil(BLOCK_STRIDE);
        let step = candidates.div_ceil(MAX_BLOCKS);
        let mut blocks = Vec::new();

        for (nth, i) in (0..last_start).step_by(BLOCK_STRIDE).enumerate() {
            if nth % step != 0 {
                continue;
            }

            let end = (i + BLOCK_SIZE).min(tokens.len());
            let block_tokens = &tokens[i..end];

            if block_tokens.len() < self.min_tokens {
                continue;
            }

            let (Some(first_token), Some(last_token)) = (block_tokens.first(), block_tokens.last())
            else {
                continue;
            };

            blocks.push(CodeBlock {
                start_token: i,
                end_token: end,
                start_line: line_for(line_starts, first_token.start),
                end_line: line_for(line_starts, last_token.end),
            });
        }

        blocks
    }

    /// Do two tokens play the same role in their blocks' normalized sequences?
    ///
    /// This is the whole normalization step: identifiers, numeric literals,
    /// and string literals compare by role alone, so renamed variables and
    /// re-typed literals match, while keywords, operators, and punctuation
    /// compare by exact text, which is what leaves the similarity signal
    /// structural.
    fn tokens_match(a: &Token, b: &Token) -> bool {
        match (a.kind, b.kind) {
            (TokenKind::Identifier, TokenKind::Identifier)
            | (TokenKind::Number, TokenKind::Number)
            | (TokenKind::String, TokenKind::String) => true,
            _ => a.text == b.text,
        }
    }

    /// Find clones between blocks
    ///
    /// Pairs every block with every later block: `O(B^2)` pairs for `B`
    /// blocks. Each pair is settled by [`Self::pair_similarity`], which picks
    /// the best-aligned window phase in `O(BLOCK_STRIDE * BLOCK_SIZE)` and
    /// scores it with an `O(BLOCK_SIZE^2)` comparison that gives up early
    /// once the pair cannot reach [`Self::min_similarity`]. This is the same
    /// pairing shape the detector has always had; no cross-file or
    /// all-against-all pass beyond it is introduced.
    ///
    /// Collection stops at `MAX_REPORTED_CLONES`, so a file where nearly
    /// every pair qualifies neither floods the report nor pays for the rest
    /// of the quadratic pass.
    fn find_clones(&self, tokens: &[Token], blocks: &[CodeBlock], source: &str) -> Vec<CodeClone> {
        let mut clones = Vec::new();
        let (labels, distinct_labels) = Self::label_tokens(tokens);
        let mut scratch = PairingScratch {
            labels: &labels,
            counts: vec![0; distinct_labels],
            touched: Vec::new(),
            lcs: LcsRows::new(BLOCK_SIZE),
        };

        'pairing: for (i, first) in blocks.iter().enumerate() {
            for second in &blocks[i + 1..] {
                let Some(similarity) = self.pair_similarity(tokens, first, second, &mut scratch)
                else {
                    continue;
                };

                let clone_type = Self::classify_clone(similarity);

                clones.push(CodeClone {
                    clone_type,
                    location1: CloneLocation {
                        file: source.to_string(),
                        start_line: first.start_line,
                        end_line: first.end_line,
                        function: None,
                    },
                    location2: CloneLocation {
                        file: source.to_string(),
                        start_line: second.start_line,
                        end_line: second.end_line,
                        function: None,
                    },
                    similarity,
                    token_count: first.end_token - first.start_token,
                });

                if clones.len() >= MAX_REPORTED_CLONES {
                    break 'pairing;
                }
            }
        }

        // Sort by similarity descending
        clones.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        clones
    }

    /// Similarity for one block pair, or `None` when the pair is never
    /// compared or cannot reach [`Self::min_similarity`].
    ///
    /// Block starts advance `BLOCK_STRIDE` tokens at a time, so two copied
    /// regions are only compared by phase-aligned windows when their
    /// separation happens to be a multiple of `BLOCK_STRIDE`. One phase
    /// inside the stride is therefore picked first — the one that aligns the
    /// most tokens exactly — and only that alignment is scored by the LCS.
    /// Picking by position is what keeps the per-pair cost at a single LCS
    /// run, and it hands the scorer the alignment a reader would pick for a
    /// real copy, so a verbatim copy whose offset is not a multiple of
    /// `BLOCK_STRIDE` is still reported as a Type-1 clone rather than as a
    /// near miss.
    ///
    /// A window is never compared against a window it overlaps — that pair
    /// samples the same code twice rather than twice-written code — so
    /// overlapping blocks of one region, and a pair whose only in-bounds
    /// alignment is an overlapping one, produce nothing. Because the
    /// alignment is picked by exact position matches, a pair with no exactly
    /// aligned token at any phase is not scored at all; content that only
    /// overlaps as a shifted subsequence is out of reach for this detector.
    ///
    /// Cost: `O(BLOCK_STRIDE * BLOCK_SIZE)` to pick the alignment, one
    /// label-multiset bound, and at most one LCS run, so pairing stays
    /// `O(B^2)` block pairs.
    fn pair_similarity(
        &self,
        tokens: &[Token],
        a: &CodeBlock,
        b: &CodeBlock,
        scratch: &mut PairingScratch<'_>,
    ) -> Option<f64> {
        let width = b.end_token - b.start_token;
        let first = &tokens[a.start_token..a.end_token];

        let mut aligned: Option<usize> = None;
        let mut aligned_matches = 0usize;
        for phase in 0..BLOCK_STRIDE {
            let Some(start) = b.start_token.checked_sub(phase) else {
                break;
            };
            let end = start + width;
            if end > tokens.len() {
                break;
            }
            if start < a.end_token && a.start_token < end {
                continue;
            }

            let mut matches = 0usize;
            for (one, other) in first.iter().zip(&tokens[start..end]) {
                if Self::tokens_match(one, other) {
                    matches += 1;
                }
            }
            if matches > aligned_matches {
                aligned_matches = matches;
                aligned = Some(start);
            }
        }
        let start = aligned?;
        let second = &tokens[start..start + width];

        let labels = scratch.labels;
        let second_labels = &labels[start..start + width];
        let bound = scratch.multiset_bound(&labels[a.start_token..a.end_token], second_labels);
        let bound_ratio = (2.0 * bound as f64) / ((first.len() + second.len()) as f64);
        if bound_ratio < self.min_similarity {
            return None;
        }

        self.range_similarity(first, second, &mut scratch.lcs)
    }

    /// Comparison label id of every token, in order, plus the number of
    /// distinct labels.
    ///
    /// The labels mirror [`Self::tokens_match`]: identifiers, numbers, and
    /// string literals share one id per role, every other token is labelled by
    /// its kind and text. Cost: `O(tokens)`.
    fn label_tokens(tokens: &[Token]) -> (Vec<usize>, usize) {
        let mut ids = Vec::with_capacity(tokens.len());
        let mut seen: HashMap<(u8, &str), usize> = HashMap::new();
        for token in tokens {
            let key = Self::label_key(token);
            let next = seen.len();
            ids.push(*seen.entry(key).or_insert(next));
        }
        (ids, seen.len())
    }

    /// Comparison label of a single token, mirroring
    /// [`Self::tokens_match`]: a role for identifiers and literals, kind plus
    /// text for everything else.
    fn label_key(token: &Token) -> (u8, &str) {
        let kind = match token.kind {
            TokenKind::Keyword => 0u8,
            TokenKind::Identifier => 1,
            TokenKind::Number => 2,
            TokenKind::String => 3,
            TokenKind::Operator => 4,
            TokenKind::Punctuation => 5,
            TokenKind::Other => 6,
        };
        match token.kind {
            TokenKind::Identifier | TokenKind::Number | TokenKind::String => (kind, ""),
            _ => (kind, token.text.as_str()),
        }
    }

    /// Similarity for two equal-role token sequences, or `None` when the pair
    /// is proven unable to reach [`Self::min_similarity`].
    ///
    /// The ratio is the standard matching-ratio scaling of the longest common
    /// subsequence, `2 * matched / (len_a + len_b)`: equal-length sequences
    /// that match token for token score 1.0, sequences that share nothing
    /// score 0.0.
    ///
    /// Two sound bounds prune before or during the LCS:
    ///
    /// * a common subsequence can never be longer than the shorter sequence,
    ///   so `2 * min(len_a, len_b) / (len_a + len_b)` bounds the ratio from
    ///   above and is checked in `O(1)`;
    /// * [`Self::match_floor`] is the smallest match count that could clear
    ///   the threshold, and the LCS abandons a row as soon as reaching it is
    ///   no longer possible.
    ///
    /// [`Self::pair_similarity`] runs the label-multiset bound first, which
    /// is a third sound bound and the cheapest of the three.
    fn range_similarity(
        &self,
        first: &[Token],
        second: &[Token],
        lcs: &mut LcsRows,
    ) -> Option<f64> {
        if first.is_empty() || second.is_empty() {
            return None;
        }

        let total = first.len() + second.len();
        let longest_possible = first.len().min(second.len());
        let floor = Self::match_floor(self.min_similarity, total, longest_possible);
        if longest_possible < floor {
            return None;
        }

        let matched = lcs.length(first, second, floor);
        if matched < floor {
            return None;
        }

        let similarity = 2.0 * matched as f64 / total as f64;
        (similarity >= self.min_similarity).then_some(similarity)
    }

    /// Smallest match count whose similarity clears `min_similarity` for two
    /// sequences of `total` tokens, capped at `max_matches`.
    ///
    /// Found by a forward search instead of `ceil` so that a floating-point
    /// rounding artefact cannot push the cutoff one match too high and drop a
    /// pair sitting exactly on the threshold.
    fn match_floor(min_similarity: f64, total: usize, max_matches: usize) -> usize {
        let mut floor = 0;
        while floor < max_matches && (2.0 * floor as f64) / (total as f64) < min_similarity {
            floor += 1;
        }
        floor
    }

    /// Classify a clone pair from its normalized-sequence similarity.
    ///
    /// | similarity | type |
    /// |---|---|
    /// | `TYPE1_SIMILARITY` (0.98) and above | [`CloneType::Type1`] |
    /// | `TYPE2_SIMILARITY` (0.85) to 0.98 | [`CloneType::Type2`] |
    /// | `TYPE3_SIMILARITY` (0.75) to 0.85 | [`CloneType::Type3`] |
    /// | below `TYPE3_SIMILARITY` | [`CloneType::Type4`] |
    ///
    /// The bands are unchanged from the pre-near-miss detector. Two naming
    /// caveats are inherited with them and recorded here rather than hidden:
    /// because identifiers are compared by role, a rename-only copy scores
    /// 1.0 and is reported Type-1 (Type-2 is reached by pairs that differ in a
    /// couple of structural tokens), and Type-4 is unreachable at the default
    /// threshold because `TYPE3_SIMILARITY` is also the reporting floor.
    fn classify_clone(similarity: f64) -> CloneType {
        if similarity >= TYPE1_SIMILARITY {
            CloneType::Type1
        } else if similarity >= TYPE2_SIMILARITY {
            CloneType::Type2
        } else if similarity >= TYPE3_SIMILARITY {
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

/// Byte offset of the first character of each line in `content`, in order.
fn line_starts(content: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(content.match_indices('\n').map(|(offset, _)| offset + 1))
        .collect()
}

/// 1-indexed number of the line containing byte offset `offset`.
fn line_for(line_starts: &[usize], offset: usize) -> usize {
    line_starts.partition_point(|&start| start <= offset)
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

/// A code block: a half-open range of the token stream plus its line span.
#[derive(Debug, Clone)]
struct CodeBlock {
    start_token: usize,
    end_token: usize,
    start_line: usize,
    end_line: usize,
}

/// Rolling-row scratch space for the longest-common-subsequence length.
///
/// `CloneDetector::find_clones` holds a single instance for the whole
/// pairing loop, so comparing a block pair allocates nothing.
#[derive(Debug)]
struct LcsRows {
    previous: Vec<usize>,
    current: Vec<usize>,
}

impl LcsRows {
    /// Allocate scratch space wide enough for sequences of `width` tokens.
    fn new(width: usize) -> Self {
        Self {
            previous: vec![0; width + 1],
            current: vec![0; width + 1],
        }
    }

    /// Length of the longest common subsequence of `a` and `b`, where two
    /// elements match when [`CloneDetector::tokens_match`] says so.
    ///
    /// `floor` is the smallest match count that could still clear the
    /// caller's similarity threshold; the scan abandons a row as soon as
    /// matching every remaining element of `a` cannot reach it, and the value
    /// returned then is below `floor` and must not be read as a true LCS.
    /// With `floor == 0` the scan always runs to completion and the result is
    /// exact.
    ///
    /// Cost: `O(a.len() * b.len())` time, `O(b.len())` space.
    fn length(&mut self, a: &[Token], b: &[Token], floor: usize) -> usize {
        if a.is_empty() || b.is_empty() {
            return 0;
        }

        if self.previous.len() < b.len() + 1 {
            self.previous.resize(b.len() + 1, 0);
            self.current.resize(b.len() + 1, 0);
        }
        self.previous[..=b.len()].fill(0);

        for (i, symbol) in a.iter().enumerate() {
            self.current[0] = 0;
            let mut row_best = 0;
            for j in 1..=b.len() {
                self.current[j] = if CloneDetector::tokens_match(symbol, &b[j - 1]) {
                    self.previous[j - 1] + 1
                } else {
                    self.previous[j].max(self.current[j - 1])
                };
                row_best = row_best.max(self.current[j]);
            }
            std::mem::swap(&mut self.previous, &mut self.current);

            // Sound cutoff: a common subsequence that extends the best one
            // found so far can add at most one element per remaining element
            // of `a`, so if even that cannot reach `floor` the pair is out.
            if row_best + (a.len() - i - 1) < floor {
                return row_best;
            }
        }

        self.previous[b.len()]
    }
}

/// Scratch space for one detection run: comparison labels, the multiset
/// counters they index, and the rolling LCS rows.
///
/// `CloneDetector::find_clones` builds it once, so comparing a block pair
/// allocates nothing.
#[derive(Debug)]
struct PairingScratch<'a> {
    /// Comparison label id of every token in the source, in order.
    labels: &'a [usize],
    /// Per-label token counts, reused across block pairs.
    counts: Vec<usize>,
    /// The labels `counts` was touched with, reused across block pairs.
    touched: Vec<usize>,
    /// Rolling rows for the longest-common-subsequence length.
    lcs: LcsRows,
}

impl PairingScratch<'_> {
    /// Upper bound on the longest common subsequence of two token ranges,
    /// taken from their label multisets: a common subsequence can use a label
    /// no more often than it occurs in each range, so summing the per-label
    /// minima bounds it from above. Two ranges that share few labels are
    /// rejected here without running the LCS.
    ///
    /// `counts` is scratch space indexed by label id and `touched` records
    /// which slots were used, so the pairing loop reuses both across pairs
    /// without reallocating. Cost: `O(first.len() + second.len())`.
    fn multiset_bound(&mut self, first: &[usize], second: &[usize]) -> usize {
        self.touched.clear();
        for id in first {
            let slot = &mut self.counts[*id];
            if *slot == 0 {
                self.touched.push(*id);
            }
            *slot += 1;
        }

        let mut bound = 0;
        for id in second {
            let slot = &mut self.counts[*id];
            if *slot > 0 {
                *slot -= 1;
                bound += 1;
            }
        }

        for id in &self.touched {
            self.counts[*id] = 0;
        }
        bound
    }
}

/// Clone detection error
#[derive(Debug, thiserror::Error)]
pub enum CloneError {
    /// The source file could not be read from disk; wraps the underlying
    /// [`std::io::Error`].
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = CloneDetector::new();
        assert!((detector.min_similarity - 0.75).abs() < f64::EPSILON);
        let _ = detector;
    }

    #[test]
    fn test_detector_with_options() {
        let detector = CloneDetector::new()
            .with_min_similarity(0.9)
            .with_min_tokens(5);
        assert!((detector.min_similarity - 0.9).abs() < f64::EPSILON);
        let _ = detector;
    }

    #[test]
    fn test_identical_code_detection() {
        let detector = CloneDetector::new();
        let content = r#"
fn foo() {
    let x = 1;
    let y = 2;
    let width = measure(x, y);
    let height = measure(y, x);
    println!("{} {}", width, height);
}

fn bar() {
    let a = 1;
    let b = 2;
    let span = measure(a, b);
    let reach = measure(b, a);
    println!("{} {}", span, reach);
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
                file: String::new(),
                start_line: 1,
                end_line: 1,
                function: None,
            },
            location2: CloneLocation {
                file: String::new(),
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
        assert!((detector.min_similarity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_clone_detector_default() {
        let detector = CloneDetector::default();
        assert!((detector.min_similarity - 0.75).abs() < f64::EPSILON);
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
        let debug_str = format!("{clone:?}");
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
    fn test_clone_type_kind_names() {
        assert_eq!(CloneType::Type1.kind_name(), "type-1");
        assert_eq!(CloneType::Type2.kind_name(), "type-2");
        assert_eq!(CloneType::Type3.kind_name(), "type-3");
        assert_eq!(CloneType::Type4.kind_name(), "type-4");
    }

    #[test]
    fn test_clone_report_from_code_clone() {
        let clone = CodeClone {
            clone_type: CloneType::Type3,
            location1: CloneLocation {
                file: "a.rs".to_string(),
                start_line: 2,
                end_line: 12,
                function: None,
            },
            location2: CloneLocation {
                file: "a.rs".to_string(),
                start_line: 20,
                end_line: 31,
                function: None,
            },
            similarity: 0.857_491_2,
            token_count: 40,
        };

        let report = CloneReport::from_code_clone(&clone);
        assert_eq!(report.kind, "type-3");
        assert_eq!(report.description, CloneType::Type3.description());
        assert!((report.similarity - 0.8575).abs() < 1e-9);
        assert_eq!(report.token_count, 40);
        assert_eq!(report.locations.len(), 2);
        assert_eq!(report.locations[0].file, "a.rs");
        assert_eq!(report.locations[0].start_line, 2);
        assert_eq!(report.locations[0].end_line, 12);
        assert_eq!(report.locations[1].start_line, 20);
        assert_eq!(report.locations[1].end_line, 31);
    }

    #[test]
    fn test_clone_report_serialization_shape() {
        let clone = CodeClone {
            clone_type: CloneType::Type1,
            location1: CloneLocation {
                file: "x.rs".to_string(),
                start_line: 1,
                end_line: 5,
                function: None,
            },
            location2: CloneLocation {
                file: "x.rs".to_string(),
                start_line: 10,
                end_line: 14,
                function: None,
            },
            similarity: 1.0,
            token_count: 40,
        };

        let json = serde_json::to_value(CloneReport::from_code_clone(&clone)).unwrap();
        assert_eq!(json["kind"], "type-1");
        assert_eq!(json["similarity"], 1.0);
        assert_eq!(json["token_count"], 40);
        assert_eq!(json["locations"][0]["file"], "x.rs");
        assert_eq!(json["locations"][0]["start_line"], 1);
        assert_eq!(json["locations"][1]["end_line"], 14);
        // The wire shape carries location lines only — no function field.
        assert!(json["locations"][0].get("function").is_none());
    }

    #[test]
    fn test_detect_file_nonexistent() {
        let detector = CloneDetector::new();
        let result = detector.detect_file(Path::new("/nonexistent/file.txt"));
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
        // Below the near-miss floor a pair is only reachable when the caller
        // lowers the threshold, and is then labelled Type-4.
        assert_eq!(CloneDetector::classify_clone(0.74), CloneType::Type4);
    }

    #[test]
    fn test_classify_clone_band_boundaries() {
        assert_eq!(CloneDetector::classify_clone(1.0), CloneType::Type1);
        assert_eq!(CloneDetector::classify_clone(0.98), CloneType::Type1);
        assert_eq!(CloneDetector::classify_clone(0.979), CloneType::Type2);
        assert_eq!(CloneDetector::classify_clone(0.85), CloneType::Type2);
        assert_eq!(CloneDetector::classify_clone(0.849), CloneType::Type3);
        assert_eq!(CloneDetector::classify_clone(0.75), CloneType::Type3);
    }

    /// Two straight-line functions that differ only in the names of their
    /// variables and callees.
    fn renamed_pair() -> String {
        String::from(
            r"
fn alpha() {
    let total = compute_total(price, quantity);
    let discount = apply_discount(total, rate);
    validate_discount(discount, ledger);
    publish_discount(ledger, receipt);
    return finalize(receipt, audit);
}

fn beta() {
    let sum = compute_total(cost, count);
    let rebate = apply_discount(sum, ratio);
    check_rebate(rebate, book);
    publish_rebate(book, token);
    return finalize(token, trail);
}
",
        )
    }

    #[test]
    fn test_renamed_identifiers_only_still_classify_as_before() {
        // A pure rename scores 1.0 on the aligned windows and is reported as
        // a Type-1 clone, exactly as the pre-near-miss detector reported it.
        let detector = CloneDetector::new();
        let clones = detector.detect_content(&renamed_pair(), "t.rs").unwrap();

        let best = &clones[0];
        assert_eq!(best.clone_type, CloneType::Type1);
        assert!((best.similarity - 1.0).abs() < f64::EPSILON);
        assert!(
            clones.iter().all(|c| c.similarity <= 1.0),
            "similarity must stay within [0, 1]"
        );
    }

    #[test]
    fn test_type3_reordered_statements_detected() {
        // The second function is the first with two statements swapped, so
        // the pair is a near miss rather than an exact clone.
        let content = r"
fn one() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    let stored = write_entry(stamped, journal);
    audit_entry(stored, sink);
    return stored;
}

fn two() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    audit_entry(stamped, sink);
    let stored = write_entry(stamped, journal);
    return stored;
}
";
        let detector = CloneDetector::new();
        let clones = detector.detect_content(content, "t.rs").unwrap();

        let near_misses: Vec<&CodeClone> = clones
            .iter()
            .filter(|c| c.clone_type == CloneType::Type3)
            .collect();
        assert!(
            !near_misses.is_empty(),
            "reordered statements must yield a near-miss clone, got {:?}",
            clones
                .iter()
                .map(|c| (c.clone_type, c.similarity))
                .collect::<Vec<_>>()
        );
        assert!(
            near_misses
                .iter()
                .all(|c| c.similarity >= TYPE3_SIMILARITY && c.similarity < TYPE2_SIMILARITY),
            "Type-3 similarity must sit in the near-miss band"
        );
    }

    #[test]
    fn test_type3_inserted_statement_detected() {
        // The second function carries one extra statement in the middle of an
        // otherwise verbatim copy.
        let content = r"
fn first() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    let stored = write_entry(stamped, journal);
    return stored;
}

fn second() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let quarantined = quarantine(parsed, rules);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    let stored = write_entry(stamped, journal);
    return stored;
}
";
        let detector = CloneDetector::new();
        let clones = detector.detect_content(content, "t.rs").unwrap();
        assert!(
            clones
                .iter()
                .any(|c| c.clone_type == CloneType::Type3 && c.similarity < TYPE2_SIMILARITY),
            "an inserted statement must yield a near-miss clone, got {:?}",
            clones
                .iter()
                .map(|c| (c.clone_type, c.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_unrelated_blocks_are_not_reported() {
        // Two functions that share nothing but idiomatic statement shapes.
        // Under the previous bag-of-tokens score this pair reported as a
        // Type-1 clone at similarity 1.0.
        let content = r"
fn loader() {
    let raw = read_config(path);
    if raw.is_empty() {
        return Config::default();
    }
    let parsed = parse_yaml(raw);
    for entry in parsed.entries {
        merge_defaults(entry, profile);
    }
    return parsed;
}

fn renderer() {
    while let Some(event) = queue.pop() {
        match event.kind {
            Kind::Press => surface.draw(event.key),
            Kind::Release => surface.clear(event.key),
            Kind::Move => cursor.advance(event.delta),
        }
        frames.push(cursor.position());
    }
    flush(surface);
}
";
        let detector = CloneDetector::new();
        let clones = detector.detect_content(content, "t.rs").unwrap();
        assert!(
            clones.is_empty(),
            "unrelated functions must not be reported, got {:?}",
            clones
                .iter()
                .map(|c| (c.clone_type, c.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_exact_duplicate_is_type1() {
        let body = r"
fn original() {
    let payload = build_payload(headers, body);
    let signed = sign_payload(payload, private_key);
    let sent = transmit(signed, endpoint_url);
    verify_response(sent, expected_code);
    record_audit(sent, audit_log);
    return sent;
}
";
        let content = format!("{body}{body}");
        let detector = CloneDetector::new();
        let clones = detector.detect_content(&content, "t.rs").unwrap();

        assert!(
            clones.iter().any(|c| c.clone_type == CloneType::Type1),
            "a verbatim copy must contain a Type-1 clone, got {:?}",
            clones
                .iter()
                .map(|c| (c.clone_type, c.similarity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_min_similarity_gates_type3() {
        let content = r"
fn one() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    let stored = write_entry(stamped, journal);
    audit_entry(stored, sink);
    return stored;
}

fn two() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    let stamped = stamp_receipt(encoded, clock);
    audit_entry(stamped, sink);
    let stored = write_entry(stamped, journal);
    return stored;
}
";
        let permissive = CloneDetector::new();
        let strict = CloneDetector::new().with_min_similarity(0.95);

        let permissive_clones = permissive.detect_content(content, "t.rs").unwrap();
        let strict_clones = strict.detect_content(content, "t.rs").unwrap();

        assert!(
            permissive_clones
                .iter()
                .any(|c| c.clone_type == CloneType::Type3),
            "the default threshold must admit near-miss clones"
        );
        assert!(
            strict_clones
                .iter()
                .all(|c| c.similarity >= strict.min_similarity),
            "every reported pair must clear the configured threshold"
        );
        assert!(
            strict_clones
                .iter()
                .all(|c| c.clone_type != CloneType::Type3),
            "a threshold above the Type-2 band must suppress near-miss output"
        );
    }

    #[test]
    fn test_min_tokens_filters_small_blocks() {
        let content = "let alpha = one(beta, gamma); let delta = two(alpha, epsilon);";
        let detector = CloneDetector::new().with_min_tokens(30);
        let clones = detector.detect_content(content, "t.rs").unwrap();
        assert!(
            clones.is_empty(),
            "a block smaller than min_tokens must not be compared"
        );
    }

    #[test]
    fn test_empty_content_yields_no_clones() {
        let detector = CloneDetector::new();
        assert!(detector.detect_content("", "t.rs").unwrap().is_empty());
        assert!(detector
            .detect_content("\n\n  \n", "t.rs")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_multibyte_identifiers_are_detected() {
        let content = r"
fn αφη() {
    let κατάσταση = φόρτωση_ρυθμίσεων(διαδρομή);
    let συγχωνευμένη = συγχώνευση(κατάσταση, προφίλ);
    let ελεγμένη = επικύρωση(συγχωνευμένη, όριο);
    let πιστοποιημένη = υπογραφή(ελεγμένη, κλειδί);
    let αποθηκευμένη = καταχώρηση(πιστοποιημένη, ημερολόγιο);
    return ειδοποίηση(αποθηκευμένη, παραλήπτης);
}

fn βξζ() {
    let κατάσταση = φόρτωση_ρυθμίσεων(διαδρομή);
    let συγχωνευμένη = συγχώνευση(κατάσταση, προφίλ);
    let ελεγμένη = επικύρωση(συγχωνευμένη, όριο);
    let πιστοποιημένη = υπογραφή(ελεγμένη, κλειδί);
    let αποθηκευμένη = καταχώρηση(πιστοποιημένη, ημερολόγιο);
    return ειδοποίηση(αποθηκευμένη, παραλήπτης);
}
";
        let detector = CloneDetector::new();
        let clones = detector.detect_content(content, "t.rs").unwrap();
        assert!(
            clones.iter().any(|c| c.clone_type == CloneType::Type1),
            "multibyte identifiers must not break tokenization or detection, got {clones:?}"
        );
    }

    #[test]
    fn test_report_is_capped_per_file() {
        // One body repeated far past the cap: every surviving window pair is
        // a verbatim match, so collection would run the full quadratic grid
        // — 256 blocks would mean 32k+ pairs — if it were uncapped.
        let body = r"
fn original() {
    let payload = build_payload(headers, body);
    let signed = sign_payload(payload, private_key);
    let sent = transmit(signed, endpoint_url);
    verify_response(sent, expected_code);
    record_audit(sent, audit_log);
    return sent;
}
";
        let content = body.repeat(400);
        let detector = CloneDetector::new();
        let clones = detector.detect_content(&content, "t.rs").unwrap();

        assert_eq!(
            clones.len(),
            MAX_REPORTED_CLONES,
            "a pathological file must stop reporting at the per-file cap"
        );
        // Repetition seams and non-phase-aligned windows score below 1.0, so
        // the mix spans the bands — but nothing below the reporting floor
        // may be in the list.
        assert!(
            clones.iter().all(|c| c.similarity >= 0.75),
            "every capped pair must clear the similarity floor, got {:?}",
            clones.iter().map(|c| c.similarity).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_clone_locations_point_at_the_copied_lines() {
        let body = r"
fn original() {
    let payload = build_payload(headers, body);
    let signed = sign_payload(payload, private_key);
    let sent = transmit(signed, endpoint_url);
    verify_response(sent, expected_code);
    record_audit(sent, audit_log);
    return sent;
}
";
        let content = format!("{body}{body}");
        let detector = CloneDetector::new();
        let clones = detector.detect_content(&content, "t.rs").unwrap();

        let best = &clones[0];
        // `body` opens with a leading newline, so the copy starts on line 11
        // of the concatenation; every reported span must sit on real lines.
        assert_eq!(best.location1.start_line, 2);
        assert_eq!(best.location2.start_line, 12);
        assert!(best.location1.end_line >= best.location1.start_line);
        assert!(best.location2.end_line >= best.location2.start_line);
    }

    #[test]
    fn test_similarity_is_symmetric() {
        let content = r"
fn one() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    return encoded;
}

fn two() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    audit_entry(checked, sink);
    return encoded;
}
";
        // A zero floor disables every prune, so the raw ratio comes back for
        // both orders.
        let tokens = CloneDetector::tokenize(content);
        assert!(tokens.len() > BLOCK_SIZE + 1, "fixture must span a block");
        let mut lcs = LcsRows::new(BLOCK_SIZE);

        let split = tokens.len() / 2;
        let forward = lcs.length(&tokens[..split], &tokens[split..], 0);
        let reverse = lcs.length(&tokens[split..], &tokens[..split], 0);
        assert_eq!(forward, reverse, "the LCS must be symmetric");
        assert!(
            forward > 0,
            "the halves of one file must produce a non-empty LCS"
        );
    }

    #[test]
    fn test_match_floor_reaches_the_threshold_exactly() {
        // Two 40-token blocks: 30 matched tokens is exactly 0.75 similarity,
        // so the floor must be 30 and a pair matching 30 of 40 must survive.
        assert_eq!(CloneDetector::match_floor(0.75, 80, 40), 30);
        assert_eq!(CloneDetector::match_floor(0.98, 80, 40), 40);
        assert_eq!(CloneDetector::match_floor(0.85, 80, 40), 34);
        assert_eq!(CloneDetector::match_floor(0.0, 80, 40), 0);
        // An unreachable threshold is capped, and the caller's own
        // similarity comparison rejects the pair afterwards.
        assert_eq!(CloneDetector::match_floor(2.0, 80, 40), 40);
    }

    #[test]
    fn test_multiset_bound_never_undercounts_the_lcs() {
        let content = r"
fn one() {
    let parsed = read_config(raw_path);
    let merged = merge_defaults(parsed, profile);
    let checked = validate_limits(merged, budget);
    let encoded = encode_payload(checked, codec);
    return encoded;
}

fn two() {
    while let Some(event) = queue.pop() {
        match event.kind {
            Kind::Press => surface.draw(event.key),
            Kind::Release => surface.clear(event.key),
        }
        frames.push(cursor.position());
    }
    flush(surface);
}
";
        let tokens = CloneDetector::tokenize(content);
        let (labels, distinct) = CloneDetector::label_tokens(&tokens);
        let mut scratch = PairingScratch {
            labels: &labels,
            counts: vec![0; distinct],
            touched: Vec::new(),
            lcs: LcsRows::new(BLOCK_SIZE),
        };

        let tail = tokens.len() - BLOCK_SIZE;
        let bound = scratch.multiset_bound(&labels[..BLOCK_SIZE], &labels[tail..]);
        let matched = scratch
            .lcs
            .length(&tokens[..BLOCK_SIZE], &tokens[tail..], 0);
        assert!(
            bound >= matched,
            "the multiset bound must not fall below the LCS: {bound} < {matched}"
        );
        assert_eq!(
            scratch.multiset_bound(&labels[..BLOCK_SIZE], &labels[..BLOCK_SIZE]),
            BLOCK_SIZE,
            "identical ranges must reach the range length"
        );
        // The scratch space must be left clean for the next pair.
        assert!(scratch.counts.iter().all(|count| *count == 0));
    }

    #[test]
    fn test_lcs_rows_match_by_role_and_text() {
        let id_a = Token {
            start: 0,
            end: 1,
            text: "alpha".to_string(),
            kind: TokenKind::Identifier,
        };
        let id_b = Token {
            start: 2,
            end: 3,
            text: "beta".to_string(),
            kind: TokenKind::Identifier,
        };
        let keyword = Token {
            start: 4,
            end: 5,
            text: "let".to_string(),
            kind: TokenKind::Keyword,
        };
        let other = Token {
            start: 6,
            end: 7,
            text: "return".to_string(),
            kind: TokenKind::Keyword,
        };

        assert!(CloneDetector::tokens_match(&id_a, &id_b));
        assert!(!CloneDetector::tokens_match(&keyword, &other));

        let mut rows = LcsRows::new(BLOCK_SIZE);
        let a = vec![keyword.clone(), id_a.clone(), other.clone()];
        let b = vec![keyword.clone(), id_b.clone(), other.clone()];
        assert_eq!(rows.length(&a, &b, 0), 3, "renamed identifiers still match");
    }
}
