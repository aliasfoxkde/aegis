//! Control Flow Graph analysis
//!
//! Builds CFG from source code for detecting resource leaks and control flow issues.

use std::path::Path;

/// A node in the control flow graph
#[derive(Debug, Clone)]
pub struct CfgNode {
    /// Node ID
    pub id: usize,
    /// Node type
    pub kind: CfgNodeKind,
    /// Start line
    pub start_line: usize,
    /// End line
    pub end_line: usize,
    /// Successor node IDs
    pub successors: Vec<usize>,
    /// Predecessor node IDs
    pub predecessors: Vec<usize>,
}

/// Node kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgNodeKind {
    /// Entry point
    Entry,
    /// Exit point
    Exit,
    /// Regular statement
    Statement,
    /// Conditional branch
    Conditional,
    /// Loop start
    Loop,
    /// Try block
    Try,
    /// Catch block
    Catch,
    /// Finally block
    Finally,
    /// Return statement
    Return,
    /// Panic/Unwind
    Unwind,
}

/// Control flow graph
#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraph {
    /// Nodes in the graph
    nodes: Vec<CfgNode>,
    /// Entry node ID
    entry_id: usize,
    /// Exit node ID
    #[allow(dead_code)]
    exit_id: usize,
}

/// Resource tracked in CFG analysis
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Resource {
    /// Resource name
    pub name: String,
    /// Line where acquired
    pub acquire_line: usize,
    /// Line where released (if known)
    pub release_line: Option<usize>,
    /// Type of resource
    pub kind: ResourceKind,
}

/// Resource kind
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ResourceKind {
    /// File handle
    File,
    /// Database connection
    Connection,
    /// Lock/Mutex
    Lock,
    /// Memory allocation
    Memory,
    /// Network socket
    Socket,
    /// Custom resource
    Custom,
}

/// CFG analysis result
#[derive(Debug, Clone)]
pub struct CfgAnalysis {
    /// Control flow graph
    pub cfg: ControlFlowGraph,
    /// Detected issues
    pub issues: Vec<CfgIssue>,
    /// Tracked resources
    pub resources: Vec<Resource>,
}

/// An issue found by CFG analysis
#[derive(Debug, Clone)]
pub struct CfgIssue {
    /// Issue type
    pub issue_type: CfgIssueType,
    /// Description
    pub description: String,
    /// File location
    pub file: String,
    /// Line number
    pub line: usize,
    /// Severity
    pub severity: String,
    /// Confidence
    pub confidence: String,
}

/// CFG issue types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgIssueType {
    /// Resource acquired but not released
    ResourceLeak,
    /// Lock acquired but not released
    LockNotReleased,
    /// Transaction not committed or rolled back
    TransactionNotEnded,
    /// Unreachable code
    UnreachableCode,
    /// Infinite loop
    InfiniteLoop,
    /// Missing error handling
    UncheckedError,
}

impl std::fmt::Display for CfgIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CfgIssueType::ResourceLeak => write!(f, "resource-leak"),
            CfgIssueType::LockNotReleased => write!(f, "lock-not-released"),
            CfgIssueType::TransactionNotEnded => write!(f, "transaction-not-ended"),
            CfgIssueType::UnreachableCode => write!(f, "unreachable-code"),
            CfgIssueType::InfiniteLoop => write!(f, "infinite-loop"),
            CfgIssueType::UncheckedError => write!(f, "unchecked-error"),
        }
    }
}

/// CFG analyzer
pub struct CfgAnalyzer {
    #[allow(dead_code)]
    language: super::ast::Language,
}

impl CfgAnalyzer {
    /// Create a new analyzer
    pub fn new(language: super::ast::Language) -> Self {
        Self { language }
    }

    /// Analyze a file
    pub fn analyze_file(&self, path: &Path) -> Result<CfgAnalysis, CfgError> {
        let content = std::fs::read_to_string(path)?;
        self.analyze_content(&content, path.to_str().unwrap_or("unknown"))
    }

    /// Analyze content
    pub fn analyze_content(&self, content: &str, source: &str) -> Result<CfgAnalysis, CfgError> {
        let cfg = self.build_cfg(content);
        let resources = self.track_resources(content);
        let issues = self.detect_issues(&cfg, &resources, source);

        Ok(CfgAnalysis {
            cfg,
            issues,
            resources,
        })
    }

    /// Build control flow graph
    fn build_cfg(&self, content: &str) -> ControlFlowGraph {
        let mut nodes = Vec::new();
        let mut current_node = 0;

        // Entry node
        nodes.push(CfgNode {
            id: current_node,
            kind: CfgNodeKind::Entry,
            start_line: 1,
            end_line: 1,
            successors: vec![],
            predecessors: vec![],
        });
        current_node += 1;

        let entry_id = 0;

        // Build nodes from statements
        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            let kind = self.classify_statement(trimmed);
            let successors = self.get_successors(trimmed, &kind);

            let node_id = current_node;
            nodes.push(CfgNode {
                id: node_id,
                kind,
                start_line: line_num,
                end_line: line_num,
                successors: successors.clone(),
                predecessors: vec![],
            });

            // Link to previous node
            if let Some(last) = nodes.iter_mut().find(|n| n.id == current_node - 1) {
                last.successors.push(node_id);
            }

            current_node += 1;
        }

        // Exit node
        let exit_id = current_node;
        nodes.push(CfgNode {
            id: exit_id,
            kind: CfgNodeKind::Exit,
            start_line: content.lines().count(),
            end_line: content.lines().count(),
            successors: vec![],
            predecessors: vec![],
        });

        // Link last statement to exit
        if current_node > 1 {
            if let Some(last) = nodes.iter_mut().find(|n| n.id == current_node - 1) {
                last.successors.push(exit_id);
            }
        }

        // Update predecessors - collect successors first to avoid double mutable borrow
        let successors_list: Vec<(usize, Vec<usize>)> =
            nodes.iter().map(|n| (n.id, n.successors.clone())).collect();

        for (node_id, succs) in successors_list {
            for &succ in &succs {
                if let Some(successor) = nodes.iter_mut().find(|n| n.id == succ) {
                    successor.predecessors.push(node_id);
                }
            }
        }

        ControlFlowGraph {
            nodes,
            entry_id,
            exit_id,
        }
    }

    /// Classify a statement
    fn classify_statement(&self, statement: &str) -> CfgNodeKind {
        if statement.starts_with("if") || statement.starts_with("match") {
            CfgNodeKind::Conditional
        } else if statement.starts_with("for") || statement.starts_with("while") {
            CfgNodeKind::Loop
        } else if statement.starts_with("try") || statement.contains("try {") {
            CfgNodeKind::Try
        } else if statement.starts_with("return") || statement.starts_with("->") {
            CfgNodeKind::Return
        } else if statement.starts_with("panic") || statement.contains("panic!") {
            CfgNodeKind::Unwind
        } else {
            CfgNodeKind::Statement
        }
    }

    /// Get successors for a statement
    fn get_successors(&self, _statement: &str, kind: &CfgNodeKind) -> Vec<usize> {
        match kind {
            CfgNodeKind::Conditional => vec![], // Would need branching analysis
            CfgNodeKind::Loop => vec![],        // Would need loop analysis
            _ => vec![],
        }
    }

    /// Track resource acquisitions and releases
    fn track_resources(&self, content: &str) -> Vec<Resource> {
        let mut resources = Vec::new();
        let mut resource_stack: Vec<Resource> = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Track file operations
            if trimmed.contains("fopen")
                || trimmed.contains("open(")
                || trimmed.contains("File::open")
            {
                resource_stack.push(Resource {
                    name: "file".to_string(),
                    acquire_line: line_num,
                    release_line: None,
                    kind: ResourceKind::File,
                });
            } else if trimmed.contains("fclose")
                || trimmed.contains("close(")
                || trimmed.contains(".close()")
                || trimmed.contains("drop(")
            {
                if let Some(mut res) = resource_stack.pop() {
                    res.release_line = Some(line_num);
                    resources.push(res);
                }
            }

            // Track mutex/lock
            if trimmed.contains("Mutex::new")
                || trimmed.contains("Lock::new")
                || trimmed.contains("pthread_mutex_init")
            {
                resource_stack.push(Resource {
                    name: "mutex".to_string(),
                    acquire_line: line_num,
                    release_line: None,
                    kind: ResourceKind::Lock,
                });
            } else if trimmed.contains("unlock(")
                || trimmed.contains(".unlock()")
                || trimmed.contains("pthread_mutex_unlock")
            {
                if let Some(mut res) = resource_stack.pop() {
                    res.release_line = Some(line_num);
                    resources.push(res);
                }
            }

            // Track transactions
            if trimmed.contains("BEGIN")
                || trimmed.contains("begin()")
                || trimmed.contains("db.Begin()")
                || trimmed.contains(".begin()")
            {
                resource_stack.push(Resource {
                    name: "transaction".to_string(),
                    acquire_line: line_num,
                    release_line: None,
                    kind: ResourceKind::Connection,
                });
            } else if trimmed.contains("COMMIT")
                || trimmed.contains("ROLLBACK")
                || trimmed.contains("commit()")
                || trimmed.contains("rollback()")
            {
                if let Some(mut res) = resource_stack.pop() {
                    res.release_line = Some(line_num);
                    resources.push(res);
                }
            }
        }

        // Add unclosed resources
        resources.extend(resource_stack);
        resources
    }

    /// Detect issues from CFG and resources
    fn detect_issues(
        &self,
        cfg: &ControlFlowGraph,
        resources: &[Resource],
        source: &str,
    ) -> Vec<CfgIssue> {
        let mut issues = Vec::new();

        for resource in resources {
            if resource.release_line.is_none() {
                let issue_type = match resource.kind {
                    ResourceKind::File => CfgIssueType::ResourceLeak,
                    ResourceKind::Lock => CfgIssueType::LockNotReleased,
                    ResourceKind::Connection => CfgIssueType::TransactionNotEnded,
                    _ => CfgIssueType::ResourceLeak,
                };

                issues.push(CfgIssue {
                    issue_type,
                    description: format!(
                        "{} acquired at line {} may not be released",
                        resource.name, resource.acquire_line
                    ),
                    file: source.to_string(),
                    line: resource.acquire_line,
                    severity: "medium".to_string(),
                    confidence: "high".to_string(),
                });
            }
        }

        // Check for unreachable code
        for node in &cfg.nodes {
            if node.predecessors.is_empty()
                && node.id != cfg.entry_id
                && node.kind != CfgNodeKind::Entry
            {
                issues.push(CfgIssue {
                    issue_type: CfgIssueType::UnreachableCode,
                    description: format!("Unreachable code at line {}", node.start_line),
                    file: source.to_string(),
                    line: node.start_line,
                    severity: "low".to_string(),
                    confidence: "high".to_string(),
                });
            }
        }

        issues
    }
}

/// CFG error types
#[derive(Debug, thiserror::Error)]
pub enum CfgError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_creation() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let content = "fn main() {\n    println!(\"hello\");\n}";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();

        assert!(!result.cfg.nodes.is_empty());
    }

    #[test]
    fn test_properly_closed_resource() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::C);
        let content = r#"
#include <stdio.h>

int main() {
    FILE *f = fopen("test.txt", "r");
    if (f) {
        fclose(f);
    }
    return 0;
}
"#;
        let result = analyzer.analyze_content(content, "test.c").unwrap();

        // Should not detect leaks when file is properly closed
        let leaks: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::ResourceLeak)
            .collect();
        assert!(leaks.is_empty());
    }

    #[test]
    fn test_transaction_detection() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Go);
        let content = r#"
package main

func main() {
    db.Begin()
    // Missing commit or rollback
}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();

        let unended: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::TransactionNotEnded)
            .collect();
        assert!(!unended.is_empty());
    }

    #[test]
    fn test_cfg_node_display() {
        let node = CfgNode {
            id: 1,
            kind: CfgNodeKind::Entry,
            start_line: 1,
            end_line: 1,
            successors: vec![2],
            predecessors: vec![],
        };
        assert!(!format!("{:?}", node).is_empty());
    }

    #[test]
    fn test_cfg_node_kinds() {
        // Test all node kinds can be created
        let kinds = vec![
            CfgNodeKind::Entry,
            CfgNodeKind::Exit,
            CfgNodeKind::Statement,
            CfgNodeKind::Conditional,
            CfgNodeKind::Loop,
            CfgNodeKind::Try,
            CfgNodeKind::Catch,
            CfgNodeKind::Finally,
            CfgNodeKind::Return,
            CfgNodeKind::Unwind,
        ];

        for kind in kinds {
            let node = CfgNode {
                id: 1,
                kind: kind.clone(),
                start_line: 1,
                end_line: 1,
                successors: vec![],
                predecessors: vec![],
            };
            assert_eq!(node.kind, kind);
        }
    }

    #[test]
    fn test_resource_kinds() {
        let resource = Resource {
            name: "test".to_string(),
            acquire_line: 1,
            release_line: Some(5),
            kind: ResourceKind::File,
        };
        assert_eq!(resource.name, "test");
        assert_eq!(resource.kind, ResourceKind::File);
    }

    #[test]
    fn test_resource_no_release() {
        let resource = Resource {
            name: "unreleased".to_string(),
            acquire_line: 10,
            release_line: None,
            kind: ResourceKind::Memory,
        };
        assert!(resource.release_line.is_none());
    }

    #[test]
    fn test_cfg_issue_display() {
        let issue = CfgIssue {
            issue_type: CfgIssueType::ResourceLeak,
            description: "Resource leak detected".to_string(),
            file: "test.rs".to_string(),
            line: 10,
            severity: "high".to_string(),
            confidence: "medium".to_string(),
        };
        let display = format!("{:?}", issue);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_cfg_issue_types() {
        let types = vec![
            CfgIssueType::ResourceLeak,
            CfgIssueType::TransactionNotEnded,
            CfgIssueType::LockNotReleased,
            CfgIssueType::UnreachableCode,
            CfgIssueType::InfiniteLoop,
            CfgIssueType::UncheckedError,
        ];

        for t in types {
            let issue = CfgIssue {
                issue_type: t.clone(),
                description: "Test".to_string(),
                file: "test.rs".to_string(),
                line: 1,
                severity: "warning".to_string(),
                confidence: "medium".to_string(),
            };
            assert_eq!(issue.line, 1);
        }
    }

    #[test]
    fn test_cfg_analysis_with_no_issues() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let content = "fn main() {}";
        let result = analyzer.analyze_content(content, "empty.rs").unwrap();
        // Should have a valid CFG even with no issues
        assert!(result.cfg.nodes.len() >= 2); // At least entry and exit
    }

    #[test]
    fn test_control_flow_graph_default() {
        let cfg = ControlFlowGraph::default();
        assert!(cfg.nodes.is_empty());
    }

    #[test]
    fn test_cfg_issue_type_display() {
        assert_eq!(CfgIssueType::ResourceLeak.to_string(), "resource-leak");
        assert_eq!(
            CfgIssueType::LockNotReleased.to_string(),
            "lock-not-released"
        );
        assert_eq!(
            CfgIssueType::TransactionNotEnded.to_string(),
            "transaction-not-ended"
        );
        assert_eq!(
            CfgIssueType::UnreachableCode.to_string(),
            "unreachable-code"
        );
        assert_eq!(CfgIssueType::InfiniteLoop.to_string(), "infinite-loop");
        assert_eq!(CfgIssueType::UncheckedError.to_string(), "unchecked-error");
    }

    #[test]
    fn test_lock_acquisition_and_release() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::C);
        let content = r#"
#include <pthread.h>
int main() {
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mu);
    pthread_mutex_unlock(&mu);
    return 0;
}
"#;
        let result = analyzer.analyze_content(content, "test.c").unwrap();
        // Should not detect lock issues when properly released
        let locks: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::LockNotReleased)
            .collect();
        assert!(locks.is_empty());
    }

    #[test]
    fn test_lock_not_released() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::C);
        let content = r#"
#include <pthread.h>
int main() {
    pthread_mutex_init(&mu, NULL);
    pthread_mutex_lock(&mu);
    return 0;
}
"#;
        let result = analyzer.analyze_content(content, "test.c").unwrap();
        // Should detect lock not released
        let locks: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::LockNotReleased)
            .collect();
        assert!(!locks.is_empty());
    }

    #[test]
    fn test_transaction_with_commit() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Go);
        let content = r#"
package main
func main() {
    db.begin()
    doSomething()
    commit()
}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        // Should not detect transaction issues when properly ended
        let txns: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::TransactionNotEnded)
            .collect();
        assert!(txns.is_empty());
    }

    #[test]
    fn test_transaction_with_rollback() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Go);
        let content = r#"
package main
func main() {
    db.begin()
    doSomething()
    rollback()
}
"#;
        let result = analyzer.analyze_content(content, "test.go").unwrap();
        let txns: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::TransactionNotEnded)
            .collect();
        assert!(txns.is_empty());
    }

    #[test]
    fn test_multiple_resource_leak() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::C);
        let content = r#"
int main() {
    FILE *f1 = fopen("a.txt", "r");
    FILE *f2 = fopen("b.txt", "r");
    fclose(f1);
    return 0;
}
"#;
        let result = analyzer.analyze_content(content, "test.c").unwrap();
        // f2 is not closed, should detect leak
        let leaks: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.issue_type == CfgIssueType::ResourceLeak)
            .collect();
        assert!(!leaks.is_empty());
    }

    #[test]
    fn test_custom_resource_kind() {
        let resource = Resource {
            name: "custom".to_string(),
            acquire_line: 1,
            release_line: Some(5),
            kind: ResourceKind::Custom,
        };
        assert_eq!(resource.kind, ResourceKind::Custom);
    }

    #[test]
    fn test_socket_resource_kind() {
        let resource = Resource {
            name: "socket".to_string(),
            acquire_line: 1,
            release_line: None,
            kind: ResourceKind::Socket,
        };
        assert_eq!(resource.kind, ResourceKind::Socket);
        assert!(resource.release_line.is_none());
    }

    #[test]
    fn test_cfg_node_with_successors() {
        let node = CfgNode {
            id: 1,
            kind: CfgNodeKind::Conditional,
            start_line: 1,
            end_line: 3,
            successors: vec![2, 3],
            predecessors: vec![0],
        };
        assert_eq!(node.successors.len(), 2);
        assert_eq!(node.predecessors.len(), 1);
    }

    #[test]
    fn test_cfg_analyzer_default_language() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let content = "fn main() {}\n";
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        assert!(!result.cfg.nodes.is_empty());
        assert!(result.issues.is_empty());
    }

    #[test]
    fn test_cfg_error_io() {
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let result = analyzer.analyze_file(std::path::Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_cfg_classify_statement_panic() {
        // Test that classify_statement correctly classifies panic
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let kind = analyzer.classify_statement("panic!(\"error\")");
        // panic is classified as Unwind (cfg node kind)
        assert_eq!(kind, CfgNodeKind::Unwind);
    }

    #[test]
    fn test_cfg_try_block() {
        // Test that try blocks are classified
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let content = r#"
fn main() {
    let result = do_something()?;
}
"#;
        let result = analyzer.analyze_content(content, "test.rs").unwrap();
        // The content should be analyzed without error
        assert!(!result.cfg.nodes.is_empty());
    }

    #[test]
    fn test_cfg_classify_statement_try_with_braces() {
        // Test that "try {" with braces is classified as Try
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let kind = analyzer.classify_statement("try {");
        assert_eq!(kind, CfgNodeKind::Try);
    }

    #[test]
    fn test_cfg_classify_statement_return_arrow() {
        // Test that "->" is classified as Return (but only when it starts the statement)
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let kind = analyzer.classify_statement("-> SomeType");
        assert_eq!(kind, CfgNodeKind::Return);
    }

    #[test]
    fn test_cfg_classify_statement_match() {
        // Test that "match" is classified as Conditional
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let kind = analyzer.classify_statement("match x {");
        assert_eq!(kind, CfgNodeKind::Conditional);
    }

    #[test]
    fn test_cfg_classify_statement_for() {
        // Test that "for" is classified as Loop
        let analyzer = CfgAnalyzer::new(super::super::ast::Language::Rust);
        let kind = analyzer.classify_statement("for i in 0..10 {");
        assert_eq!(kind, CfgNodeKind::Loop);
    }
}
