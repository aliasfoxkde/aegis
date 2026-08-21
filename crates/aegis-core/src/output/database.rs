//! # Database Output Handler
//!
//! Supports writing findings to databases: SQLite, PostgreSQL, MySQL.

use super::{OutputResult, SyncOutputHandler};
use crate::finding::{Finding, ScanStats};
use crate::risk::RiskScore;
use std::fmt::Debug;

/// Database output handler
#[derive(Debug)]
pub enum DatabaseOutput {
    /// SQLite database
    Sqlite(SqliteOutput),
    /// PostgreSQL database
    PostgreSql(PostgreSqlOutput),
    /// MySQL database
    MySql(MySqlOutput),
}

#[derive(Debug)]
pub struct SqliteOutput {
    path: std::path::PathBuf,
    table_name: String,
    enabled: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PostgreSqlOutput {
    connection_string: String,
    table_name: String,
    enabled: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MySqlOutput {
    connection_string: String,
    table_name: String,
    enabled: bool,
}

impl SqliteOutput {
    /// Create a new SQLite output
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            table_name: "aegis_findings".to_string(),
            enabled: true,
        }
    }

    /// Set the table name
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table_name = table.into();
        self
    }

    /// Enable or disable
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    fn ensure_table(&self) -> OutputResult {
        use rusqlite::{params, Connection};

        let conn = Connection::open(&self.path)?;
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    column_number INTEGER NOT NULL,
                    matched_content TEXT,
                    description TEXT,
                    fingerprint TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_id TEXT
                )",
                self.table_name
            ),
            params![],
        )?;
        Ok(())
    }

    fn insert_findings(&self, findings: &[Finding], scan_id: &str) -> OutputResult {
        use rusqlite::{params, Connection};

        let conn = Connection::open(&self.path)?;

        for finding in findings {
            conn.execute(
                &format!(
                    "INSERT INTO {} (id, pattern, category, severity, confidence, file_path, line_number, column_number, matched_content, description, fingerprint, scan_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    self.table_name
                ),
                params![
                    finding.id,
                    finding.pattern,
                    finding.category,
                    finding.severity,
                    finding.confidence,
                    finding.location.file,
                    finding.location.line,
                    finding.location.column,
                    // Keep the legacy nullable column for schema compatibility,
                    // but never persist detected secret material.
                    Option::<String>::None,
                    finding.description,
                    finding.fingerprint,
                    scan_id,
                ],
            )?;
        }
        Ok(())
    }
}

impl PostgreSqlOutput {
    /// Create a new PostgreSQL output
    pub fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
            table_name: "aegis_findings".to_string(),
            enabled: true,
        }
    }

    /// Set the table name
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table_name = table.into();
        self
    }

    /// Enable or disable
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl MySqlOutput {
    /// Create a new MySQL output
    pub fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
            table_name: "aegis_findings".to_string(),
            enabled: true,
        }
    }

    /// Set the table name
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table_name = table.into();
        self
    }

    /// Enable or disable
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl SyncOutputHandler for SqliteOutput {
    fn emit_sync(
        &self,
        findings: &[Finding],
        _stats: &ScanStats,
        _risk: &RiskScore,
    ) -> OutputResult {
        if !self.enabled {
            return Ok(());
        }

        self.ensure_table()?;
        let scan_id = uuid_v4();
        self.insert_findings(findings, &scan_id)
    }

    fn flush_sync(&self) -> OutputResult {
        Ok(())
    }

    fn name(&self) -> &str {
        "sqlite"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl SyncOutputHandler for PostgreSqlOutput {
    fn emit_sync(
        &self,
        findings: &[Finding],
        _stats: &ScanStats,
        _risk: &RiskScore,
    ) -> OutputResult {
        if !self.enabled {
            return Ok(());
        }

        // Note: Actual PostgreSQL implementation would use tokio-postgres
        // This is a placeholder showing the expected interface
        tracing::info!(
            "PostgreSQL output would insert {} findings to table '{}'",
            findings.len(),
            self.table_name
        );
        Ok(())
    }

    fn flush_sync(&self) -> OutputResult {
        Ok(())
    }

    fn name(&self) -> &str {
        "postgresql"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl SyncOutputHandler for MySqlOutput {
    fn emit_sync(
        &self,
        findings: &[Finding],
        _stats: &ScanStats,
        _risk: &RiskScore,
    ) -> OutputResult {
        if !self.enabled {
            return Ok(());
        }

        // Note: Actual MySQL implementation would use sqlx or mysql_async
        // This is a placeholder showing the expected interface
        tracing::info!(
            "MySQL output would insert {} findings to table '{}'",
            findings.len(),
            self.table_name
        );
        Ok(())
    }

    fn flush_sync(&self) -> OutputResult {
        Ok(())
    }

    fn name(&self) -> &str {
        "mysql"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl SyncOutputHandler for DatabaseOutput {
    fn emit_sync(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> OutputResult {
        match self {
            DatabaseOutput::Sqlite(output) => output.emit_sync(findings, stats, risk),
            DatabaseOutput::PostgreSql(output) => output.emit_sync(findings, stats, risk),
            DatabaseOutput::MySql(output) => output.emit_sync(findings, stats, risk),
        }
    }

    fn flush_sync(&self) -> OutputResult {
        match self {
            DatabaseOutput::Sqlite(output) => output.flush_sync(),
            DatabaseOutput::PostgreSql(output) => output.flush_sync(),
            DatabaseOutput::MySql(output) => output.flush_sync(),
        }
    }

    fn name(&self) -> &str {
        match self {
            DatabaseOutput::Sqlite(output) => output.name(),
            DatabaseOutput::PostgreSql(output) => output.name(),
            DatabaseOutput::MySql(output) => output.name(),
        }
    }

    fn is_enabled(&self) -> bool {
        match self {
            DatabaseOutput::Sqlite(output) => output.is_enabled(),
            DatabaseOutput::PostgreSql(output) => output.is_enabled(),
            DatabaseOutput::MySql(output) => output.is_enabled(),
        }
    }
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_output_creation() {
        let output = SqliteOutput::new("/tmp/test.db");
        assert!(output.is_enabled());
        assert_eq!(output.name(), "sqlite");
    }

    #[test]
    fn test_sqlite_output_with_options() {
        let output = SqliteOutput::new("/tmp/test.db")
            .with_table("custom_table")
            .with_enabled(false);

        assert!(!output.is_enabled());
    }

    #[test]
    fn test_postgresql_output_creation() {
        let output = PostgreSqlOutput::new("postgresql://user:pass@localhost/db");
        assert!(output.is_enabled());
    }

    #[test]
    fn test_mysql_output_creation() {
        let output = MySqlOutput::new("mysql://user:pass@localhost/db");
        assert!(output.is_enabled());
    }

    #[test]
    fn test_database_output_enum() {
        let sqlite = DatabaseOutput::Sqlite(SqliteOutput::new("/tmp/test.db"));
        assert_eq!(sqlite.name(), "sqlite");
        assert!(sqlite.is_enabled());

        let postgres =
            DatabaseOutput::PostgreSql(PostgreSqlOutput::new("postgresql://localhost/db"));
        assert_eq!(postgres.name(), "postgresql");

        let mysql = DatabaseOutput::MySql(MySqlOutput::new("mysql://localhost/db"));
        assert_eq!(mysql.name(), "mysql");
    }

    #[test]
    fn test_sqlite_output_redacts_matched_content() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let path = temp_dir.path().join("findings.db");
        let secret = "TOP-SECRET-DATABASE-FIXTURE";
        let finding = Finding::new(
            "hardcoded-secret",
            "secrets",
            "high",
            "high",
            crate::finding::Location::new("config.toml", 4, 2, format!("token = '{secret}'")),
            secret,
            "Hardcoded secret detected",
        );
        SqliteOutput::new(&path)
            .emit_sync(
                std::slice::from_ref(&finding),
                &ScanStats::for_content("config.toml", 32),
                &RiskScore::new(&[], &Default::default(), &Default::default()),
            )
            .unwrap();

        let connection = rusqlite::Connection::open(path).unwrap();
        let (matched_content, fingerprint): (Option<String>, String) = connection
            .query_row(
                "SELECT matched_content, fingerprint FROM aegis_findings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(matched_content.is_none());
        assert!(!fingerprint.contains(secret));
    }
}
