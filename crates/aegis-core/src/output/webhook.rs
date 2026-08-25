//! # Webhook Output Handler
//!
//! Supports sending findings to webhooks: HTTP, Discord, Slack, Teams.

use super::{OutputError, OutputResult, SyncOutputHandler};
use crate::finding::{Finding, ScanStats};
use crate::risk::{RiskLevel, RiskScore};
use std::fmt::Debug;

/// Webhook output handler - sends findings to webhooks
#[derive(Debug)]
pub struct WebhookOutput {
    url: String,
    webhook_type: WebhookType,
    enabled: bool,
    retry_count: u32,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum WebhookType {
    /// Generic HTTP webhook
    Http,
    /// Discord webhook
    Discord,
    /// Slack webhook
    Slack,
    /// Microsoft Teams webhook
    Teams,
}

impl WebhookOutput {
    /// Create a new HTTP webhook output
    pub fn http(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            webhook_type: WebhookType::Http,
            enabled: true,
            retry_count: 3,
            timeout_secs: 30,
        }
    }

    /// Create a new Discord webhook output
    pub fn discord(webhook_url: impl Into<String>) -> Self {
        Self {
            url: webhook_url.into(),
            webhook_type: WebhookType::Discord,
            enabled: true,
            retry_count: 3,
            timeout_secs: 30,
        }
    }

    /// Create a new Slack webhook output
    pub fn slack(webhook_url: impl Into<String>) -> Self {
        Self {
            url: webhook_url.into(),
            webhook_type: WebhookType::Slack,
            enabled: true,
            retry_count: 3,
            timeout_secs: 30,
        }
    }

    /// Create a new Microsoft Teams webhook output
    pub fn teams(webhook_url: impl Into<String>) -> Self {
        Self {
            url: webhook_url.into(),
            webhook_type: WebhookType::Teams,
            enabled: true,
            retry_count: 3,
            timeout_secs: 30,
        }
    }

    /// Set retry count
    pub fn with_retries(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    /// Set timeout in seconds
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Enable or disable this output
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    fn get_risk_emoji(risk: &RiskLevel) -> &'static str {
        match risk {
            RiskLevel::Critical | RiskLevel::High => "🔴",
            RiskLevel::Medium => "🟡",
            RiskLevel::Low | RiskLevel::None => "🟢",
        }
    }

    fn get_risk_color(risk: &RiskLevel) -> &'static str {
        match risk {
            RiskLevel::Critical | RiskLevel::High => "FF0000",
            RiskLevel::Medium => "FFFF00",
            RiskLevel::Low | RiskLevel::None => "00FF00",
        }
    }

    fn is_high_risk(risk: &RiskLevel) -> bool {
        matches!(risk, RiskLevel::Critical | RiskLevel::High)
    }

    fn is_medium_risk(risk: &RiskLevel) -> bool {
        matches!(risk, RiskLevel::Medium)
    }

    fn build_payload(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> String {
        match self.webhook_type {
            WebhookType::Discord => self.build_discord_payload(findings, stats, risk),
            WebhookType::Slack => self.build_slack_payload(findings, stats, risk),
            WebhookType::Teams => self.build_teams_payload(findings, stats, risk),
            WebhookType::Http => self.build_json_payload(findings, stats, risk),
        }
    }

    fn build_discord_payload(
        &self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> String {
        let severity = if Self::is_high_risk(&risk.level) {
            "🔴 HIGH"
        } else if Self::is_medium_risk(&risk.level) {
            "🟡 MEDIUM"
        } else {
            "🟢 LOW"
        };

        let finding_count = findings.len();
        let description = if findings.is_empty() {
            "No security findings detected.".to_string()
        } else {
            let top_findings: Vec<String> = findings
                .iter()
                .take(5)
                .map(|f| {
                    format!(
                        "**{}** at {}:{} - {}",
                        f.pattern, f.location.file, f.location.line, f.description
                    )
                })
                .collect();
            top_findings.join("\n")
        };

        serde_json::json!({
            "embeds": [{
                "title": format!("Aegis Security Scan - {}", severity),
                "description": description,
                "fields": [
                    {"name": "Files Scanned", "value": stats.files_scanned.to_string(), "inline": true},
                    {"name": "Findings", "value": finding_count.to_string(), "inline": true},
                    {"name": "Risk Level", "value": risk.level.to_string(), "inline": true}
                ],
                "footer": {"text": "Aegis Security Scanner"}
            }]
        }).to_string()
    }

    fn build_slack_payload(
        &self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> String {
        let emoji = Self::get_risk_emoji(&risk.level);

        let blocks: Vec<serde_json::Value> = vec![
            serde_json::json!({
                "type": "header",
                "text": {"type": "plain_text", "text": format!("{} Aegis Security Scan", emoji)}
            }),
            serde_json::json!({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": format!("*Risk Level:*\n{}", risk.level)},
                    {"type": "mrkdwn", "text": format!("*Findings:*\n{}", findings.len())},
                    {"type": "mrkdwn", "text": format!("*Files Scanned:*\n{}", stats.files_scanned)}
                ]
            }),
        ];

        serde_json::json!({"blocks": blocks}).to_string()
    }

    fn build_teams_payload(
        &self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> String {
        let color = Self::get_risk_color(&risk.level);

        serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": format!("Aegis found {} security findings", findings.len()),
            "sections": [{
                "activityTitle": "Aegis Security Scan",
                "facts": [
                    {"name": "Risk Level", "value": risk.level.to_string()},
                    {"name": "Findings", "value": findings.len().to_string()},
                    {"name": "Files Scanned", "value": stats.files_scanned.to_string()}
                ],
                "facts": findings.iter().take(5).map(|f| {
                    serde_json::json!({"name": f.pattern.clone(), "value": format!("{} at {}:{}", f.severity, f.location.file, f.location.line)})
                }).collect::<Vec<_>>()
            }]
        }).to_string()
    }

    fn build_json_payload(
        &self,
        findings: &[Finding],
        stats: &ScanStats,
        risk: &RiskScore,
    ) -> String {
        serde_json::json!({
            "findings": findings,
            "stats": stats,
            "risk": risk
        })
        .to_string()
    }

    fn send_webhook(&self, payload: &str) -> OutputResult {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| OutputError::Http(e.to_string()))?;

        let mut last_error = None;

        for attempt in 0..=self.retry_count {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * 2_u64.pow(attempt - 1),
                ));
            }

            match client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(payload.to_string())
                .send()
            {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    last_error = Some(OutputError::Webhook(format!(
                        "HTTP {}: {}",
                        response.status().as_u16(),
                        response.text().unwrap_or_default()
                    )));
                }
                Err(e) => {
                    last_error = Some(OutputError::Http(e.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| OutputError::Webhook("Unknown error".to_string())))
    }
}

impl SyncOutputHandler for WebhookOutput {
    fn emit_sync(&self, findings: &[Finding], stats: &ScanStats, risk: &RiskScore) -> OutputResult {
        if !self.enabled {
            return Ok(());
        }

        let payload = self.build_payload(findings, stats, risk);
        self.send_webhook(&payload)
    }

    fn flush_sync(&self) -> OutputResult {
        // No buffering, nothing to flush
        Ok(())
    }

    fn name(&self) -> &str {
        match self.webhook_type {
            WebhookType::Discord => "discord",
            WebhookType::Slack => "slack",
            WebhookType::Teams => "teams",
            WebhookType::Http => "http",
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_webhook_output_creation() {
        let webhook = WebhookOutput::http("https://example.com/webhook");
        assert_eq!(webhook.name(), "http");
        assert!(webhook.is_enabled());
    }

    #[test]
    fn test_discord_webhook_creation() {
        let webhook = WebhookOutput::discord("https://discord.com/api/webhooks/123");
        assert_eq!(webhook.name(), "discord");
    }

    #[test]
    fn test_slack_webhook_creation() {
        let webhook = WebhookOutput::slack("https://hooks.slack.com/services/xxx");
        assert_eq!(webhook.name(), "slack");
    }

    #[test]
    fn test_teams_webhook_creation() {
        let webhook = WebhookOutput::teams("https://outlook.office.com/webhook/xxx");
        assert_eq!(webhook.name(), "teams");
    }

    #[test]
    fn test_webhook_with_options() {
        let webhook = WebhookOutput::http("https://example.com")
            .with_retries(5)
            .with_timeout(60)
            .with_enabled(false);

        assert!(!webhook.is_enabled());
    }
}
