use anyhow::Result;
use std::{fs, path::Path};

use super::SecretsMatch;

pub fn write(root: &Path, matches: &[SecretsMatch]) -> Result<()> {
    let zentra = root.join(".zentra");
    fs::create_dir_all(&zentra)?;

    let active: Vec<&SecretsMatch> = matches.iter().filter(|m| !m.suppressed).collect();
    let suppressed: Vec<&SecretsMatch> = matches.iter().filter(|m| m.suppressed).collect();

    let mut md = String::new();
    md.push_str("# Secrets Scan Report\n\n");
    md.push_str(&format!("## Active Findings ({})\n\n", active.len()));

    if active.is_empty() {
        md.push_str("No active findings.\n\n");
    } else {
        md.push_str("| File | Line | Commit | Detector | Entropy | Redacted |\n");
        md.push_str("|------|------|--------|----------|---------|----------|\n");
        for m in &active {
            let commit = m
                .commit
                .as_deref()
                .map(|c| c.get(..7).unwrap_or(c))
                .unwrap_or("working tree");
            let entropy = m
                .entropy
                .map(|e| format!("{:.1}", e))
                .unwrap_or_else(|| "-".to_string());
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                m.file, m.line, commit, m.detector, entropy, m.redacted
            ));
        }
        md.push('\n');
    }

    md.push_str(&format!("## Suppressed ({})\n\n", suppressed.len()));
    if !suppressed.is_empty() {
        md.push_str("| File | Line | Detector | Reason |\n");
        md.push_str("|------|------|----------|--------|\n");
        for m in &suppressed {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                m.file,
                m.line,
                m.detector,
                m.suppression_reason.as_deref().unwrap_or("-")
            ));
        }
    }

    fs::write(zentra.join("secrets-report.md"), &md)?;

    let json = serde_json::to_string_pretty(matches)?;
    fs::write(zentra.join("secrets-findings.json"), json)?;

    Ok(())
}

pub fn to_tool_json(matches: &[SecretsMatch]) -> serde_json::Value {
    let total_active = matches.iter().filter(|m| !m.suppressed).count();
    let total_suppressed = matches.iter().filter(|m| m.suppressed).count();

    let findings: Vec<serde_json::Value> = matches
        .iter()
        .filter(|m| !m.suppressed)
        .take(50)
        .map(|m| {
            serde_json::json!({
                "file": m.file,
                "line": m.line,
                "commit": m.commit,
                "detector": m.detector,
                "entropy": m.entropy,
                "redacted": m.redacted
            })
        })
        .collect();

    serde_json::json!({
        "total_active": total_active,
        "total_suppressed": total_suppressed,
        "findings": findings
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_active(file: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 42,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(4.8),
            redacted: "AKIA...MPLE".to_string(),
            suppressed: false,
            suppression_reason: None,
        }
    }

    fn make_suppressed(file: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 10,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(3.0),
            redacted: "your_key".to_string(),
            suppressed: true,
            suppression_reason: Some("placeholder_value".to_string()),
        }
    }

    #[test]
    fn write_creates_md_and_json() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

        let matches = vec![
            make_active("src/config.rs", "aws_access_key"),
            make_suppressed("tests/fixtures.rs", "aws_access_key"),
        ];

        write(dir.path(), &matches).unwrap();

        let md = std::fs::read_to_string(dir.path().join(".zentra/secrets-report.md")).unwrap();
        assert!(md.contains("Active Findings (1)"), "MD should show 1 active finding");
        assert!(md.contains("aws_access_key"), "MD should contain detector name");
        assert!(md.contains("Suppressed (1)"), "MD should show 1 suppressed");
        assert!(md.contains("placeholder_value"), "MD should show suppression reason");

        let raw = std::fs::read_to_string(dir.path().join(".zentra/secrets-findings.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(json.is_array(), "findings.json should be a JSON array");
        assert_eq!(json.as_array().unwrap().len(), 2, "array should contain all matches (both active and suppressed)");
    }

    #[test]
    fn to_tool_json_caps_at_50_active() {
        let matches: Vec<SecretsMatch> = (0..80)
            .map(|i| SecretsMatch {
                file: format!("file{}.rs", i),
                line: i as u32,
                commit: None,
                detector: "aws_access_key".to_string(),
                entropy: Some(4.8),
                redacted: "AKIA...MPLE".to_string(),
                suppressed: false,
                suppression_reason: None,
            })
            .collect();

        let json = to_tool_json(&matches);
        assert_eq!(json["total_active"], 80, "total_active should reflect true count");
        assert_eq!(
            json["findings"].as_array().unwrap().len(),
            50,
            "findings array should be capped at 50"
        );
    }

    #[test]
    fn to_tool_json_excludes_suppressed() {
        let matches = vec![
            make_active("src/real.rs", "aws_access_key"),
            make_suppressed("tests/fake.rs", "aws_access_key"),
        ];

        let json = to_tool_json(&matches);
        assert_eq!(json["total_active"], 1);
        assert_eq!(json["total_suppressed"], 1);
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn to_tool_json_never_includes_raw_secret() {
        let mut m = make_active("src/config.rs", "aws_access_key");
        m.redacted = "AKIA...MPLE".to_string();
        let json = to_tool_json(&[m]);
        let finding = &json["findings"][0];
        let redacted_val = finding["redacted"].as_str().unwrap();
        assert!(redacted_val.contains("..."), "redacted field must contain ellipsis");
        assert!(!redacted_val.contains("AKIAIOSFODNN7EXAMPLE"), "raw secret must not appear");
    }
}
