//! SARIF 2.1.0 output writer.
//!
//! Produces a deterministic SARIF report from a slice of [`Finding`] structs.
//! GitHub code-scanning, GitLab, and Azure DevOps consume the output natively.
//! The writer is deterministic: the same findings always produce the same JSON.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::state::finding::{Finding, Severity};

// ---------------------------------------------------------------------------
// SARIF 2.1.0 structure types.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    default_configuration: SarifRuleConfig,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifRuleConfig {
    level: String,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    partial_fingerprints: HashMap<String, String>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_location: Option<SarifPhysicalLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_location: Option<SarifLogicalLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    name: String,
    kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    severity: String,
    scanner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_vector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owasp: Option<String>,
    recommendation: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    corroborated_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    screening: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Map a zentra severity to a SARIF level.
fn severity_to_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

/// Return the rule id for a finding. Use the CWE id when present; otherwise
/// fall back to `<scanner>/<short-hash-of-title>`.
fn rule_id(finding: &Finding) -> String {
    if let Some(cwe) = &finding.cwe {
        let trimmed = cwe.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(finding.title.as_bytes());
    let hash = hasher.finalize();
    let short: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{}/{}", finding.scanner, short)
}

/// Compute a deterministic fingerprint for a finding. The hash covers the
/// title and the location string so two findings at different sites with the
/// same title do not collide.
fn fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    let payload = format!(
        "{}|{}",
        finding.title,
        finding.location.as_deref().unwrap_or("")
    );
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a location string into a file URI and an optional line number.
///
/// Handles three forms:
/// - `"src/file.rs:42"` → `("src/file.rs", Some(42))`
/// - `"src/file.rs:42:10"` → `("src/file.rs", Some(42))` (column ignored)
/// - `"src/file.rs"` → `("src/file.rs", None)`
///
/// Backslashes are normalized to forward slashes so the URI is cross-platform.
/// When the segment after a colon is not numeric, the whole string is the URI.
fn parse_location(loc: &str) -> (String, Option<u32>) {
    let normalized = loc.replace('\\', "/");
    let parts: Vec<&str> = normalized.splitn(3, ':').collect();
    match parts.as_slice() {
        [path, line, ..] => match line.parse::<u32>() {
            Ok(n) => (path.to_string(), Some(n)),
            Err(_) => (normalized.to_string(), None),
        },
        _ => (normalized.to_string(), None),
    }
}

/// Build a SARIF rule from a finding.
fn build_rule(finding: &Finding, rid: &str) -> SarifRule {
    let level = severity_to_level(finding.severity).to_string();

    let help_uri = finding.cwe.as_ref().and_then(|cwe| {
        let trimmed = cwe.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(crate::config::cwe_link(
                trimmed,
                crate::config::DEFAULT_CWE_URL_TEMPLATE,
            ))
        }
    });

    let mut tags = vec![finding.severity.to_string().to_lowercase()];
    if let Some(owasp) = &finding.owasp {
        if !owasp.is_empty() {
            tags.push(owasp.clone());
        }
    }

    SarifRule {
        id: rid.to_string(),
        name: finding
            .cwe
            .clone()
            .filter(|c| !c.trim().is_empty())
            .unwrap_or_else(|| finding.title.clone()),
        short_description: SarifMessage {
            text: finding.title.clone(),
        },
        full_description: SarifMessage {
            text: finding.recommendation.clone(),
        },
        help_uri,
        default_configuration: SarifRuleConfig { level },
        properties: SarifRuleProperties { tags },
    }
}

/// Build a SARIF result from a finding.
fn build_result(finding: &Finding) -> SarifResult {
    let rid = rule_id(finding);
    let level = severity_to_level(finding.severity).to_string();
    let message = SarifMessage {
        text: format!("{}: {}", finding.title, finding.description),
    };

    let locations = match finding.location.as_deref() {
        Some(loc) if !loc.trim().is_empty() => {
            let (uri, line) = parse_location(loc);
            vec![SarifLocation {
                physical_location: Some(SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri },
                    region: line.map(|n| SarifRegion { start_line: n }),
                }),
                logical_location: None,
            }]
        }
        _ => vec![SarifLocation {
            physical_location: None,
            logical_location: Some(SarifLogicalLocation {
                name: finding.scanner.clone(),
                kind: "scanner".to_string(),
            }),
        }],
    };

    let mut partial_fingerprints = HashMap::new();
    partial_fingerprints.insert("primaryLocationLineHash".to_string(), fingerprint(finding));

    let properties = SarifResultProperties {
        severity: finding.severity.to_string(),
        scanner: finding.scanner.clone(),
        cwe: finding.cwe.clone(),
        cvss_score: finding.cvss_score,
        cvss_vector: finding.cvss_vector.clone(),
        owasp: finding.owasp.clone(),
        recommendation: finding.recommendation.clone(),
        corroborated_by: finding.corroborated_by.clone(),
        screening: finding.screening.map(|s| s.to_string()),
        confidence: finding.confidence,
        evidence: finding.evidence.clone(),
    };

    SarifResult {
        rule_id: rid,
        level,
        message,
        locations,
        partial_fingerprints,
        properties,
    }
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Build a SARIF 2.1.0 report as a [`serde_json::Value`].
///
/// The output is deterministic: the same findings always produce the same JSON.
/// Results are sorted by severity (Critical first), then location, then title.
pub fn write_sarif(findings: &[Finding]) -> serde_json::Value {
    // Sort findings deterministically: severity, then location, then title.
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        a.severity
            .order()
            .cmp(&b.severity.order())
            .then_with(|| {
                a.location
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.location.as_deref().unwrap_or(""))
            })
            .then_with(|| a.title.cmp(&b.title))
    });

    // Build rules: one per unique rule id, in sorted order.
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for finding in sorted.iter().copied() {
        let id = rule_id(finding);
        if seen.insert(id.clone()) {
            rules.push(build_rule(finding, &id));
        }
    }

    let results: Vec<SarifResult> = sorted.iter().copied().map(build_result).collect();

    let report = SarifReport {
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "zentra".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/kestrel-sec/zentra".to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_value(&report).expect("SARIF serialization is infallible for these types")
}

/// Render a SARIF 2.1.0 report as a pretty-printed JSON string.
pub fn render_sarif(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(&write_sarif(findings))
        .expect("SARIF pretty-print is infallible for these types")
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finding::Screening;

    fn sample_finding() -> Finding {
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: "SQL Injection".to_string(),
            description: "User input concatenated into query".to_string(),
            location: Some("src/db.rs:42".to_string()),
            recommendation: "Use parameterized queries".to_string(),
            corroborated_by: vec!["supply-chain".to_string()],
            cwe: Some("CWE-89".to_string()),
            secondary_cwe: vec![],
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            cvss_score: Some(9.8),
            owasp: Some("A03:2021-Injection".to_string()),
            confidence: Some(85),
            screening: Some(Screening::Confirmed),
            evidence: Some("reachable from the HTTP handler".to_string()),
        }
    }

    // 1. Empty findings produce valid SARIF with an empty results array.
    #[test]
    fn empty_findings_produce_valid_sarif() {
        let json = write_sarif(&[]);
        assert_eq!(json["version"], "2.1.0");
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"].as_array().unwrap().len(), 1);
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty(), "results must be empty for no findings");
        let rules = json["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules.is_empty(), "rules must be empty for no findings");
    }

    // 2. A finding with CWE, CVSS, location, and OWASP maps to the correct
    //    ruleId, level, locations, and properties.
    #[test]
    fn enriched_finding_maps_correctly() {
        let f = sample_finding();
        let json = write_sarif(&[f]);

        let result = &json["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "CWE-89");
        assert_eq!(result["level"], "error", "High severity maps to error");
        assert_eq!(
            result["message"]["text"],
            "SQL Injection: User input concatenated into query"
        );

        // Physical location with uri and startLine.
        let loc = &result["locations"][0]["physicalLocation"];
        assert!(loc["artifactLocation"]["uri"].is_string());
        assert_eq!(loc["artifactLocation"]["uri"], "src/db.rs");
        assert_eq!(loc["region"]["startLine"], 42);

        // No logical location when a physical one is present.
        assert!(
            result["locations"][0]["logicalLocation"].is_null(),
            "logicalLocation must be absent when physicalLocation is set"
        );

        // Properties carry the enrichment fields.
        let props = &result["properties"];
        assert_eq!(props["severity"], "HIGH");
        assert_eq!(props["scanner"], "sast");
        assert_eq!(props["cwe"], "CWE-89");
        assert!(
            (props["cvssScore"].as_f64().unwrap_or(0.0) - 9.8).abs() < 0.001,
            "cvssScore must be approximately 9.8"
        );
        assert!(props["cvssVector"].is_string());
        assert_eq!(props["owasp"], "A03:2021-Injection");
        assert_eq!(props["recommendation"], "Use parameterized queries");
        assert_eq!(props["screening"], "confirmed");
        assert_eq!(props["confidence"], 85);
        assert_eq!(props["evidence"], "reachable from the HTTP handler");
        assert_eq!(props["corroboratedBy"][0], "supply-chain");

        // The rule has a helpUri pointing at the CWE page.
        let rule = &json["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "CWE-89");
        assert_eq!(rule["helpUri"], "https://cwe.mitre.org/data/definitions/89.html");
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert!(rule["properties"]["tags"].as_array().unwrap().contains(&serde_json::Value::from("high")));
        assert!(
            rule["properties"]["tags"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::from("A03:2021-Injection"))
        );
    }

    // 2b. A finding without evidence omits the property entirely (backward
    //     compatible with consumers that predate the field).
    #[test]
    fn evidence_omitted_when_absent() {
        let mut f = sample_finding();
        f.evidence = None;
        let json = write_sarif(&[f]);
        let props = &json["runs"][0]["results"][0]["properties"];
        assert!(
            props.get("evidence").is_none(),
            "evidence must be absent when the finding has none"
        );
    }

    // 3. A finding with no location emits a logicalLocation instead of a
    //    physicalLocation.
    #[test]
    fn no_location_emits_logical_location() {
        let mut f = sample_finding();
        f.location = None;
        let json = write_sarif(&[f]);

        let loc = &json["runs"][0]["results"][0]["locations"][0];
        assert!(
            loc["physicalLocation"].is_null(),
            "physicalLocation must be absent when no location"
        );
        assert_eq!(loc["logicalLocation"]["name"], "sast");
        assert_eq!(loc["logicalLocation"]["kind"], "scanner");
    }

    // 4. Location parsing splits the file path from the line number.
    #[test]
    fn parse_location_with_line() {
        let (uri, line) = parse_location("src/file.rs:42");
        assert_eq!(uri, "src/file.rs");
        assert_eq!(line, Some(42));
    }

    #[test]
    fn parse_location_without_line() {
        let (uri, line) = parse_location("src/file.rs");
        assert_eq!(uri, "src/file.rs");
        assert_eq!(line, None);
    }

    #[test]
    fn parse_location_with_column() {
        let (uri, line) = parse_location("src/file.rs:42:10");
        assert_eq!(uri, "src/file.rs");
        assert_eq!(line, Some(42), "column must be ignored");
    }

    #[test]
    fn parse_location_non_numeric_line() {
        let (uri, line) = parse_location("src/file.rs:abc");
        assert_eq!(uri, "src/file.rs:abc", "whole string is the uri");
        assert_eq!(line, None);
    }

    #[test]
    fn parse_location_backslashes() {
        let (uri, line) = parse_location("src\\file.rs:7");
        assert_eq!(uri, "src/file.rs");
        assert_eq!(line, Some(7));
    }

    // 5. Fingerprint determinism: the same finding always produces the same
    //    fingerprint.
    #[test]
    fn fingerprint_is_deterministic() {
        let f = sample_finding();
        let fp1 = fingerprint(&f);
        let fp2 = fingerprint(&f);
        assert_eq!(fp1, fp2, "same finding must produce the same fingerprint");
        assert_eq!(fp1.len(), 64, "fingerprint is a full sha256 hex string");

        // A finding at a different location produces a different fingerprint.
        let mut f2 = sample_finding();
        f2.location = Some("src/other.rs:1".to_string());
        assert_ne!(fingerprint(&f2), fp1, "different location must differ");
    }

    // 6. The top-level JSON has the required keys: version and runs.
    #[test]
    fn top_level_json_has_required_keys() {
        let json = write_sarif(&[sample_finding()]);
        assert!(json.get("version").is_some(), "version key must exist");
        assert!(json.get("runs").is_some(), "runs key must exist");
        assert_eq!(json["version"], "2.1.0");

        // The run has tool and results.
        let run = &json["runs"][0];
        assert!(run.get("tool").is_some());
        assert!(run.get("results").is_some());
        assert!(run["tool"]["driver"]["name"].is_string());
        assert_eq!(run["tool"]["driver"]["name"], "zentra");
    }

    // Severity-to-level mapping for all severities.
    #[test]
    fn severity_level_mapping() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "warning");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    // A finding without a CWE falls back to a scanner/title-hash rule id.
    #[test]
    fn no_cwe_falls_back_to_scanner_title_hash() {
        let mut f = sample_finding();
        f.cwe = None;
        let json = write_sarif(&[f]);
        let rule_id = json["runs"][0]["results"][0]["ruleId"].as_str().unwrap();
        assert!(
            rule_id.starts_with("sast/"),
            "fallback rule id must start with scanner name, got: {rule_id}"
        );
    }

    // Results are sorted by severity, then location, then title.
    #[test]
    fn results_sorted_deterministically() {
        let low = Finding {
            severity: Severity::Low,
            title: "Z Issue".to_string(),
            location: Some("src/a.rs:1".to_string()),
            ..sample_finding()
        };
        let critical = Finding {
            severity: Severity::Critical,
            title: "A Issue".to_string(),
            location: Some("src/b.rs:1".to_string()),
            ..sample_finding()
        };
        let json = write_sarif(&[low, critical]);
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["properties"]["severity"], "CRITICAL");
        assert_eq!(results[1]["properties"]["severity"], "LOW");
    }

    // Two findings with the same CWE produce one rule and two results.
    #[test]
    fn same_cwe_deduplicates_rules() {
        let f1 = sample_finding();
        let f2 = Finding {
            title: "Another SQLi".to_string(),
            location: Some("src/other.rs:5".to_string()),
            ..sample_finding()
        };
        let json = write_sarif(&[f1, f2]);
        let rules = json["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "one rule per unique CWE id");
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "two results for two findings");
    }
}