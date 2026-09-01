use serde_json::Value;
use zentra_cli::pentest::sandbox::report::{
    dedup_sandbox_findings, fingerprint, map_severity, render_sarif, SandboxFinding,
};
use zentra_cli::pentest::{PentestFinding, PentestSeverity};

fn finding(
    category: &str,
    endpoint: &str,
    severity: PentestSeverity,
    title: &str,
) -> SandboxFinding {
    SandboxFinding {
        fingerprint: fingerprint(category, endpoint, title),
        category: category.to_string(),
        endpoint: endpoint.to_string(),
        finding: PentestFinding {
            severity,
            cvss: None,
            title: title.to_string(),
            impact: "impact".to_string(),
            reproduction_steps: vec!["step".to_string()],
            evidence_paths: vec!["evidence".to_string()],
            remediation: "fix".to_string(),
        },
    }
}

#[test]
fn severity_table_covers_each_bucket() {
    assert_eq!(map_severity("RCE"), PentestSeverity::Critical);
    assert_eq!(map_severity("IDOR"), PentestSeverity::High);
    assert_eq!(map_severity("security header"), PentestSeverity::Medium);
    assert_eq!(map_severity("info disclosure"), PentestSeverity::Low);
    assert_eq!(map_severity("unknown"), PentestSeverity::Medium);
}

#[test]
fn fingerprint_is_stable_and_normalizes_query_case() {
    let a = fingerprint("SQLI", "HTTPS://Example.TEST/api/?x=1#frag", " Issue ");
    let b = fingerprint("sqli", "https://example.test/api", "issue");
    assert_eq!(a, b);
    assert_eq!(a.len(), 16);
}

#[test]
fn dedup_keeps_first_order_and_higher_severity() {
    let input = vec![
        finding(
            "xss",
            "https://target.test/a",
            PentestSeverity::Low,
            "first",
        ),
        finding(
            "xss",
            "https://target.test/a",
            PentestSeverity::High,
            "second",
        ),
        finding(
            "cors",
            "https://target.test/b",
            PentestSeverity::Medium,
            "third",
        ),
    ];
    let output = dedup_sandbox_findings(input);
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].finding.title, "second");
    assert_eq!(output[1].finding.title, "third");
}

#[test]
fn sarif_is_valid_and_deterministic() {
    let findings = vec![
        finding(
            "sqli",
            "https://target.test/a",
            PentestSeverity::Critical,
            "SQLi",
        ),
        finding("xss", "https://target.test/b", PentestSeverity::High, "XSS"),
    ];
    let first = render_sarif(&findings).unwrap();
    let second = render_sarif(&findings).unwrap();
    assert_eq!(first, second);
    let json: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(json["version"], "2.1.0");
    assert_eq!(json["runs"][0]["results"].as_array().unwrap().len(), 2);
}
