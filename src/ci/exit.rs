use crate::state::{Finding, Severity};

pub fn should_fail_ci(findings: &[Finding], fail_threshold: Severity) -> bool {
    findings
        .iter()
        .any(|finding| severity_rank(&finding.severity) <= severity_rank(&fail_threshold))
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}
