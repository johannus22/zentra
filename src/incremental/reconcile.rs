use crate::incremental::{ChangeSet, ScanDelta};
use crate::state::Finding;

const NEW_MARKER: &str = "🆕 ";

fn file_of(location: &Option<String>) -> Option<String> {
    let loc = location.as_deref()?;
    let path = loc.split(':').next().unwrap_or(loc).trim();
    if path.is_empty() {
        None
    } else {
        Some(path.replace('\\', "/"))
    }
}

fn in_zone(file: &str, change_set: &ChangeSet) -> bool {
    let f = file.replace('\\', "/");
    change_set.changed.iter().any(|c| c.replace('\\', "/") == f)
        || change_set.impact.iter().any(|c| c.replace('\\', "/") == f)
}

/// Two findings refer to the same issue if they share normalized location and
/// a case-insensitive title match (after stripping any NEW marker).
fn same_issue(a: &Finding, b: &Finding) -> bool {
    let title_a = a.title.trim_start_matches(NEW_MARKER).to_ascii_lowercase();
    let title_b = b.title.trim_start_matches(NEW_MARKER).to_ascii_lowercase();
    file_of(&a.location) == file_of(&b.location) && title_a == title_b
}

pub fn reconcile(
    prior: Vec<Finding>,
    fresh: Vec<Finding>,
    change_set: &ChangeSet,
) -> (Vec<Finding>, ScanDelta) {
    let mut delta = ScanDelta::default();
    let mut merged: Vec<Finding> = Vec::new();

    // Carried zone: prior findings whose file is outside changed∪impact, plus
    // no-location (architectural) findings.
    let (carried, prior_in_zone): (Vec<Finding>, Vec<Finding>) =
        prior.into_iter().partition(|f| match file_of(&f.location) {
            None => true,
            Some(file) => !in_zone(&file, change_set),
        });
    delta.carried = carried.len();
    merged.extend(carried);

    // Fresh findings: NEW if not matched to a prior in-zone finding.
    for f in fresh {
        let matched = prior_in_zone.iter().any(|p| same_issue(p, &f));
        if matched {
            merged.push(f); // still present — unmarked
        } else {
            let mut nf = f;
            if !nf.title.starts_with(NEW_MARKER) {
                nf.title = format!("{}{}", NEW_MARKER, nf.title);
            }
            delta.new += 1;
            merged.push(nf);
        }
    }

    // Prior in-zone findings not reproduced this run → resolved (dropped).
    let still_present = prior_in_zone
        .iter()
        .filter(|p| merged.iter().any(|m| same_issue(p, m)))
        .count();
    delta.resolved = prior_in_zone.len().saturating_sub(still_present);

    (merged, delta)
}

pub fn is_arch_significant(changed: &[String]) -> bool {
    changed.iter().any(|f| {
        let lower = f.replace('\\', "/").to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or(&lower);
        matches!(
            name,
            "cargo.toml"
                | "cargo.lock"
                | "package.json"
                | "package-lock.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "requirements.txt"
                | "pyproject.toml"
                | "poetry.lock"
                | "go.mod"
                | "go.sum"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "dockerfile"
                | "docker-compose.yml"
                | "docker-compose.yaml"
        ) || lower.ends_with(".tf")
            || lower.contains("k8s/")
            || lower.contains("kubernetes/")
            || lower.contains("helm/")
            || lower.contains(".github/workflows/")
            || lower.contains("/auth")
            || lower.contains("auth/")
            || lower.contains("config")
            || lower.contains("main.rs")
            || lower.contains("/index.")
            || lower.contains("app.")
            || lower.contains("server")
    })
}

pub fn build_focus_context(change_set: &ChangeSet) -> String {
    let fmt = |files: &[String]| -> String {
        if files.is_empty() {
            "- none".to_string()
        } else {
            files
                .iter()
                .map(|f| format!("- {f}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    format!(
        "This is an INCREMENTAL rescan. Findings for files outside the impact set \
below were carried over from the previous scan and are NOT in scope. Focus ONLY \
on the changed and impacted files. Consider how changed files affect their \
dependencies and dependents within this set.\n\nChanged files ({}):\n{}\n\n\
Impact files ({}):\n{}",
        change_set.changed.len(),
        fmt(&change_set.changed),
        change_set.impact.len(),
        fmt(&change_set.impact),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Severity;

    fn finding(scanner: &str, title: &str, loc: Option<&str>) -> Finding {
        Finding {
            scanner: scanner.into(),
            severity: Severity::High,
            title: title.into(),
            description: "d".into(),
            location: loc.map(|s| s.into()),
            recommendation: "r".into(),
            corroborated_by: vec![],
        }
    }

    fn change_set(changed: &[&str], impact: &[&str]) -> ChangeSet {
        ChangeSet {
            changed: changed.iter().map(|s| s.to_string()).collect(),
            impact: impact.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn carries_findings_outside_change_set() {
        let prior = vec![finding("sast", "SQLi", Some("src/untouched.rs:10"))];
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let (merged, delta) = reconcile(prior, vec![], &cs);
        assert_eq!(merged.len(), 1);
        assert_eq!(delta.carried, 1);
        assert_eq!(delta.new, 0);
        assert_eq!(delta.resolved, 0);
        assert!(!merged[0].title.starts_with("🆕"));
    }

    #[test]
    fn resolved_when_prior_in_changed_zone_not_reproduced() {
        let prior = vec![finding("sast", "XSS", Some("src/changed.rs:5"))];
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let (merged, delta) = reconcile(prior, vec![], &cs);
        assert!(merged.is_empty());
        assert_eq!(delta.resolved, 1);
    }

    #[test]
    fn new_when_fresh_finding_not_in_prior() {
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let fresh = vec![finding("sast", "New bug", Some("src/changed.rs:8"))];
        let (merged, delta) = reconcile(vec![], fresh, &cs);
        assert_eq!(merged.len(), 1);
        assert_eq!(delta.new, 1);
        assert!(merged[0].title.starts_with("🆕"));
    }

    #[test]
    fn matched_finding_in_changed_zone_is_not_new_or_resolved() {
        let prior = vec![finding("sast", "SQLi", Some("src/changed.rs:10"))];
        let fresh = vec![finding("sast", "SQLi", Some("src/changed.rs:10"))];
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let (merged, delta) = reconcile(prior, fresh, &cs);
        assert_eq!(merged.len(), 1);
        assert_eq!(delta.new, 0);
        assert_eq!(delta.resolved, 0);
        assert!(!merged[0].title.starts_with("🆕"));
    }

    #[test]
    fn no_location_finding_is_carried() {
        let prior = vec![finding("threat_model", "Trust boundary", None)];
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let (merged, delta) = reconcile(prior, vec![], &cs);
        assert_eq!(merged.len(), 1);
        assert_eq!(delta.carried, 1);
    }

    #[test]
    fn arch_significant_detects_manifest_and_auth() {
        assert!(is_arch_significant(&["Cargo.toml".into()]));
        assert!(is_arch_significant(&["src/auth/mod.rs".into()]));
        assert!(is_arch_significant(&["Dockerfile".into()]));
        assert!(!is_arch_significant(&["src/util/format.rs".into()]));
    }
}
