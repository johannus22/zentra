use crate::incremental::{ChangeSet, ScanDelta};
use crate::state::Finding;

const NEW_MARKER: &str = "🆕 ";

fn file_of(location: &Option<String>) -> Option<String> {
    let loc = location.as_deref()?;
    // Strip a trailing `:line` and optional `:col` without splitting on the
    // first colon — a Windows drive-absolute path (`C:\...\db.rs:10`) keeps its
    // own colon, so `split(':').next()` would collapse it to just "C".
    let mut path = loc.trim();
    for _ in 0..2 {
        if let Some((head, tail)) = path.rsplit_once(':') {
            if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
                path = head;
                continue;
            }
        }
        break;
    }
    let path = path.trim();
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

/// Two findings refer to the same issue if they share the same scanner,
/// normalized location, and a case-insensitive title match (after stripping
/// any NEW marker).
fn same_issue(a: &Finding, b: &Finding) -> bool {
    let title_a = a.title.trim_start_matches(NEW_MARKER).to_ascii_lowercase();
    let title_b = b.title.trim_start_matches(NEW_MARKER).to_ascii_lowercase();
    a.scanner == b.scanner && file_of(&a.location) == file_of(&b.location) && title_a == title_b
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
        // Exact filename matches for manifests / lockfiles / IaC
        let manifest = matches!(
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
        );
        // Path-substring matches for IaC directories / CI (unchanged from original)
        let iac = lower.ends_with(".tf")
            || lower.contains("k8s/")
            || lower.contains("kubernetes/")
            || lower.contains("helm/")
            || lower.contains(".github/workflows/");
        // Segment-boundary-aware check: a path segment must BE the keyword
        // (or start/end with it as a separator-adjacent token) to avoid matching
        // unrelated words like "reconfiguration" or "observer".
        let seg = |needle: &str| {
            lower.split('/').any(|s| {
                s == needle
                    || s.starts_with(&format!("{needle}."))
                    || s.starts_with(&format!("{needle}_"))
                    || s.ends_with(&format!("_{needle}"))
            })
        };
        let entrypoint = seg("auth")
            || seg("config")
            || seg("server")
            || name == "main.rs"
            || name == "index.js"
            || name == "index.ts"
            || name.starts_with("app.");
        manifest || iac || entrypoint
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

    // F16: file_of used `location.split(':').next()`, collapsing every Windows
    // drive-absolute location (`C:\...\db.rs:10`) to the pseudo-file "C" — so all
    // such findings normalized to the same file (never matched to changed paths,
    // cross-file mis-dedup).
    #[test]
    fn file_of_strips_line_from_windows_drive_path() {
        let loc = Some("C:\\Users\\x\\db.rs:10".to_string());
        assert_eq!(file_of(&loc).as_deref(), Some("C:/Users/x/db.rs"));
    }

    #[test]
    fn file_of_strips_line_and_col() {
        assert_eq!(
            file_of(&Some("src/db.rs:10:5".to_string())).as_deref(),
            Some("src/db.rs")
        );
        assert_eq!(
            file_of(&Some("src/db.rs".to_string())).as_deref(),
            Some("src/db.rs")
        );
    }

    fn finding(scanner: &str, title: &str, loc: Option<&str>) -> Finding {
        Finding {
            scanner: scanner.into(),
            severity: Severity::High,
            title: title.into(),
            description: "d".into(),
            location: loc.map(|s| s.into()),
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: Vec::new(),
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
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

    #[test]
    fn new_marker_is_not_doubled() {
        // A fresh finding whose title already starts with the 🆕 marker should
        // NOT get a second prefix applied.
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let fresh = vec![finding(
            "sast",
            "🆕 Pre-marked bug",
            Some("src/changed.rs:1"),
        )];
        let (merged, delta) = reconcile(vec![], fresh, &cs);
        assert_eq!(delta.new, 1);
        assert_eq!(merged.len(), 1);
        assert!(
            !merged[0].title.starts_with("🆕 🆕"),
            "title must not be double-prefixed: {:?}",
            merged[0].title
        );
    }

    #[test]
    fn cross_scanner_same_title_not_matched() {
        // A prior finding from "sast" and a fresh one from "supply_chain" with
        // identical title + location must NOT be treated as the same issue.
        let prior = vec![finding("sast", "Issue", Some("src/changed.rs:1"))];
        let fresh = vec![finding("supply_chain", "Issue", Some("src/changed.rs:1"))];
        let cs = change_set(&["src/changed.rs"], &["src/changed.rs"]);
        let (merged, delta) = reconcile(prior, fresh, &cs);
        // The supply_chain finding is brand-new (no prior supply_chain match).
        assert_eq!(delta.new, 1, "supply_chain finding must be counted as new");
        // The sast finding was not reproduced by sast this run → resolved.
        assert_eq!(
            delta.resolved, 1,
            "sast finding must be counted as resolved"
        );
        // They must not be collapsed: the 🆕-prefixed supply_chain finding
        // should be the only finding in merged.
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].scanner, "supply_chain");
    }

    #[test]
    fn build_focus_context_lists_changed_and_impact() {
        let cs = change_set(&["a.rs", "b.rs"], &["a.rs", "b.rs", "c.rs"]);
        let ctx = build_focus_context(&cs);
        assert!(
            ctx.contains("Changed files (2)"),
            "must mention Changed files (2), got: {ctx}"
        );
        assert!(
            ctx.contains("Impact files (3)"),
            "must mention Impact files (3), got: {ctx}"
        );
        assert!(ctx.contains("- a.rs"), "must list a.rs, got: {ctx}");
    }

    #[test]
    fn arch_significant_segment_boundaries() {
        // These must be true:
        assert!(
            is_arch_significant(&["auth.rs".into()]),
            "auth.rs must be arch-significant"
        );
        assert!(
            is_arch_significant(&["src/config/db.rs".into()]),
            "src/config/db.rs must be arch-significant"
        );
        // These must be false:
        assert!(
            !is_arch_significant(&["src/reconfiguration.rs".into()]),
            "src/reconfiguration.rs must NOT be arch-significant"
        );
        assert!(
            !is_arch_significant(&["src/observer.rs".into()]),
            "src/observer.rs must NOT be arch-significant"
        );
    }
}
