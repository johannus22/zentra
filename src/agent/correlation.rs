//! Cross-scanner finding correlation / dedup.
//!
//! Independent scanners (most notably `ThreatModel` and `Sast`) frequently flag
//! the *same* underlying vulnerability with different wording. This pass collapses
//! such duplicates into a single finding and records the other scanners that
//! independently found it in [`Finding::corroborated_by`] — corroboration across
//! independent scanners is a confidence signal that a finding is a true positive.
//!
//! Detection is hybrid: a free deterministic pre-pass merges the easy cases (same
//! normalized location + strong title overlap), then a single LLM call clusters the
//! semantic duplicates that don't match textually.
//!
//! **Best-effort:** on any LLM error or unparseable response, the findings from the
//! deterministic pre-pass are returned unchanged. The pass never drops a finding —
//! a duplicate is strictly better than a dropped Critical.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::provider::{AgentMessage, LLMProvider, ToolDefinition};
use crate::state::Finding;

/// Descriptions are truncated to this many chars in the LLM listing to bound token cost.
const MAX_DESC_LEN: usize = 300;
/// Title token overlap (Jaccard) required for the deterministic pre-pass to merge.
const TITLE_JACCARD_THRESHOLD: f32 = 0.5;

/// Correlate findings across scanners, merging duplicates and recording corroboration.
pub async fn correlate(provider: &Arc<dyn LLMProvider>, findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() < 2 {
        return findings;
    }

    // Phase A: deterministic pre-pass (no tokens).
    let pre = deterministic_prepass(findings);
    if pre.len() < 2 {
        return pre;
    }

    // Phase B: LLM semantic clustering for what remains.
    match llm_clusters(provider, &pre).await {
        Some(clusters) => apply_clusters(pre, clusters),
        None => pre, // LLM failed / returned nothing usable — keep the pre-pass result.
    }
}

/// Merge findings that share a normalized location and strong title overlap, or an
/// exact normalized title. Returns the collapsed set.
fn deterministic_prepass(findings: Vec<Finding>) -> Vec<Finding> {
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();

    for i in 0..n {
        for j in (i + 1)..n {
            if same_issue_deterministic(&findings[i], &findings[j]) {
                union(&mut parent, i, j);
            }
        }
    }

    let clusters = clusters_from_parent(&mut parent);
    apply_clusters(findings, clusters)
}

fn same_issue_deterministic(a: &Finding, b: &Finding) -> bool {
    let title_a = normalize(&a.title);
    let title_b = normalize(&b.title);

    // Exact (normalized) title match is a strong signal regardless of location.
    if !title_a.is_empty() && title_a == title_b {
        return true;
    }

    // Same concrete location + meaningful title overlap.
    match (&a.location, &b.location) {
        (Some(la), Some(lb)) if normalize(la) == normalize(lb) => {
            title_jaccard(&title_a, &title_b) >= TITLE_JACCARD_THRESHOLD
        }
        _ => false,
    }
}

fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

fn title_tokens(title: &str) -> BTreeSet<String> {
    title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 2)
        .map(|t| t.to_string())
        .collect()
}

fn title_jaccard(a: &str, b: &str) -> f32 {
    let ta = title_tokens(a);
    let tb = title_tokens(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count() as f32;
    let union = ta.union(&tb).count() as f32;
    inter / union
}

/// Build a structured cluster request, ask the LLM to group equivalent findings,
/// and return the index clusters. Returns `None` on any failure.
async fn llm_clusters(
    provider: &Arc<dyn LLMProvider>,
    findings: &[Finding],
) -> Option<Vec<Vec<usize>>> {
    let tool = ToolDefinition {
        name: "report_clusters".to_string(),
        description: "Report groups of finding indices that describe the SAME underlying \
vulnerability. Each inner array is one group of 2+ indices. Omit findings that have no duplicate."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "clusters": {
                    "type": "array",
                    "description": "Groups of finding indices that are the same issue",
                    "items": {
                        "type": "array",
                        "items": { "type": "integer" }
                    }
                }
            },
            "required": ["clusters"]
        }),
    };

    let system =
        "You are a security finding de-duplication engine. You receive a numbered list of \
findings produced by independent scanners. Cluster together findings that describe the SAME \
underlying vulnerability, even if the wording, scanner, or location differ. An architectural \
finding (no file:line) and a code-level finding (with file:line) that share the same root cause \
MUST be clustered together. Do NOT merge findings that are genuinely distinct vulnerabilities. \
Call report_clusters with the groups; each group is an array of 2 or more indices. Indices that \
have no duplicate must be left out entirely.";

    let mut listing = String::new();
    for (i, f) in findings.iter().enumerate() {
        let loc = f.location.as_deref().unwrap_or("(no location)");
        listing.push_str(&format!(
            "{} | {} | {} | {} | {} | {}\n",
            i,
            f.scanner,
            f.severity,
            f.title,
            loc,
            truncate(&f.description, MAX_DESC_LEN),
        ));
    }
    let user = format!(
        "Findings (index | scanner | severity | title | location | description):\n\n{}\n\
Call report_clusters with groups of indices that describe the same underlying vulnerability.",
        listing
    );

    let messages = vec![AgentMessage::User(user)];
    let resp = match provider
        .complete_with_tools(system, &messages, std::slice::from_ref(&tool), 1024, None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            crate::logging::warn(
                "scan",
                format!("finding correlation skipped: LLM call failed: {e}"),
            );
            return None;
        }
    };

    let call = resp
        .tool_calls
        .into_iter()
        .find(|c| c.name == "report_clusters")?;
    let arr = call.arguments.get("clusters")?.as_array()?;

    let clusters: Vec<Vec<usize>> = arr
        .iter()
        .filter_map(|group| {
            let g: Vec<usize> = group
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64().map(|u| u as usize))
                .collect();
            Some(g)
        })
        .collect();

    Some(clusters)
}

/// Apply index clusters to `findings`, merging each group of 2+ into one finding and
/// passing singletons through unchanged. Defensive against out-of-range / duplicate /
/// overlapping indices: each finding is used at most once, first cluster wins.
fn apply_clusters(findings: Vec<Finding>, clusters: Vec<Vec<usize>>) -> Vec<Finding> {
    let n = findings.len();
    let mut used = vec![false; n];
    let mut merged = Vec::new();

    for group in clusters {
        // Keep only valid, not-yet-used, deduplicated indices.
        let mut idxs: Vec<usize> = Vec::new();
        for i in group {
            if i < n && !used[i] && !idxs.contains(&i) {
                idxs.push(i);
            }
        }
        if idxs.len() < 2 {
            continue; // not a real cluster — leave members as singletons below
        }
        for &i in &idxs {
            used[i] = true;
        }
        merged.push(merge_group(&findings, &idxs));
    }

    // Emit untouched findings in their original order, interleaving merged ones is not
    // necessary — the file is re-sorted by severity on write.
    let mut out = merged;
    for (i, f) in findings.into_iter().enumerate() {
        if !used[i] {
            out.push(f);
        }
    }
    out
}

/// Merge a group of findings (indices into `findings`) into a single finding:
/// keep the highest severity, prefer a member with a concrete location as the
/// primary, and record the other scanners in `corroborated_by`.
fn merge_group(findings: &[Finding], idxs: &[usize]) -> Finding {
    // Primary: prefer a member with a concrete location, then highest severity,
    // then lowest index — fully deterministic.
    let primary_idx = *idxs
        .iter()
        .min_by(|&&a, &&b| {
            let fa = &findings[a];
            let fb = &findings[b];
            let loc = fb.location.is_some().cmp(&fa.location.is_some()); // Some before None
            loc.then(fa.severity.order().cmp(&fb.severity.order()))
                .then(a.cmp(&b))
        })
        .expect("group is non-empty");

    let mut primary = findings[primary_idx].clone();

    // Highest severity across the whole group (smallest order).
    primary.severity = idxs
        .iter()
        .map(|&i| findings[i].severity)
        .min_by_key(|s| s.order())
        .unwrap_or(primary.severity);

    // Corroborating scanners: every other scanner name that contributed, excluding
    // the primary's own scanner. Fold in any pre-existing corroboration lists too.
    let mut corroborators: BTreeSet<String> = BTreeSet::new();
    for &i in idxs {
        let f = &findings[i];
        corroborators.insert(f.scanner.clone());
        for c in &f.corroborated_by {
            corroborators.insert(c.clone());
        }
    }
    corroborators.remove(&primary.scanner);
    primary.corroborated_by = corroborators.into_iter().collect();

    // Backfill enriched classification fields the primary lacks from other members.
    for &idx in idxs {
        if idx == primary_idx {
            continue;
        }
        let m = &findings[idx];
        if primary.cwe.is_none() {
            primary.cwe = m.cwe.clone();
        }
        if primary.secondary_cwe.is_empty() {
            primary.secondary_cwe = m.secondary_cwe.clone();
        }
        if primary.cvss_vector.is_none() {
            primary.cvss_vector = m.cvss_vector.clone();
            primary.cvss_score = m.cvss_score;
        }
        if primary.owasp.is_none() {
            primary.owasp = m.owasp.clone();
        }
    }

    primary
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

// ---- union-find helpers ----

fn find(parent: &mut [usize], x: usize) -> usize {
    let mut root = x;
    while parent[root] != root {
        root = parent[root];
    }
    // Path compression.
    let mut cur = x;
    while parent[cur] != root {
        let next = parent[cur];
        parent[cur] = root;
        cur = next;
    }
    root
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        parent[ra.max(rb)] = ra.min(rb);
    }
}

fn clusters_from_parent(parent: &mut [usize]) -> Vec<Vec<usize>> {
    let n = parent.len();
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = find(parent, i);
        groups.entry(root).or_default().push(i);
    }
    groups.into_values().filter(|g| g.len() > 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Severity;

    fn f(scanner: &str, sev: Severity, title: &str, loc: Option<&str>) -> Finding {
        Finding {
            scanner: scanner.to_string(),
            severity: sev,
            title: title.to_string(),
            description: format!("desc for {}", title),
            location: loc.map(str::to_string),
            recommendation: "fix it".to_string(),
            corroborated_by: Vec::new(),
            cwe: None,
            secondary_cwe: Vec::new(),
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
        }
    }

    #[test]
    fn prepass_merges_same_location_and_title() {
        let findings = vec![
            f(
                "sast",
                Severity::High,
                "SQL injection in login",
                Some("src/auth.rs:42"),
            ),
            f(
                "api_scan",
                Severity::Medium,
                "SQL injection login flow",
                Some("src/auth.rs:42"),
            ),
        ];
        let out = deterministic_prepass(findings);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity.order(), Severity::High.order()); // highest kept
        assert_eq!(out[0].corroborated_by, vec!["api_scan".to_string()]);
    }

    #[test]
    fn prepass_keeps_distinct_findings() {
        let findings = vec![
            f(
                "sast",
                Severity::High,
                "SQL injection in login",
                Some("src/auth.rs:42"),
            ),
            f(
                "sast",
                Severity::Low,
                "Missing CSRF token",
                Some("src/web.rs:10"),
            ),
        ];
        let out = deterministic_prepass(findings);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn apply_clusters_merges_across_scanners_keeping_highest_severity() {
        let findings = vec![
            f(
                "threat_model",
                Severity::Critical,
                "Broken access control",
                None,
            ),
            f(
                "sast",
                Severity::Medium,
                "Missing auth check on admin route",
                Some("src/admin.rs:5"),
            ),
        ];
        // LLM says these two are the same issue.
        let out = apply_clusters(findings, vec![vec![0, 1]]);
        assert_eq!(out.len(), 1);
        // Primary prefers the one with a concrete location (sast), but severity is max.
        assert_eq!(out[0].scanner, "sast");
        assert_eq!(out[0].severity.order(), Severity::Critical.order());
        assert_eq!(out[0].corroborated_by, vec!["threat_model".to_string()]);
        assert_eq!(out[0].location.as_deref(), Some("src/admin.rs:5"));
    }

    #[test]
    fn apply_clusters_ignores_bad_indices_and_singletons() {
        let findings = vec![
            f("sast", Severity::High, "A", Some("a.rs:1")),
            f("sast", Severity::Low, "B", Some("b.rs:1")),
        ];
        // Out-of-range index collapses group0 to a singleton; group1 is a singleton.
        // No valid 2+ group remains, so both findings pass through untouched.
        let out = apply_clusters(findings, vec![vec![0, 99], vec![1]]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn apply_clusters_uses_each_finding_once() {
        let findings = vec![
            f("sast", Severity::High, "A", Some("a.rs:1")),
            f("threat_model", Severity::Medium, "A variant", None),
        ];
        // Duplicate/overlapping clusters: first wins, second is ignored (already used).
        let out = apply_clusters(findings, vec![vec![0, 1], vec![0, 1]]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].corroborated_by, vec!["threat_model".to_string()]);
    }

    #[test]
    fn merge_backfills_enriched_fields_from_corroborator() {
        // Primary (concrete location, sast) lacks CWE; corroborator (threat_model) has it.
        let primary = Finding {
            scanner: "sast".into(),
            severity: Severity::High,
            title: "SQLi".into(),
            description: "d".into(),
            location: Some("src/db.rs:1".into()),
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
        };
        let other = Finding {
            scanner: "threat_model".into(),
            severity: Severity::High,
            title: "SQLi".into(),
            description: "d".into(),
            location: None,
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: Some("CWE-89".into()),
            secondary_cwe: vec!["CWE-20".into()],
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
            cvss_score: Some(9.8),
            owasp: Some("A03:2021-Injection".into()),
            confidence: None,
            screening: None,
        };
        let group = vec![primary, other];
        let merged = merge_group(&group, &[0, 1]);
        assert_eq!(merged.scanner, "sast"); // primary unchanged
        assert_eq!(merged.cwe.as_deref(), Some("CWE-89")); // backfilled
        assert_eq!(merged.secondary_cwe, vec!["CWE-20".to_string()]);
        assert_eq!(merged.owasp.as_deref(), Some("A03:2021-Injection"));
        assert!((merged.cvss_score.unwrap() - 9.8).abs() < 0.001);
    }

    #[test]
    fn merge_keeps_primary_enriched_fields_when_present() {
        let primary = Finding {
            scanner: "sast".into(),
            severity: Severity::High,
            title: "SQLi".into(),
            description: "d".into(),
            location: Some("src/db.rs:1".into()),
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: Some("CWE-89".into()),
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
        };
        let other = Finding {
            scanner: "threat_model".into(),
            severity: Severity::High,
            title: "SQLi".into(),
            description: "d".into(),
            location: None,
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: Some("CWE-999".into()),
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
        };
        let merged = merge_group(&[primary, other], &[0, 1]);
        assert_eq!(merged.cwe.as_deref(), Some("CWE-89")); // primary wins
    }
}
