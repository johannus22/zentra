//! GitLab triage issue publishing for full-scan, report-only pipelines.
//!
//! Distinct from MR-mode sticky comments (`comment.rs`): the staging job scans
//! the whole repo, never fails the pipeline, and files/updates one GitLab issue
//! labeled `security,zentra-triage` so a human can verify the findings. GitLab
//! only — GitHub push is intentionally unsupported.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

use super::comment::{comment_http_timeout, gitlab_auth_header_from_env, GitlabAuthHeader};
use super::{severity_counts, CiContext, CiPlatformKind};
use crate::security::audit_log::sha256_str;
use crate::state::{Finding, Severity};

/// Hidden marker embedded in the issue description, so the sticky-issue lookup
/// can tell our issue apart from a human-created one with the same labels.
pub const TRIAGE_ISSUE_MARKER: &str = "<!-- zentra-triage-issue -->";

/// Wraps a hidden JSON array of every current finding fingerprint, so the next
/// run can diff against it to compute the "New since last run" set.
const FINGERPRINT_PREFIX: &str = "<!-- zentra-fingerprints:";
const FINGERPRINT_SUFFIX: &str = "-->";

/// Labels applied to the triage issue. `zentra-triage` is the sticky-lookup key.
const TRIAGE_LABELS: &str = "security,zentra-triage";

/// Cap response reads so a misconfigured or hostile API endpoint cannot exhaust
/// runner memory. Mirrors `comment::fetch_existing_comments`; 8 MiB is far above
/// any real issue list or body.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Stable identity for a finding across runs: sha256 of `scanner|title|location`,
/// truncated to 16 hex chars. Changing any of the three changes the fingerprint,
/// which surfaces the finding as "new" on the next run.
pub fn finding_fingerprint(finding: &Finding) -> String {
    let location = finding.location.as_deref().unwrap_or("");
    let raw = format!("{}|{}|{}", finding.scanner, finding.title, location);
    let full = sha256_str(&raw);
    full.chars().take(16).collect()
}

/// Extract the hidden fingerprint array from a prior issue body. Returns an
/// empty vec on any parse problem (missing marker, malformed JSON, truncated
/// array) so callers degrade cleanly: everything looks new.
pub fn parse_prior_fingerprints(body: &str) -> Vec<String> {
    let Some(marker_start) = body.find(FINGERPRINT_PREFIX) else {
        return Vec::new();
    };
    let after_prefix = &body[marker_start + FINGERPRINT_PREFIX.len()..];
    let Some(bracket_start) = after_prefix.find('[') else {
        return Vec::new();
    };
    let rest = &after_prefix[bracket_start..];
    let Some(bracket_end) = rest.find(']') else {
        return Vec::new();
    };
    let json_str = &rest[..=bracket_end];
    serde_json::from_str::<Vec<String>>(json_str).unwrap_or_default()
}

/// Build the GitLab triage issue body. Contains the marker, a severity summary,
/// a "New since last run" section (findings whose fingerprint is in
/// `new_fingerprints`), a full findings table, the branch and commit, and the
/// hidden fingerprint array covering ALL current findings. When findings is
/// empty, the body states the scan is clean.
pub fn build_triage_issue_body(
    context: &CiContext,
    findings: &[Finding],
    new_fingerprints: &[String],
) -> String {
    let counts = severity_counts(findings);
    let new_set: HashSet<&str> = new_fingerprints.iter().map(String::as_str).collect();

    let mut body = String::new();
    body.push_str(TRIAGE_ISSUE_MARKER);
    body.push_str("\n# Zentra Security Triage\n\n");

    if findings.is_empty() {
        body.push_str("The latest full scan is clean. There are no findings to verify.\n\n");
    } else {
        body.push_str(&format!(
            "Summary: {} findings to verify — {} Critical, {} High, {} Medium, {} Low, {} Info.\n\n",
            findings.len(),
            counts.critical,
            counts.high,
            counts.medium,
            counts.low,
            counts.info,
        ));

        let new_findings: Vec<&Finding> = findings
            .iter()
            .filter(|finding| new_set.contains(finding_fingerprint(finding).as_str()))
            .collect();

        body.push_str("## New since last run\n\n");
        if new_findings.is_empty() {
            body.push_str("There are no new findings since the last run.\n\n");
        } else {
            body.push_str(&format!(
                "{} new finding(s) need a first review:\n\n",
                new_findings.len()
            ));
            let mut sorted_new = new_findings.clone();
            sorted_new.sort_by_key(|finding| finding.severity.order());
            for finding in sorted_new {
                body.push_str(&format!(
                    "- [ ] {} {} — `{}`\n",
                    finding.severity,
                    finding.title,
                    finding.location.as_deref().unwrap_or("N/A"),
                ));
            }
            body.push('\n');
        }

        body.push_str("## All findings\n\n");
        body.push_str("| Severity | Finding | Scanner | Location | CWE |\n|---|---|---|---|---|\n");
        let mut sorted = findings.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|finding| finding.severity.order());
        for finding in sorted {
            body.push_str(&format!(
                "| {} {} | {} | {} | `{}` | {} |\n",
                severity_emoji(&finding.severity),
                finding.severity,
                finding.title,
                finding.scanner,
                finding.location.as_deref().unwrap_or("N/A"),
                finding.cwe.as_deref().unwrap_or("—"),
            ));
        }
        body.push('\n');
    }

    body.push_str(&format!("Branch: `{}`\n", context.head_ref));
    if let Some(sha) = &context.commit_sha {
        body.push_str(&format!("Commit: `{}`\n", sha));
    }
    body.push_str("\nThe full findings list and recommendations are in the pipeline artifacts: `.zentra/ci-report.md`.\n\n");

    let fingerprints: Vec<String> = findings.iter().map(finding_fingerprint).collect();
    let fingerprint_json =
        serde_json::to_string(&fingerprints).unwrap_or_else(|_| "[]".to_string());
    body.push_str(&format!(
        "{FINGERPRINT_PREFIX} {fingerprint_json} {FINGERPRINT_SUFFIX}\n"
    ));

    body
}

/// File or update the sticky GitLab triage issue for this run. Never hard-fails
/// the pipeline: every error path prints a clear reason and returns `Ok`. The
/// returned `String` is the triage outcome note for the CI report.
///
/// - No token → prints setup guidance, returns a "not created" note.
/// - Sticky issue found (description contains the marker) → PUT update.
/// - No sticky issue and findings present → POST create.
/// - No sticky issue and no findings → skip creation with a note.
pub async fn publish_triage_issue_best_effort(
    context: &CiContext,
    findings: &[Finding],
) -> Result<String> {
    let env = std::env::vars().collect::<HashMap<_, _>>();
    publish_triage_issue_with_env(&env, context, findings).await
}

/// Testable core: takes an explicit env map so tests do not mutate process env.
async fn publish_triage_issue_with_env(
    env: &HashMap<String, String>,
    context: &CiContext,
    findings: &[Finding],
) -> Result<String> {
    if context.platform != CiPlatformKind::Gitlab {
        println!(
            "Zentra triage ticket skipped: triage issues are GitLab only (platform is {}).",
            context.platform.as_str()
        );
        return Ok("skipped (GitLab only)".to_string());
    }

    let auth_header = match triage_auth_header_from_env(env) {
        Some(header) => header,
        None => {
            println!(
                "Zentra triage ticket skipped: no GitLab token found. \
                 Set ZENTRA_GITLAB_TOKEN (PAT with 'api' scope) as a masked CI/CD variable \
                 to enable auto-ticketing. Findings are in the pipeline artifacts: \
                 .zentra/ci-report.md"
            );
            return Ok("not created (no GitLab token configured)".to_string());
        }
    };

    let project_id = match env.get("CI_PROJECT_ID").filter(|v| !v.is_empty()) {
        Some(id) => id.clone(),
        None => {
            println!("Zentra triage ticket skipped: missing CI_PROJECT_ID.");
            return Ok("not created (missing CI_PROJECT_ID)".to_string());
        }
    };

    let api_url = env
        .get("CI_API_V4_URL")
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| "https://gitlab.com/api/v4".to_string());

    let client = match triage_http_client() {
        Ok(c) => c,
        Err(err) => {
            println!("Zentra triage ticket skipped: failed to build HTTP client: {err}");
            return Ok("not created (HTTP client error)".to_string());
        }
    };

    let assignee_ids = resolve_assignee(&client, &api_url, env, &auth_header).await;

    let existing = match fetch_open_triage_issues(&client, &api_url, &project_id, &auth_header).await {
        Ok(issues) => issues,
        Err(err) => {
            println!("Zentra triage ticket skipped: failed to list open issues: {err}");
            return Ok("not created (failed to list issues)".to_string());
        }
    };

    let sticky = existing
        .iter()
        .find(|issue| {
            issue
                .description
                .as_deref()
                .is_some_and(|d| d.contains(TRIAGE_ISSUE_MARKER))
        })
        .cloned();

    let current_fingerprints: Vec<String> = findings.iter().map(finding_fingerprint).collect();

    match sticky {
        Some(issue) => {
            let prior = issue
                .description
                .as_deref()
                .map(parse_prior_fingerprints)
                .unwrap_or_default();
            let prior_set: HashSet<&str> = prior.iter().map(String::as_str).collect();
            let new_fingerprints: Vec<String> = current_fingerprints
                .iter()
                .filter(|fp| !prior_set.contains(fp.as_str()))
                .cloned()
                .collect();

            let body =
                build_triage_issue_body(context, findings, &new_fingerprints);

            match update_issue(
                &client,
                &api_url,
                &project_id,
                issue.iid,
                &body,
                &assignee_ids,
                &auth_header,
            )
            .await
            {
                Ok(()) => {
                    println!("Zentra triage ticket: updated issue #{}", issue.iid);
                    Ok(format!("updated issue #{}", issue.iid))
                }
                Err(err) => {
                    println!(
                        "Zentra triage ticket: failed to update issue #{}: {err}",
                        issue.iid
                    );
                    Ok("not created (update failed)".to_string())
                }
            }
        }
        None => {
            if findings.is_empty() {
                println!("Zentra triage ticket: no open sticky issue and no findings; not creating one.");
                return Ok("skipped (no findings)".to_string());
            }
            let title = format!(
                "Zentra security triage — {} — {} findings to verify",
                context.head_ref,
                findings.len()
            );
            // First run: every current finding is new.
            let body = build_triage_issue_body(context, findings, &current_fingerprints);

            match create_issue(
                &client,
                &api_url,
                &project_id,
                &title,
                &body,
                &assignee_ids,
                &auth_header,
            )
            .await
            {
                Ok(iid) => {
                    println!("Zentra triage ticket: created issue #{iid}");
                    Ok(format!("created issue #{iid}"))
                }
                Err(err) => {
                    println!("Zentra triage ticket: failed to create issue: {err}");
                    Ok("not created (create failed)".to_string())
                }
            }
        }
    }
}

#[derive(Clone, Deserialize)]
struct GitlabIssue {
    iid: u64,
    description: Option<String>,
}

#[derive(Deserialize)]
struct GitlabUser {
    id: u64,
}

#[derive(Deserialize)]
struct CreatedIssue {
    iid: u64,
}

fn triage_http_timeout() -> Duration {
    comment_http_timeout()
}

/// Resolve the GitLab auth header for triage publishing. The README documents
/// `ZENTRA_GITLAB_TOKEN` as the dedicated triage variable, so it takes priority:
/// a PAT scoped to `api` with no other consumers. If unset, fall back to the
/// shared `gitlab_auth_header_from_env` resolver (`GITLAB_TOKEN`, then
/// `CI_JOB_TOKEN`) unchanged — MR-comment behavior is not touched by this path.
fn triage_auth_header_from_env(env: &HashMap<String, String>) -> Option<GitlabAuthHeader> {
    env.get("ZENTRA_GITLAB_TOKEN")
        .filter(|value| !value.is_empty())
        .map(|token| GitlabAuthHeader {
            name: "Authorization",
            value: format!("Bearer {token}"),
        })
        .or_else(|| gitlab_auth_header_from_env(env))
}

fn triage_http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(triage_http_timeout())
        .build()?)
}

/// Resolve the issue assignee. Order:
/// 1. `ZENTRA_TRIAGE_ASSIGNEE` username → GET /users?username=… → id.
/// 2. GET /user with the token → token owner's id (auto path).
/// 3. Any failure → empty (unassigned) with a printed warning. Never bails.
async fn resolve_assignee(
    client: &Client,
    api_url: &str,
    env: &HashMap<String, String>,
    auth_header: &GitlabAuthHeader,
) -> Vec<u64> {
    if let Some(username) = env
        .get("ZENTRA_TRIAGE_ASSIGNEE")
        .filter(|v| !v.trim().is_empty())
    {
        let url = format!(
            "{api_url}/users",
        );
        match client
            .get(&url)
            .header(auth_header.name, auth_header.value.clone())
            .query(&[("username", username.as_str())])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match fetch_capped_json::<Vec<GitlabUser>>(resp).await {
                    Ok(users) if !users.is_empty() => return vec![users[0].id],
                    Ok(_) => {
                        println!(
                            "Zentra triage ticket: ZENTRA_TRIAGE_ASSIGNEE '{username}' matched no GitLab user; leaving the issue unassigned."
                        );
                    }
                    Err(err) => {
                        println!(
                            "Zentra triage ticket: could not parse user lookup for '{username}': {err}; leaving the issue unassigned."
                        );
                    }
                }
            }
            Ok(resp) => {
                println!(
                    "Zentra triage ticket: user lookup for '{username}' returned status {}; leaving the issue unassigned.",
                    resp.status()
                );
            }
            Err(err) => {
                println!(
                    "Zentra triage ticket: user lookup for '{username}' failed: {err}; leaving the issue unassigned."
                );
            }
        }
        return Vec::new();
    }

    // Auto path: the ticket follows whoever owns the token.
    let url = format!("{api_url}/user");
    match client
        .get(&url)
        .header(auth_header.name, auth_header.value.clone())
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match fetch_capped_json::<GitlabUser>(resp).await {
            Ok(user) => vec![user.id],
            Err(err) => {
                println!(
                    "Zentra triage ticket: could not parse token owner: {err}; leaving the issue unassigned."
                );
                Vec::new()
            }
        },
        Ok(resp) => {
            println!(
                "Zentra triage ticket: token-owner lookup returned status {}; leaving the issue unassigned.",
                resp.status()
            );
            Vec::new()
        }
        Err(err) => {
            println!(
                "Zentra triage ticket: token-owner lookup failed: {err}; leaving the issue unassigned."
            );
            Vec::new()
        }
    }
}

async fn fetch_open_triage_issues(
    client: &Client,
    api_url: &str,
    project_id: &str,
    auth_header: &GitlabAuthHeader,
) -> Result<Vec<GitlabIssue>> {
    let url = format!("{api_url}/projects/{project_id}/issues");
    let resp = client
        .get(&url)
        .header(auth_header.name, auth_header.value.clone())
        .query(&[
            ("labels", "zentra-triage"),
            ("state", "opened"),
        ])
        .send()
        .await?
        .error_for_status()?;
    fetch_capped_json::<Vec<GitlabIssue>>(resp).await
}

async fn update_issue(
    client: &Client,
    api_url: &str,
    project_id: &str,
    issue_iid: u64,
    body: &str,
    assignee_ids: &[u64],
    auth_header: &GitlabAuthHeader,
) -> Result<()> {
    let url = format!("{api_url}/projects/{project_id}/issues/{issue_iid}");
    let mut payload = serde_json::json!({ "description": body });
    if !assignee_ids.is_empty() {
        payload["assignee_ids"] = serde_json::json!(assignee_ids);
    }
    client
        .put(&url)
        .header(auth_header.name, auth_header.value.clone())
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn create_issue(
    client: &Client,
    api_url: &str,
    project_id: &str,
    title: &str,
    body: &str,
    assignee_ids: &[u64],
    auth_header: &GitlabAuthHeader,
) -> Result<u64> {
    let url = format!("{api_url}/projects/{project_id}/issues");
    let mut payload = serde_json::json!({
        "title": title,
        "description": body,
        "labels": TRIAGE_LABELS,
    });
    if !assignee_ids.is_empty() {
        payload["assignee_ids"] = serde_json::json!(assignee_ids);
    }
    let resp = client
        .post(&url)
        .header(auth_header.name, auth_header.value.clone())
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    let created = fetch_capped_json::<CreatedIssue>(resp).await?;
    Ok(created.iid)
}

/// Read the response body under `MAX_RESPONSE_BYTES`, then parse as JSON. The
/// cap prevents an over-large or hostile body from exhausting runner memory
/// before `serde_json` ever sees it.
async fn fetch_capped_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < MAX_RESPONSE_BYTES {
        match resp.chunk().await? {
            Some(chunk) => {
                let take = (MAX_RESPONSE_BYTES - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            None => break,
        }
    }
    Ok(serde_json::from_slice(&buf)?)
}

fn severity_emoji(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(severity: Severity, title: &str, location: &str) -> Finding {
        Finding {
            scanner: "sast".to_string(),
            severity,
            title: title.to_string(),
            description: "desc".to_string(),
            location: Some(location.to_string()),
            recommendation: "fix it".to_string(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        }
    }

    #[test]
    fn fingerprint_is_stable_and_changes_with_inputs() {
        let f = sample_finding(Severity::High, "SQLi", "src/a.rs:1");
        let fp1 = finding_fingerprint(&f);
        let fp2 = finding_fingerprint(&f);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
        assert_eq!(fp1.len(), 16, "fingerprint must be 16 hex chars");

        // title change → different fingerprint
        let mut other = f.clone();
        other.title = "SQLi v2".to_string();
        assert_ne!(finding_fingerprint(&other), fp1);

        // location change → different fingerprint
        let mut other = f.clone();
        other.location = Some("src/b.rs:2".to_string());
        assert_ne!(finding_fingerprint(&other), fp1);

        // scanner change → different fingerprint
        let mut other = f.clone();
        other.scanner = "iac_scan".to_string();
        assert_ne!(finding_fingerprint(&other), fp1);
    }

    #[test]
    fn parse_prior_fingerprints_returns_empty_for_garbage() {
        assert!(parse_prior_fingerprints("no marker here").is_empty());
        assert!(parse_prior_fingerprints("<!-- zentra-fingerprints: not json -->").is_empty());
        assert!(parse_prior_fingerprints("<!-- zentra-fingerprints: [unclosed").is_empty());
    }

    #[test]
    fn parse_prior_fingerprints_roundtrips_through_body() {
        let context = CiContext {
            platform: CiPlatformKind::Gitlab,
            base_ref: "staging".to_string(),
            head_ref: "staging".to_string(),
            changed_files: vec![],
            impact_files: vec![],
            commit_sha: Some("abc123".to_string()),
            pr_or_mr_number: None,
        };
        let findings = vec![
            sample_finding(Severity::Critical, "A", "f.rs:1"),
            sample_finding(Severity::High, "B", "f.rs:2"),
        ];
        let body = build_triage_issue_body(&context, &findings, &Vec::new());
        let parsed = parse_prior_fingerprints(&body);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&finding_fingerprint(&findings[0])));
        assert!(parsed.contains(&finding_fingerprint(&findings[1])));
    }
}
