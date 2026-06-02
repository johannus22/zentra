use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;

use super::{severity_counts, CiContext, CiPlatformKind};
use crate::state::{Finding, Severity};

pub const STICKY_COMMENT_MARKER: &str = "<!-- zentra-ci-comment -->";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CiCommentPlan {
    Publish { body: String },
    Skip { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StickyCommentAction {
    Create { body: String },
    Update { id: u64, body: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitlabAuthHeader {
    pub name: &'static str,
    pub value: String,
}

#[derive(Deserialize)]
struct ExistingComment {
    id: u64,
    body: String,
}

pub fn select_sticky_comment_action(
    existing_comments: &[(u64, String)],
    body: String,
) -> StickyCommentAction {
    existing_comments
        .iter()
        .find(|(_, existing_body)| existing_body.contains(STICKY_COMMENT_MARKER))
        .map(|(id, _)| StickyCommentAction::Update {
            id: *id,
            body: body.clone(),
        })
        .unwrap_or(StickyCommentAction::Create { body })
}

pub fn prepare_comment_request_from_env(
    env: &HashMap<String, String>,
    context: &CiContext,
    findings: &[Finding],
) -> CiCommentPlan {
    if comment_token(env, context.platform).is_none() {
        return CiCommentPlan::Skip {
            reason: "CI comment skipped: no platform token available".to_string(),
        };
    }

    if context.pr_or_mr_number.is_none() {
        return CiCommentPlan::Skip {
            reason: "CI comment skipped: missing PR/MR number".to_string(),
        };
    }

    match context.platform {
        CiPlatformKind::Github if env.get("GITHUB_REPOSITORY").is_none() => {
            return CiCommentPlan::Skip {
                reason: "CI comment skipped: missing GITHUB_REPOSITORY".to_string(),
            };
        }
        CiPlatformKind::Gitlab if env.get("CI_PROJECT_ID").is_none() => {
            return CiCommentPlan::Skip {
                reason: "CI comment skipped: missing CI_PROJECT_ID".to_string(),
            };
        }
        _ => {}
    }

    CiCommentPlan::Publish {
        body: build_sticky_comment_body(context, findings),
    }
}

pub fn build_sticky_comment_body(context: &CiContext, findings: &[Finding]) -> String {
    let counts = severity_counts(findings);
    let mut body = format!(
        "{STICKY_COMMENT_MARKER}\n## Zentra CI Security Scan\n\nPlatform: {}\nScope: PR/MR {}\nBase: {}\nHead: {}\n\nCritical: {}\nHigh: {}\nMedium: {}\nLow: {}\nInfo: {}\n\nArtifacts: `.zentra/ci-report.md`, `.zentra/ci-report.json`\n",
        context.platform.as_str(),
        context.pr_or_mr_number.as_deref().unwrap_or("unknown"),
        context.base_ref,
        context.head_ref,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info,
    );

    let critical_findings = findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Critical))
        .collect::<Vec<_>>();

    if !critical_findings.is_empty() {
        body.push_str("\n### Critical Findings\n");
        for finding in critical_findings {
            body.push_str(&format!(
                "- {} ({})\n",
                finding.title,
                finding.location.as_deref().unwrap_or("N/A")
            ));
        }
    }

    body
}

pub fn redact_token(token: &str) -> String {
    if token.is_empty() {
        String::new()
    } else {
        "[redacted]".to_string()
    }
}

pub fn comment_http_timeout() -> Duration {
    Duration::from_secs(10)
}

fn comment_http_client() -> Result<Client> {
    Ok(Client::builder().timeout(comment_http_timeout()).build()?)
}

pub fn gitlab_auth_header_from_env(env: &HashMap<String, String>) -> Option<GitlabAuthHeader> {
    env.get("GITLAB_TOKEN")
        .filter(|value| !value.is_empty())
        .map(|token| GitlabAuthHeader {
            name: "Authorization",
            value: format!("Bearer {token}"),
        })
        .or_else(|| {
            env.get("CI_JOB_TOKEN")
                .filter(|value| !value.is_empty())
                .map(|token| GitlabAuthHeader {
                    name: "JOB-TOKEN",
                    value: token.to_string(),
                })
        })
}

pub async fn publish_comment_best_effort(context: &CiContext, findings: &[Finding]) -> Result<()> {
    let env = std::env::vars().collect::<HashMap<_, _>>();
    match prepare_comment_request_from_env(&env, context, findings) {
        CiCommentPlan::Skip { reason } => {
            println!("{reason}");
            Ok(())
        }
        CiCommentPlan::Publish { body } => publish_comment(&env, context, &body).await,
    }
}

async fn publish_comment(
    env: &HashMap<String, String>,
    context: &CiContext,
    body: &str,
) -> Result<()> {
    match context.platform {
        CiPlatformKind::Github => publish_github_comment(env, context, body).await,
        CiPlatformKind::Gitlab => publish_gitlab_comment(env, context, body).await,
    }
}

async fn publish_github_comment(
    env: &HashMap<String, String>,
    context: &CiContext,
    body: &str,
) -> Result<()> {
    let token = comment_token(env, context.platform).ok_or_else(|| anyhow!("missing token"))?;
    let repo = env
        .get("GITHUB_REPOSITORY")
        .ok_or_else(|| anyhow!("missing GITHUB_REPOSITORY"))?;
    let pr = context
        .pr_or_mr_number
        .as_deref()
        .ok_or_else(|| anyhow!("missing PR number"))?;
    let api_url = env
        .get("GITHUB_API_URL")
        .map(String::as_str)
        .unwrap_or("https://api.github.com");
    let url = format!("{api_url}/repos/{repo}/issues/{pr}/comments");

    let client = comment_http_client()?;
    let existing = client
        .get(&url)
        .bearer_auth(token)
        .header("User-Agent", "zentra-cli")
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<ExistingComment>>()
        .await?
        .into_iter()
        .map(|comment| (comment.id, comment.body))
        .collect::<Vec<_>>();

    match select_sticky_comment_action(&existing, body.to_string()) {
        StickyCommentAction::Create { body } => {
            client
                .post(url)
                .bearer_auth(token)
                .header("User-Agent", "zentra-cli")
                .json(&serde_json::json!({ "body": body }))
                .send()
                .await?
                .error_for_status()?;
        }
        StickyCommentAction::Update { id, body } => {
            let update_url = format!("{api_url}/repos/{repo}/issues/comments/{id}");
            client
                .patch(update_url)
                .bearer_auth(token)
                .header("User-Agent", "zentra-cli")
                .json(&serde_json::json!({ "body": body }))
                .send()
                .await?
                .error_for_status()?;
        }
    }
    Ok(())
}

async fn publish_gitlab_comment(
    env: &HashMap<String, String>,
    context: &CiContext,
    body: &str,
) -> Result<()> {
    let auth_header = gitlab_auth_header_from_env(env).ok_or_else(|| anyhow!("missing token"))?;
    let project_id = env
        .get("CI_PROJECT_ID")
        .ok_or_else(|| anyhow!("missing CI_PROJECT_ID"))?;
    let mr = context
        .pr_or_mr_number
        .as_deref()
        .ok_or_else(|| anyhow!("missing MR number"))?;
    let api_url = env
        .get("CI_API_V4_URL")
        .map(String::as_str)
        .unwrap_or("https://gitlab.com/api/v4");
    let url = format!("{api_url}/projects/{project_id}/merge_requests/{mr}/notes");

    let client = comment_http_client()?;
    let existing = client
        .get(&url)
        .header(auth_header.name, auth_header.value.clone())
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<ExistingComment>>()
        .await?
        .into_iter()
        .map(|comment| (comment.id, comment.body))
        .collect::<Vec<_>>();

    match select_sticky_comment_action(&existing, body.to_string()) {
        StickyCommentAction::Create { body } => {
            client
                .post(url)
                .header(auth_header.name, auth_header.value.clone())
                .json(&serde_json::json!({ "body": body }))
                .send()
                .await?
                .error_for_status()?;
        }
        StickyCommentAction::Update { id, body } => {
            let update_url =
                format!("{api_url}/projects/{project_id}/merge_requests/{mr}/notes/{id}");
            client
                .put(update_url)
                .header(auth_header.name, auth_header.value.clone())
                .json(&serde_json::json!({ "body": body }))
                .send()
                .await?
                .error_for_status()?;
        }
    }
    Ok(())
}

fn comment_token(env: &HashMap<String, String>, platform: CiPlatformKind) -> Option<&str> {
    let names: &[&str] = match platform {
        CiPlatformKind::Github => &["GITHUB_TOKEN", "GH_TOKEN"],
        CiPlatformKind::Gitlab => &["GITLAB_TOKEN", "CI_JOB_TOKEN"],
    };

    names.iter().find_map(|name| {
        env.get(*name)
            .filter(|value| !value.is_empty())
            .map(String::as_str)
    })
}
