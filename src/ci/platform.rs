use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

use super::CiPlatformKind;

pub const PR_MR_ONLY_MESSAGE: &str =
    "Zentra CI supports pull request and merge request pipelines only.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CiContext {
    pub platform: CiPlatformKind,
    pub base_ref: String,
    pub head_ref: String,
    pub changed_files: Vec<String>,
    pub impact_files: Vec<String>,
    pub commit_sha: Option<String>,
    pub pr_or_mr_number: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CiMetadata {
    pub platform: CiPlatformKind,
    pub base_ref: String,
    pub head_ref: String,
    pub commit_sha: Option<String>,
    pub pr_or_mr_number: Option<String>,
}

pub fn detect_ci_context_from_current_env(
    changed_files: Vec<String>,
    impact_files: Vec<String>,
) -> Result<CiContext> {
    let env = std::env::vars().collect::<HashMap<_, _>>();
    detect_ci_context_from_env(&env, changed_files, impact_files)
}

pub fn detect_ci_context_from_env(
    env: &HashMap<String, String>,
    changed_files: Vec<String>,
    impact_files: Vec<String>,
) -> Result<CiContext> {
    let metadata = extract_ci_metadata_from_env(env)?;

    if changed_files.is_empty() {
        bail!(super::diff::missing_history_guidance(metadata.platform));
    }

    Ok(CiContext {
        platform: metadata.platform,
        base_ref: metadata.base_ref,
        head_ref: metadata.head_ref,
        changed_files,
        impact_files,
        commit_sha: metadata.commit_sha,
        pr_or_mr_number: metadata.pr_or_mr_number,
    })
}

pub(crate) fn extract_ci_metadata_from_current_env() -> Result<CiMetadata> {
    let env = std::env::vars().collect::<HashMap<_, _>>();
    extract_ci_metadata_from_env(&env)
}

pub(crate) fn extract_ci_metadata_from_env(env: &HashMap<String, String>) -> Result<CiMetadata> {
    if env
        .get("GITHUB_ACTIONS")
        .is_some_and(|value| value == "true")
    {
        return extract_github_metadata(env);
    }

    if env.get("GITLAB_CI").is_some_and(|value| value == "true") {
        return extract_gitlab_metadata(env);
    }

    bail!(PR_MR_ONLY_MESSAGE);
}

fn extract_github_metadata(env: &HashMap<String, String>) -> Result<CiMetadata> {
    let event_name = env.get("GITHUB_EVENT_NAME").map(String::as_str);
    if !matches!(event_name, Some("pull_request" | "pull_request_target")) {
        bail!(PR_MR_ONLY_MESSAGE);
    }

    Ok(CiMetadata {
        platform: CiPlatformKind::Github,
        base_ref: required(env, "GITHUB_BASE_REF")?,
        head_ref: required(env, "GITHUB_HEAD_REF")?,
        commit_sha: env.get("GITHUB_SHA").cloned(),
        pr_or_mr_number: env
            .get("GITHUB_REF")
            .and_then(|value| parse_github_pr_number(value)),
    })
}

fn extract_gitlab_metadata(env: &HashMap<String, String>) -> Result<CiMetadata> {
    let mr_number = env.get("CI_MERGE_REQUEST_IID").cloned();
    if mr_number.is_none() {
        bail!(PR_MR_ONLY_MESSAGE);
    }

    Ok(CiMetadata {
        platform: CiPlatformKind::Gitlab,
        base_ref: required(env, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME")?,
        head_ref: required(env, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")?,
        commit_sha: env.get("CI_COMMIT_SHA").cloned(),
        pr_or_mr_number: mr_number,
    })
}

fn required(env: &HashMap<String, String>, name: &str) -> Result<String> {
    env.get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| anyhow!("missing required CI environment variable {name}"))
}

fn parse_github_pr_number(github_ref: &str) -> Option<String> {
    let mut parts = github_ref.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("refs"), Some("pull"), Some(number), Some("merge" | "head")) => {
            Some(number.to_string())
        }
        _ => None,
    }
}
