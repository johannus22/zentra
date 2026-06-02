mod comment;
mod diff;
mod exit;
mod impact;
mod platform;
mod report;
mod workflow;

use anyhow::{bail, Result};
use clap::ValueEnum;

pub use comment::{
    build_sticky_comment_body, comment_http_timeout, gitlab_auth_header_from_env,
    prepare_comment_request_from_env, publish_comment_best_effort, redact_token,
    select_sticky_comment_action, CiCommentPlan, GitlabAuthHeader, StickyCommentAction,
    STICKY_COMMENT_MARKER,
};
pub use diff::{
    candidate_git_diff_ranges, changed_files_from_git, git_diff_error_with_guidance,
    missing_history_guidance, parse_git_diff_name_only,
};
pub use exit::should_fail_ci;
pub use impact::select_impact_files;
pub(crate) use platform::extract_ci_metadata_from_current_env;
pub use platform::{
    detect_ci_context_from_current_env, detect_ci_context_from_env, CiContext, PR_MR_ONLY_MESSAGE,
};
pub use report::{severity_counts, write_ci_artifacts, CiArtifactPaths, SeverityCounts};
pub use workflow::generate_ci_workflow_at;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CiPlatformKind {
    Github,
    Gitlab,
}

impl CiPlatformKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
        }
    }
}

pub async fn run() -> Result<()> {
    let root = std::env::current_dir()?;
    let metadata = extract_ci_metadata_from_current_env()?;

    let changed_files = changed_files_from_git(&root, &metadata.base_ref, &metadata.head_ref)
        .map_err(|err| {
            anyhow::anyhow!(git_diff_error_with_guidance(
                metadata.platform,
                &err.to_string()
            ))
        })?;
    if changed_files.is_empty() {
        bail!(missing_history_guidance(metadata.platform));
    }
    let impact_files = select_impact_files(&root, &changed_files, 200)?;
    let _context = CiContext {
        platform: metadata.platform,
        base_ref: metadata.base_ref,
        head_ref: metadata.head_ref,
        changed_files,
        impact_files,
        commit_sha: metadata.commit_sha,
        pr_or_mr_number: metadata.pr_or_mr_number,
    };

    Ok(())
}
