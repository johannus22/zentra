use std::{path::Path, process::Command};

use anyhow::{anyhow, Result};

use super::CiPlatformKind;

pub fn parse_git_diff_name_only(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn candidate_git_diff_ranges(base_ref: &str, head_ref: &str) -> Vec<String> {
    let mut ranges = Vec::new();
    let base_branch = branch_name(base_ref);

    push_unique(&mut ranges, format!("origin/{base_branch}...HEAD"));
    push_unique(
        &mut ranges,
        format!("refs/remotes/origin/{base_branch}...HEAD"),
    );
    push_unique(&mut ranges, format!("origin/{base_branch}...{head_ref}"));
    push_unique(&mut ranges, format!("{base_ref}...HEAD"));
    push_unique(&mut ranges, format!("{base_ref}...{head_ref}"));

    // Defense-in-depth: never emit a range git would treat as an option (a ref
    // starting with '-'). head_ref only appears after `...` so it can't lead a
    // range, but base_ref does — guard it, mirroring git_tools::git_diff.
    ranges.retain(|r| !r.starts_with('-'));
    ranges
}

fn branch_name(ref_name: &str) -> &str {
    ref_name
        .strip_prefix("refs/heads/")
        .unwrap_or(ref_name)
        .strip_prefix("origin/")
        .unwrap_or_else(|| ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name))
}

fn push_unique(ranges: &mut Vec<String>, range: String) {
    if !ranges.contains(&range) {
        ranges.push(range);
    }
}

pub fn changed_files_from_git(root: &Path, base_ref: &str, head_ref: &str) -> Result<Vec<String>> {
    let mut last_error = None;

    for range in candidate_git_diff_ranges(base_ref, head_ref) {
        let output = Command::new("git")
            .args(["-c", "core.quotePath=false"])
            .arg("diff")
            .arg("--name-only")
            .arg(&range)
            .current_dir(root)
            .output()?;

        if output.status.success() {
            return Ok(parse_git_diff_name_only(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        last_error = Some(if stderr.is_empty() {
            anyhow!("git diff {range} failed with status {}", output.status)
        } else {
            anyhow!(stderr)
        });
    }

    Err(last_error.unwrap_or_else(|| anyhow!("git diff failed")))
}

pub fn git_diff_error_with_guidance(platform: CiPlatformKind, git_error: &str) -> String {
    let git_error = git_error.trim();
    if git_error.is_empty() {
        missing_history_guidance(platform)
    } else {
        format!("{git_error}\n{}", missing_history_guidance(platform))
    }
}

pub fn missing_history_guidance(platform: CiPlatformKind) -> String {
    match platform {
        CiPlatformKind::Github => concat!(
            "Zentra could not find the changed files. Make sure the GitHub Actions checkout ",
            "step fetches full history: set fetch-depth: 0."
        )
        .to_string(),
        CiPlatformKind::Gitlab => concat!(
            "Zentra could not find the changed files. Make sure GitLab CI fetches full history: ",
            "set GIT_DEPTH: \"0\"."
        )
        .to_string(),
    }
}
