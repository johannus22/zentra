use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use super::CiContext;
use crate::state::{Finding, Severity};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CiArtifactPaths {
    pub markdown: PathBuf,
    pub json: PathBuf,
    pub sarif: PathBuf,
    pub html: PathBuf,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Serialize)]
struct CiJsonReport<'a> {
    context: CiJsonContext<'a>,
    fail_threshold: String,
    summary: SeverityCounts,
    findings: &'a [Finding],
}

#[derive(Serialize)]
struct CiJsonContext<'a> {
    platform: &'static str,
    scope: String,
    base_ref: &'a str,
    head_ref: &'a str,
    changed_files_count: usize,
    impact_files_count: usize,
    changed_files: &'a [String],
    impact_files: &'a [String],
    commit_sha: Option<&'a str>,
    pr_or_mr_number: Option<&'a str>,
}

pub fn write_ci_artifacts(
    project_root: &Path,
    context: &CiContext,
    findings: &[Finding],
    fail_threshold: Severity,
    triage_note: Option<&str>,
) -> Result<CiArtifactPaths> {
    let output_dir = project_root.join(".zentra");
    fs::create_dir_all(&output_dir)?;

    let markdown = output_dir.join("ci-report.md");
    let json = output_dir.join("ci-report.json");
    let sarif = output_dir.join("ci-report.sarif");
    let html = output_dir.join("ci-report.html");

    fs::write(
        &markdown,
        render_markdown_report(context, findings, fail_threshold, triage_note),
    )?;
    fs::write(
        &json,
        serde_json::to_string_pretty(&CiJsonReport {
            context: json_context(context),
            fail_threshold: fail_threshold.to_string(),
            summary: severity_counts(findings),
            findings,
        })?,
    )?;
    fs::write(&sarif, crate::state::sarif::render_sarif(findings))?;
    fs::write(&html, render_html_report(context, findings, fail_threshold))?;

    Ok(CiArtifactPaths {
        markdown,
        json,
        sarif,
        html,
    })
}

fn render_html_report(
    context: &CiContext,
    findings: &[Finding],
    fail_threshold: Severity,
) -> String {
    let title = "Zentra CI Security Report";
    let meta = [
        ("Platform", context.platform.as_str()),
        (
            "Scope",
            &format!(
                "PR/MR {}",
                context.pr_or_mr_number.as_deref().unwrap_or("unknown")
            ),
        ),
        ("Base ref", &context.base_ref),
        ("Head ref", &context.head_ref),
        ("Changed files", &context.changed_files.len().to_string()),
        ("Impact files", &context.impact_files.len().to_string()),
        ("Fail threshold", &fail_threshold.to_string()),
    ];
    crate::state::html::render_report_html(findings, title, &meta)
}

pub fn severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

fn render_markdown_report(
    context: &CiContext,
    findings: &[Finding],
    fail_threshold: Severity,
    triage_note: Option<&str>,
) -> String {
    let counts = severity_counts(findings);
    let triage_line = triage_note
        .filter(|note| !note.trim().is_empty())
        .map(|note| format!("\nTriage ticket: {note}"))
        .unwrap_or_default();
    let mut report = format!(
        "# Zentra CI Security Report\n\n## CI Summary\n\nPlatform: {}\nScope: PR/MR {}\nBase: {}\nHead: {}\nChanged files: {}\nImpact files: {}\nFail threshold: {}\n\n## Severity Summary\n\nCritical: {}\nHigh: {}\nMedium: {}\nLow: {}\nInfo: {}\n\n## Findings\n\n",
        context.platform.as_str(),
        context.pr_or_mr_number.as_deref().unwrap_or("unknown"),
        context.base_ref,
        context.head_ref,
        context.changed_files.len(),
        context.impact_files.len(),
        fail_threshold,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info,
    );

    if !triage_line.is_empty() {
        // The triage line documents the ticket outcome (or its absence). It is
        // injected into the CI Summary so operators see it next to the policy.
        report = report.replacen(
            "## Severity Summary",
            &format!("{triage_line}\n\n## Severity Summary"),
            1,
        );
    }

    if findings.is_empty() {
        report.push_str("No findings.\n");
        return report;
    }

    for finding in findings {
        report.push_str(&format!(
            "### [{}] {}\n\nScanner: {}\nLocation: {}\n\n{}\n\nRecommendation: {}\n\n",
            finding.severity,
            finding.title,
            finding.scanner,
            finding.location.as_deref().unwrap_or("N/A"),
            finding.description,
            finding.recommendation,
        ));
    }

    report
}

fn json_context(context: &CiContext) -> CiJsonContext<'_> {
    CiJsonContext {
        platform: context.platform.as_str(),
        scope: format!(
            "PR/MR {}",
            context.pr_or_mr_number.as_deref().unwrap_or("unknown")
        ),
        base_ref: &context.base_ref,
        head_ref: &context.head_ref,
        changed_files_count: context.changed_files.len(),
        impact_files_count: context.impact_files.len(),
        changed_files: &context.changed_files,
        impact_files: &context.impact_files,
        commit_sha: context.commit_sha.as_deref(),
        pr_or_mr_number: context.pr_or_mr_number.as_deref(),
    }
}
