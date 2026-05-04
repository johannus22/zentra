use anyhow::Result;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::{
    entropy,
    patterns::{self, DetectorPattern},
    validator::ContextValidator,
    HistoryDepth, SecretsMatch,
};

fn push_match(
    results: &mut Vec<SecretsMatch>,
    m: SecretsMatch,
    validator: &ContextValidator<'_>,
    line: &str,
    prev_line: Option<&str>,
) {
    let suppressed = validator.check(&m, line, prev_line);
    let mut m = m;
    if let Some(reason) = suppressed {
        m.suppressed = true;
        m.suppression_reason = Some(reason);
    }
    results.push(m);
}

pub async fn scan_history(
    root: &Path,
    depth: &HistoryDepth,
    detector_patterns: &[DetectorPattern],
    validator: &ContextValidator<'_>,
) -> Result<Vec<SecretsMatch>> {
    if matches!(depth, HistoryDepth::Last(0)) {
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root).arg("log").arg("-p").arg("--no-merges");

    if let Some(arg) = depth.max_count_arg() {
        cmd.arg(arg);
    }

    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let stdout = child.stdout.take().expect("stdout was piped");
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    let mut current_commit: Option<String> = None;
    let mut current_file: Option<String> = None;
    let mut line_no: u32 = 0;
    let mut prev_content_line: Option<String> = None;
    let mut results: Vec<SecretsMatch> = Vec::new();

    while let Ok(Some(raw)) = lines.next_line().await {
        if raw.starts_with("commit ") {
            current_commit = raw.split_whitespace().nth(1).map(|s| s.to_string());
            current_file = None;
            line_no = 0;
            prev_content_line = None;
            continue;
        }

        if raw.starts_with("+++ b/") {
            current_file = Some(raw[6..].to_string());
            line_no = 0;
            prev_content_line = None;
            continue;
        }

        if raw.starts_with("+++ /dev/null") {
            current_file = None;
            continue;
        }

        if raw.starts_with("@@ ") {
            if let Some(plus_part) = raw.split('+').nth(1) {
                let num: u32 = plus_part
                    .split(|c| c == ',' || c == ' ')
                    .next()
                    .and_then(|s: &str| s.parse().ok())
                    .unwrap_or(1);
                line_no = num.saturating_sub(1);
            }
            prev_content_line = None;
            continue;
        }

        if current_file.is_none() {
            continue;
        }

        if raw.starts_with(' ') {
            prev_content_line = Some(raw[1..].to_string());
            line_no += 1;
            continue;
        }

        if raw.starts_with('-') && !raw.starts_with("---") {
            continue;
        }

        if raw.starts_with('+') && !raw.starts_with("+++") {
            line_no += 1;
            let line = &raw[1..];
            let file = current_file.as_deref().unwrap_or("");
            let prev = prev_content_line.as_deref();

            let pattern_hits = patterns::scan_line(line, detector_patterns);
            for hit in &pattern_hits {
                let m = SecretsMatch {
                    file: file.to_string(),
                    line: line_no,
                    commit: current_commit.clone(),
                    detector: hit.detector.clone(),
                    entropy: Some(entropy::score(&hit.secret)),
                    redacted: hit.redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                push_match(&mut results, m, validator, line, prev);
            }

            for hit in entropy::scan_line_for_high_entropy(line) {
                if pattern_hits
                    .iter()
                    .any(|s| s.secret.contains(&hit.token) || hit.token.contains(&s.secret))
                {
                    continue;
                }
                let m = SecretsMatch {
                    file: file.to_string(),
                    line: line_no,
                    commit: current_commit.clone(),
                    detector: hit.detector.clone(),
                    entropy: Some(hit.entropy),
                    redacted: patterns::redact(&hit.token),
                    suppressed: false,
                    suppression_reason: None,
                };
                push_match(&mut results, m, validator, line, prev);
            }

            prev_content_line = Some(line.to_string());
        }
    }

    child.wait().await.ok();
    Ok(results)
}
