use anyhow::Result;
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::agent::{ScanEvent, ScannerType};
use crate::state::{Finding, Severity, StateWriter};

use super::{
    allowlist::Allowlist,
    entropy,
    git_history,
    patterns,
    report,
    validator::ContextValidator,
    HistoryDepth, SecretsMatch,
};

pub struct SecretScanner {
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
}

impl SecretScanner {
    pub fn new(root: PathBuf, depth: HistoryDepth, tx: mpsc::Sender<ScanEvent>) -> Self {
        Self { root, depth, tx }
    }

    pub async fn run(self, state_writer: &StateWriter) -> Result<Vec<SecretsMatch>> {
        self.tx.send(ScanEvent::ScannerStarted(ScannerType::SecretsScan)).await.ok();

        let detector_patterns = patterns::all_patterns();
        let allowlist = Allowlist::load(&self.root);
        let validator = ContextValidator::new(&allowlist);

        let mut all_matches = Vec::new();

        let fs_matches = scan_filesystem(&self.root, detector_patterns, &validator, &self.tx);
        all_matches.extend(fs_matches);

        let git_matches =
            git_history::scan_history(&self.root, &self.depth, detector_patterns, &validator)
                .await
                .unwrap_or_default();
        all_matches.extend(git_matches);

        all_matches.sort_by(|a, b| {
            (&a.file, a.line, &a.detector)
                .cmp(&(&b.file, b.line, &b.detector))
        });
        all_matches.dedup_by(|a, b| {
            a.file == b.file && a.line == b.line && a.detector == b.detector
        });

        // Non-fatal: findings are still returned to the orchestrator even if file write fails
        report::write(&self.root, &all_matches).unwrap_or_else(|e| {
            eprintln!("secrets report write error: {}", e);
        });

        for m in all_matches.iter().filter(|m| !m.suppressed) {
            let commit_note = m
                .commit
                .as_deref()
                .map(|c| format!(" (commit {})", &c[..7.min(c.len())]))
                .unwrap_or_default();

            let finding = Finding {
                scanner: ScannerType::SecretsScan.name().to_string(),
                severity: Severity::High,
                title: format!("Potential secret: {}", m.detector),
                description: format!(
                    "Detected {} at {}:{}{}. Redacted value: {}",
                    m.detector, m.file, m.line, commit_note, m.redacted
                ),
                location: Some(format!("{}:{}", m.file, m.line)),
                recommendation: "Remove the secret, rotate it immediately, and replace with an environment variable or secrets manager reference.".to_string(),
            };
            state_writer.write_finding(&finding).ok();
            self.tx.send(ScanEvent::FindingAdded(finding)).await.ok();
        }

        self.tx.send(ScanEvent::ScannerCompleted(ScannerType::SecretsScan)).await.ok();
        Ok(all_matches)
    }
}

fn push_match_fs(
    results: &mut Vec<SecretsMatch>,
    m: SecretsMatch,
    validator: &ContextValidator<'_>,
    line: &str,
    prev_line: Option<&str>,
) {
    let suppression = validator.check(&m, line, prev_line);
    let mut m = m;
    if let Some(reason) = suppression {
        m.suppressed = true;
        m.suppression_reason = Some(reason);
    }
    results.push(m);
}

fn scan_filesystem(
    root: &Path,
    detector_patterns: &[patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
    tx: &mpsc::Sender<ScanEvent>,
) -> Vec<SecretsMatch> {
    let mut results = Vec::new();

    let mut override_builder = OverrideBuilder::new(root);
    for pat in &[
        "node_modules", "target", "dist", "build", ".git",
        "vendor", "__pycache__", ".pytest_cache", "*.egg-info",
        ".next", ".nuxt", ".svelte-kit", ".zentra",
    ] {
        let _ = override_builder.add(&format!("!{}/", pat));
    }

    let walker = WalkBuilder::new(root)
        .standard_filters(true)
        .overrides(override_builder.build().unwrap_or_else(|_| ignore::overrides::Override::empty()))
        .hidden(false)
        .follow_links(false)
        .build();

    let mut file_count: usize = 0;
    for entry in walker.flatten()
    {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();

        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();

        if let Ok(meta) = entry.metadata() {
            if meta.len() > 1_048_576 {
                continue; // skip files > 1MB
            }
        }

        file_count += 1;
        if file_count % 100 == 0 {
            let _ = tx.try_send(ScanEvent::ToolCall {
                scanner: ScannerType::SecretsScan,
                tool: "scan_files".to_string(),
                arg: format!("{} files checked", file_count),
            });
        }

        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut buf = [0u8; 8192];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if buf[..n].contains(&0) {
            continue; // binary file
        }
        let mut content = String::from_utf8_lossy(&buf[..n]).into_owned();
        let mut remainder = String::new();
        if file.read_to_string(&mut remainder).is_ok() {
            content.push_str(&remainder);
        }

        let content_lines: Vec<&str> = content.lines().collect();

        for (i, line) in content_lines.iter().enumerate() {
            let line_no = (i + 1) as u32;
            let prev_line = if i > 0 { Some(content_lines[i - 1]) } else { None };

            let pattern_hits = patterns::scan_line(line, detector_patterns);

            for hit in &pattern_hits {
                let m = SecretsMatch {
                    file: rel.clone(),
                    line: line_no,
                    commit: None,
                    detector: hit.detector.clone(),
                    entropy: Some(entropy::score(&hit.secret)),
                    redacted: hit.redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                push_match_fs(&mut results, m, validator, line, prev_line);
            }

            for hit in entropy::scan_line_for_high_entropy(line) {
                if pattern_hits.iter().any(|s| s.secret.contains(&hit.token) || hit.token.contains(&s.secret)) {
                    continue;
                }
                let m = SecretsMatch {
                    file: rel.clone(),
                    line: line_no,
                    commit: None,
                    detector: hit.detector.clone(),
                    entropy: Some(hit.entropy),
                    redacted: patterns::redact(&hit.token),
                    suppressed: false,
                    suppression_reason: None,
                };
                push_match_fs(&mut results, m, validator, line, prev_line);
            }
        }
    }

    results
}
