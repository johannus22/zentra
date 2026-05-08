use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::agent::{ScanEvent, ScannerType};
use crate::state::{Finding, Severity, StateWriter};

use super::{
    allowlist::Allowlist,
    cache::ScanCache,
    entropy,
    git_history,
    patterns,
    report,
    validator::ContextValidator,
    HistoryDepth, SecretsMatch,
};

const _: fn() = || {
    fn _assert_sync<T: Sync>() {}
    _assert_sync::<ContextValidator<'static>>();
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

        // ── Incremental cache ────────────────────────────────────────────────
        let mut cache = ScanCache::load(&self.root);
        let phash = patterns_hash(detector_patterns);
        cache.invalidate_if_hash_mismatch(&phash);

        let mut all_matches = Vec::new();

        // ── Filesystem scan ──────────────────────────────────────────────────
        let fs_matches = scan_filesystem(&self.root, detector_patterns, &validator, &self.tx, &mut cache);
        all_matches.extend(fs_matches);

        // ── Git history scan ─────────────────────────────────────────────────
        let head = git_head(&self.root);
        let git_matches = if head.as_deref().map(|h| cache.git_head_matches(h)).unwrap_or(false) {
            cache.get_git_findings().to_vec()
        } else {
            let matches = git_history::scan_history(
                &self.root,
                &self.depth,
                detector_patterns,
                &validator,
            )
            .await
            .unwrap_or_default();
            if let Some(h) = &head {
                cache.set_git(h.clone(), matches.clone());
            }
            matches
        };
        all_matches.extend(git_matches);

        // ── Save cache ───────────────────────────────────────────────────────
        cache.save(&self.root);

        all_matches.sort_by(|a, b| {
            (&a.file, a.line, &a.detector, a.suppressed)
                .cmp(&(&b.file, b.line, &b.detector, b.suppressed))
        });
        all_matches.dedup_by(|a, b| {
            a.file == b.file && a.line == b.line && a.detector == b.detector
        });

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

// ── Directory/file exclusion lists ──────────────────────────────────────────

const EXCLUDED_DIRS: &[&str] = &[
    "node_modules", "target", "dist", "build", ".git",
    "vendor", "__pycache__", ".pytest_cache", ".next", ".nuxt",
    ".svelte-kit", ".zentra", "coverage", ".nyc_output",
    "bower_components",
];

const EXCLUDED_NAMES: &[&str] = &[
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", "poetry.lock",
];

const EXCLUDED_EXTENSIONS: &[&str] = &[
    ".min.js", ".min.css", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
];

fn is_excluded_entry(entry: &ignore::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
        return EXCLUDED_DIRS.contains(&name.as_ref())
            || name.ends_with(".egg-info");
    }
    if EXCLUDED_NAMES.contains(&name.as_ref()) {
        return true;
    }
    EXCLUDED_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

// ── Filesystem scan (collect → parallel scan) ───────────────────────────────

fn scan_filesystem(
    root: &Path,
    detector_patterns: &'static [patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
    tx: &mpsc::Sender<ScanEvent>,
    cache: &mut ScanCache,
) -> Vec<SecretsMatch> {
    // Phase 1: collect all eligible file entries sequentially
    let entries: Vec<_> = WalkBuilder::new(root)
        .standard_filters(true)
        .follow_links(false)
        .filter_entry(|e| !is_excluded_entry(e))
        .build()
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() <= 1_048_576).unwrap_or(false))
        .collect();

    let total = entries.len();
    let _ = tx.try_send(ScanEvent::ToolCall {
        scanner: ScannerType::SecretsScan,
        tool: "scan_files".to_string(),
        arg: format!("{} files to scan", total),
    });

    // Phase 2: check mtime cache — split into hits (cached) and misses (need scanning)
    let mut cached_results: Vec<SecretsMatch> = Vec::new();
    let mut to_scan: Vec<(PathBuf, String, std::time::SystemTime)> = Vec::new();

    for entry in entries {
        let rel = match entry.path().strip_prefix(root) {
            Ok(p) => p.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };

        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                if let Some(hits) = cache.get_file(&rel, mtime) {
                    cached_results.extend(hits);
                    continue;
                }
                to_scan.push((entry.path().to_path_buf(), rel, mtime));
                continue;
            }
        }
        to_scan.push((entry.path().to_path_buf(), rel, std::time::SystemTime::UNIX_EPOCH));
    }

    let missed_count = to_scan.len();
    if missed_count > 0 {
        let _ = tx.try_send(ScanEvent::ToolCall {
            scanner: ScannerType::SecretsScan,
            tool: "scan_files".to_string(),
            arg: format!("{} files not cached, scanning", missed_count),
        });
    }

    // Phase 3: scan cache-miss files in parallel with rayon
    let scanned: Vec<(String, std::time::SystemTime, Vec<SecretsMatch>)> = to_scan
        .par_iter()
        .map(|(path, rel, mtime)| {
            let findings = scan_file(path, rel, detector_patterns, validator, tx);
            (rel.clone(), *mtime, findings)
        })
        .collect();

    // Phase 4: update cache and collect results
    for (rel, mtime, findings) in scanned {
        cache.set_file(rel, mtime, findings.clone());
        cached_results.extend(findings);
    }

    cached_results
}

fn scan_file(
    path: &Path,
    rel: &str,
    detector_patterns: &[patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
    tx: &mpsc::Sender<ScanEvent>,
) -> Vec<SecretsMatch> {
    let mut results = Vec::new();

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return results,
    };

    // Binary detection: read first 8 KiB, check for null bytes
    let mut buf = [0u8; 8192];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return results,
    };
    if buf[..n].contains(&0) {
        return results;
    }

    let mut content = String::from_utf8_lossy(&buf[..n]).into_owned();
    let mut rest = Vec::new();
    if file.read_to_end(&mut rest).is_ok() {
        content.push_str(&String::from_utf8_lossy(&rest));
    }

    let content_lines: Vec<&str> = content.lines().collect();

    for (i, line) in content_lines.iter().enumerate() {
        // Length guard: no pattern can match less than 16 chars
        if line.len() < 16 {
            continue;
        }

        let line_no = (i + 1) as u32;
        let prev_line = if i > 0 { Some(content_lines[i - 1]) } else { None };

        let pattern_hits = patterns::scan_line(line, detector_patterns);

        for hit in &pattern_hits {
            let m = SecretsMatch {
                file: rel.to_string(),
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
                file: rel.to_string(),
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

    let _ = tx.try_send(ScanEvent::ToolCall {
        scanner: ScannerType::SecretsScan,
        tool: "scan_file".to_string(),
        arg: rel.to_string(),
    });

    results
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

// ── Helpers ──────────────────────────────────────────────────────────────────

fn git_head(root: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["-C", root.to_str()?, "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn patterns_hash(patterns: &[patterns::DetectorPattern]) -> String {
    let mut hasher = Sha256::new();
    for p in patterns {
        hasher.update(p.name.as_bytes());
        hasher.update(p.re.as_str().as_bytes());
        hasher.update(p.secret_group.to_ne_bytes());
    }
    format!("{:x}", hasher.finalize())
}
