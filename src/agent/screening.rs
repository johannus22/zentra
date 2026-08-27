//! Finding screening — the precision pass.
//!
//! Discovery is generous by design: each `ScannerType` hunts its own class of
//! issue and reports what it sees. Nothing then challenges a finding that one
//! scanner stated confidently but cannot support. The correlation pass merges
//! duplicates, which is a different job; a single-scanner finding passes through
//! it unexamined.
//!
//! This pass batches each finding with the source file it names and asks for
//! proof of reachability from untrusted input. It runs after correlation, so it
//! screens the deduplicated set and never spends tokens twice on one issue.
//!
//! **It annotates and never drops.** Same rule as `correlation`: a disputed
//! Critical that turns out to be real must still reach the human. The verdict
//! and a confidence number land on the finding; what to do about a `Disputed`
//! finding is the reader's call, not this pass's.
//!
//! **Best-effort.** On any provider error or unparseable response, the findings
//! are returned unchanged.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::provider::{AgentMessage, LLMProvider, ToolDefinition};
use crate::state::finding::Screening;
use crate::state::Finding;

/// Findings screened per provider call. Each one carries a source excerpt, so
/// the batch has to stay well inside the input budget.
const BATCH_SIZE: usize = 8;
/// Bytes of source read per finding. Enough to judge the surrounding function
/// without pulling a whole large file into the prompt.
const MAX_EXCERPT_BYTES: usize = 4_000;
/// Description characters included per finding, matching `correlation`.
const MAX_DESC_LEN: usize = 300;
/// Lines of context kept on each side of a finding's line number.
const CONTEXT_LINES: usize = 40;

/// Screen `findings` and return them with `screening` and `confidence` set.
///
/// Findings with no location are screened too: an architectural finding still
/// has a title and description to judge, it just gets no source excerpt.
pub async fn screen(
    provider: &Arc<dyn LLMProvider>,
    project_root: &std::path::Path,
    findings: Vec<Finding>,
    cancel_token: Option<&CancellationToken>,
) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    let mut verdicts: BTreeMap<usize, (Screening, Option<u8>, Option<String>)> = BTreeMap::new();
    for (batch_index, batch) in findings.chunks(BATCH_SIZE).enumerate() {
        let offset = batch_index * BATCH_SIZE;
        if let Some(batch_verdicts) = screen_batch(provider, project_root, batch, cancel_token).await {
            for (local_index, verdict) in batch_verdicts {
                if local_index < batch.len() {
                    verdicts.insert(offset + local_index, verdict);
                }
            }
        }
    }

    apply_verdicts(findings, &verdicts)
}

/// Set the verdict on each finding that the pass returned one for. Findings the
/// pass skipped or failed on keep `None`, which reads as "never screened".
fn apply_verdicts(
    findings: Vec<Finding>,
    verdicts: &BTreeMap<usize, (Screening, Option<u8>, Option<String>)>,
) -> Vec<Finding> {
    findings
        .into_iter()
        .enumerate()
        .map(|(index, mut finding)| {
            if let Some((verdict, confidence, evidence)) = verdicts.get(&index) {
                finding.screening = Some(*verdict);
                finding.confidence = confidence.map(|c| c.min(100));
                finding.evidence = evidence.clone();
            }
            finding
        })
        .collect()
}

/// Extract the evidence reason from a `report_screening` tool-call entry.
///
/// Pure and testable: takes the raw JSON entry and returns the trimmed `reason`
/// string, or `None` when the field is missing, not a string, or blank. This is
/// the only place screening reason text enters the [`Finding`], so the on-disk
/// and SARIF exposure both flow through it.
fn parse_evidence(entry: &serde_json::Value) -> Option<String> {
    let reason = entry.get("reason")?.as_str()?;
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Screen one batch. Returns `(index_within_batch, verdict)` pairs, or `None` on
/// any provider or parse failure.
async fn screen_batch(
    provider: &Arc<dyn LLMProvider>,
    project_root: &std::path::Path,
    batch: &[Finding],
    cancel_token: Option<&CancellationToken>,
) -> Option<Vec<(usize, (Screening, Option<u8>, Option<String>))>> {
    let tool = ToolDefinition {
        name: "report_screening".to_string(),
        description: "Report a reachability verdict for each finding you were given.".to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "verdicts": {
                    "type": "array",
                    "description": "One entry per finding index you can judge",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": {
                                "type": "integer",
                                "description": "The finding index from the list you were given"
                            },
                            "verdict": {
                                "type": "string",
                                "enum": ["confirmed", "disputed", "unclear"],
                                "description": "confirmed = reachable from untrusted input with no mitigation; disputed = not reachable, or a mitigation is present; unclear = not enough context to decide"
                            },
                            "confidence": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100,
                                "description": "How sure you are of this verdict"
                            },
                            "reason": {
                                "type": "string",
                                "description": "One short sentence naming the evidence"
                            }
                        },
                        "required": ["index", "verdict", "confidence"]
                    }
                }
            },
            "required": ["verdicts"]
        }),
    };

    let user = build_batch_prompt(project_root, batch);
    let messages = vec![AgentMessage::User(user)];

    let response = match provider
        .complete_with_tools(SYSTEM_PROMPT, &messages, std::slice::from_ref(&tool), 2048, cancel_token)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            crate::logging::warn(
                "scan",
                format!("finding screening skipped: LLM call failed: {e}"),
            );
            return None;
        }
    };

    let call = response
        .tool_calls
        .into_iter()
        .find(|call| call.name == "report_screening")?;
    let entries = call.arguments.get("verdicts")?.as_array()?;

    Some(
        entries
            .iter()
            .filter_map(|entry| {
                let index = entry.get("index")?.as_u64()? as usize;
                let verdict = Screening::parse(entry.get("verdict")?.as_str()?)?;
                let confidence = entry
                    .get("confidence")
                    .and_then(|c| c.as_u64())
                    .map(|c| c.min(100) as u8);
                let evidence = parse_evidence(entry);
                Some((index, (verdict, confidence, evidence)))
            })
            .collect(),
    )
}

const SYSTEM_PROMPT: &str = "You screen security findings for reachability. Assume the \
first pass over-reported: it was told to be generous, and you are the precision step.

For each finding, decide one of three verdicts:
- confirmed: untrusted input can reach the vulnerable code, and no mitigation stops it.
- disputed: the code is not reachable from untrusted input, or a mitigation already \
handles it. Test-only code, dead code, and a hardcoded value in a fixture are disputed.
- unclear: the excerpt does not contain enough to decide. Use this instead of guessing.

Judge the code you were given, not the finding's wording. A confident description is \
not evidence. Name the evidence in one short sentence.

Call report_screening once, with one entry per finding index you can judge. Leave out \
any index you cannot judge at all.";

fn build_batch_prompt(project_root: &std::path::Path, batch: &[Finding]) -> String {
    let mut out = String::from(
        "Screen each finding below. The excerpt is the source the finding points at.\n\n",
    );

    for (index, finding) in batch.iter().enumerate() {
        out.push_str(&format!(
            "## Finding {index}\nScanner: {}\nSeverity: {}\nTitle: {}\nLocation: {}\nCWE: {}\nDescription: {}\n",
            finding.scanner,
            finding.severity,
            finding.title,
            finding.location.as_deref().unwrap_or("(none)"),
            finding.cwe.as_deref().unwrap_or("(none)"),
            truncate(&finding.description, MAX_DESC_LEN),
        ));

        match source_excerpt(project_root, finding.location.as_deref()) {
            Some(excerpt) => out.push_str(&format!("Source excerpt:\n```\n{excerpt}\n```\n\n")),
            None => out.push_str(
                "Source excerpt: unavailable — judge from the description, and prefer \
'unclear' over a guess.\n\n",
            ),
        }
    }

    out
}

/// Read the lines around a finding's location. Returns `None` when there is no
/// location, the path escapes the project root, or the file cannot be read.
fn source_excerpt(project_root: &std::path::Path, location: Option<&str>) -> Option<String> {
    let location = location?;
    let (path, line) = split_location(location);

    // The location string comes from the model, so it is untrusted input to a
    // file read. Reject anything that leaves the project root.
    let relative = std::path::Path::new(&path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return None;
    }

    let full = project_root.join(relative);
    let content = std::fs::read_to_string(&full).ok()?;
    let lines: Vec<&str> = content.lines().collect();

    let window = match line {
        Some(line) => {
            let center = line.saturating_sub(1);
            let start = center.saturating_sub(CONTEXT_LINES);
            let end = (center + CONTEXT_LINES).min(lines.len());
            lines.get(start..end)?
        }
        None => lines.get(0..lines.len().min(CONTEXT_LINES * 2))?,
    };

    let mut excerpt = window.join("\n");
    if excerpt.len() > MAX_EXCERPT_BYTES {
        let boundary = excerpt
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= MAX_EXCERPT_BYTES)
            .last()
            .unwrap_or(0);
        excerpt.truncate(boundary);
        excerpt.push_str("\n… (excerpt truncated)");
    }
    Some(excerpt)
}

/// Split `src/db.rs:42` into its path and line. Splits from the right so a
/// Windows drive letter keeps its own colon, matching `reconcile::file_of`.
fn split_location(location: &str) -> (String, Option<usize>) {
    let trimmed = location.trim();
    if let Some((head, tail)) = trimmed.rsplit_once(':') {
        if let Ok(line) = tail.trim().parse::<usize>() {
            return (head.replace('\\', "/"), Some(line));
        }
    }
    (trimmed.replace('\\', "/"), None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Severity;
    use tempfile::TempDir;

    fn finding(title: &str, location: Option<&str>) -> Finding {
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: title.to_string(),
            description: "d".to_string(),
            location: location.map(str::to_string),
            recommendation: "r".to_string(),
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
    fn split_location_reads_the_line_number() {
        assert_eq!(
            split_location("src/db.rs:42"),
            ("src/db.rs".to_string(), Some(42))
        );
        assert_eq!(
            split_location("src/db.rs"),
            ("src/db.rs".to_string(), None)
        );
    }

    #[test]
    fn split_location_keeps_a_windows_drive_colon() {
        let (path, line) = split_location("C:\\repo\\src\\db.rs:10");
        assert_eq!(path, "C:/repo/src/db.rs");
        assert_eq!(line, Some(10));
    }

    #[test]
    fn source_excerpt_reads_around_the_line() {
        let dir = TempDir::new().unwrap();
        let body: String = (1..=200).map(|i| format!("line{i}\n")).collect();
        std::fs::write(dir.path().join("big.rs"), body).unwrap();

        let excerpt = source_excerpt(dir.path(), Some("big.rs:100")).unwrap();
        assert!(excerpt.contains("line100"), "got: {excerpt}");
        assert!(!excerpt.contains("line1\n"), "window is centered: {excerpt}");
    }

    #[test]
    fn source_excerpt_rejects_a_path_escaping_the_root() {
        let dir = TempDir::new().unwrap();
        assert_eq!(source_excerpt(dir.path(), Some("../../etc/passwd:1")), None);
        let absolute = if cfg!(windows) {
            "C:\\Windows\\win.ini:1"
        } else {
            "/etc/passwd:1"
        };
        assert_eq!(source_excerpt(dir.path(), Some(absolute)), None);
    }

    #[test]
    fn source_excerpt_is_none_without_a_location() {
        let dir = TempDir::new().unwrap();
        assert_eq!(source_excerpt(dir.path(), None), None);
    }

    #[test]
    fn source_excerpt_is_none_for_a_missing_file() {
        let dir = TempDir::new().unwrap();
        assert_eq!(source_excerpt(dir.path(), Some("gone.rs:1")), None);
    }

    #[test]
    fn source_excerpt_is_capped() {
        let dir = TempDir::new().unwrap();
        let body: String = (1..=200).map(|_| "x".repeat(400) + "\n").collect();
        std::fs::write(dir.path().join("wide.rs"), body).unwrap();

        let excerpt = source_excerpt(dir.path(), Some("wide.rs:100")).unwrap();
        assert!(
            excerpt.len() <= MAX_EXCERPT_BYTES + 32,
            "excerpt must stay bounded, got {} bytes",
            excerpt.len()
        );
        assert!(excerpt.contains("truncated"), "got: {excerpt}");
    }

    #[test]
    fn batch_prompt_names_every_finding_and_flags_a_missing_excerpt() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
        let batch = vec![
            finding("Has source", Some("a.rs:1")),
            finding("No location", None),
        ];

        let prompt = build_batch_prompt(dir.path(), &batch);

        assert!(prompt.contains("## Finding 0"), "got: {prompt}");
        assert!(prompt.contains("## Finding 1"), "got: {prompt}");
        assert!(prompt.contains("fn a() {}"), "got: {prompt}");
        assert!(prompt.contains("unavailable"), "got: {prompt}");
    }

    #[test]
    fn apply_verdicts_sets_only_the_findings_it_judged() {
        let findings = vec![finding("A", Some("a.rs:1")), finding("B", Some("b.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(0, (Screening::Confirmed, Some(90), Some("reachable".into())));

        let out = apply_verdicts(findings, &verdicts);

        assert_eq!(out[0].screening, Some(Screening::Confirmed));
        assert_eq!(out[0].confidence, Some(90));
        assert_eq!(out[0].evidence.as_deref(), Some("reachable"));
        assert_eq!(out[1].screening, None, "unjudged findings stay unscreened");
        assert_eq!(out[1].confidence, None);
        assert_eq!(out[1].evidence, None);
    }

    #[test]
    fn apply_verdicts_captures_evidence() {
        let findings = vec![finding("A", Some("a.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(0, (Screening::Disputed, Some(95), Some("dead code".into())));

        let out = apply_verdicts(findings, &verdicts);
        assert_eq!(out[0].screening, Some(Screening::Disputed));
        assert_eq!(out[0].evidence.as_deref(), Some("dead code"));
    }

    #[test]
    fn apply_verdicts_keeps_evidence_none_when_absent() {
        let findings = vec![finding("A", Some("a.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(0, (Screening::Confirmed, Some(90), None));

        let out = apply_verdicts(findings, &verdicts);
        assert_eq!(out[0].screening, Some(Screening::Confirmed));
        assert!(out[0].evidence.is_none());
    }

    #[test]
    fn parse_evidence_reads_the_reason_field() {
        let entry = serde_json::json!({
            "index": 0,
            "verdict": "confirmed",
            "confidence": 90,
            "reason": "  reachable from the HTTP handler  "
        });
        assert_eq!(parse_evidence(&entry).as_deref(), Some("reachable from the HTTP handler"));
    }

    #[test]
    fn parse_evidence_is_none_when_reason_missing_or_blank() {
        assert_eq!(parse_evidence(&serde_json::json!({"index": 0})), None);
        assert_eq!(
            parse_evidence(&serde_json::json!({"index": 0, "reason": "   "})),
            None
        );
        assert_eq!(
            parse_evidence(&serde_json::json!({"index": 0, "reason": 42})),
            None
        );
    }

    #[test]
    fn apply_verdicts_never_drops_a_finding() {
        let findings = vec![finding("A", Some("a.rs:1")), finding("B", Some("b.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(0, (Screening::Disputed, Some(95), None));
        verdicts.insert(1, (Screening::Disputed, Some(99), None));

        let out = apply_verdicts(findings, &verdicts);

        assert_eq!(out.len(), 2, "a disputed finding is annotated, not removed");
        assert_eq!(out[0].screening, Some(Screening::Disputed));
        assert_eq!(out[1].screening, Some(Screening::Disputed));
    }

    #[test]
    fn apply_verdicts_clamps_confidence() {
        let findings = vec![finding("A", Some("a.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(0, (Screening::Confirmed, Some(200), None));

        let out = apply_verdicts(findings, &verdicts);
        assert_eq!(out[0].confidence, Some(100));
    }

    #[test]
    fn apply_verdicts_ignores_an_out_of_range_index() {
        let findings = vec![finding("A", Some("a.rs:1"))];
        let mut verdicts = BTreeMap::new();
        verdicts.insert(99, (Screening::Confirmed, Some(90), None));

        let out = apply_verdicts(findings, &verdicts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].screening, None);
    }
}
