pub mod cvss;
pub mod finding;
pub mod html;
pub mod sarif;
pub use finding::{Finding, Severity};

use anyhow::Result;
use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct StateWriter {
    zentra_dir: PathBuf,
    cwe_template: String,
    /// Serializes the findings-file read-modify-write. Phase 2 runs the SAST,
    /// SupplyChain, ApiScan and IaCScan scanners on separate runtime threads,
    /// all sharing one `Arc<StateWriter>`. `write_finding` (append, read whole,
    /// sort, rewrite) and `rewrite_findings` are non-atomic, so without this
    /// lock concurrent calls lose updates — silently dropping findings, up to
    /// and including a Critical, while the scan still reports success.
    findings_lock: std::sync::Mutex<()>,
}

impl StateWriter {
    pub fn new(project_root: &Path) -> Result<Self> {
        Self::open(project_root, false)
    }

    /// `preserve_findings = true` keeps an existing detailed-findings.md (used by
    /// incremental scans, which reconcile against the prior set). `false`
    /// truncates it (full scan — the historical default).
    pub fn open(project_root: &Path, preserve_findings: bool) -> Result<Self> {
        let zentra_dir = project_root.join(".zentra");
        fs::create_dir_all(&zentra_dir)?;
        fs::create_dir_all(zentra_dir.join("reports"))?;
        let findings_path = zentra_dir.join("detailed-findings.md");
        if !preserve_findings && findings_path.exists() {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&findings_path)?;
        }
        let cwe_template = crate::config::GlobalConfig::load()
            .ok()
            .and_then(|c| c.cwe_url_template)
            .unwrap_or_else(|| crate::config::DEFAULT_CWE_URL_TEMPLATE.to_string());
        Ok(Self {
            zentra_dir,
            cwe_template,
            findings_lock: std::sync::Mutex::new(()),
        })
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<()> {
        // Hold the lock across append + sort so a concurrent scanner can't read a
        // half-written file and rewrite over our block (lost update). Poison-
        // tolerant: the critical section leaves no broken in-memory invariant, so
        // recover the guard rather than cascading a panic to every other scanner.
        let _guard = self
            .findings_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = self.zentra_dir.join("detailed-findings.md");
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        write!(
            file,
            "{}",
            format_finding_block(finding, &self.cwe_template)
        )?;
        self.sort_findings_file()?;
        Ok(())
    }

    pub fn write_report(&self, content: &str) -> Result<()> {
        let date = Local::now().format("%Y%m%d").to_string();
        let path = self
            .zentra_dir
            .join("reports")
            .join(format!("{}-report.md", date));
        fs::write(path, content)?;
        Ok(())
    }

    /// Write a SARIF 2.1.0 report to `.zentra/reports/findings.sarif`. The
    /// output is deterministic. Return the path of the written file.
    pub fn write_sarif(&self, findings: &[Finding]) -> Result<PathBuf> {
        let path = self.zentra_dir.join("reports").join("findings.sarif");
        fs::write(&path, crate::state::sarif::render_sarif(findings))?;
        Ok(path)
    }

    /// Replace the entire findings file with the given set, then re-sort by
    /// severity. Used by the correlation pass to write back the deduped findings.
    pub fn rewrite_findings(&self, findings: &[Finding]) -> Result<()> {
        let _guard = self
            .findings_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = self.zentra_dir.join("detailed-findings.md");
        let body: String = findings
            .iter()
            .map(|f| format_finding_block(f, &self.cwe_template))
            .collect();
        std::fs::write(&path, body)?;
        self.sort_findings_file()?;
        Ok(())
    }

    pub fn read_findings_raw(&self) -> Result<String> {
        let path = self.zentra_dir.join("detailed-findings.md");
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn sort_findings_file(&self) -> Result<()> {
        let path = self.zentra_dir.join("detailed-findings.md");
        let raw = std::fs::read_to_string(&path)?;
        let mut blocks: Vec<String> = raw
            .split("\n\n---\n")
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .map(|b| b.to_string())
            .collect();

        blocks.sort_by_key(|block| finding_block_sort_key(block));

        let sorted = if blocks.is_empty() {
            String::new()
        } else {
            format!("{}\n\n---\n", blocks.join("\n\n---\n"))
        };

        std::fs::write(path, sorted)?;
        Ok(())
    }

    /// Write the coverage ledger for this run. Overwrites any prior file: a
    /// stale ledger is worse than none, because it would name files as unread
    /// that this run did read.
    pub fn write_coverage(&self, content: &str) -> Result<()> {
        fs::write(self.zentra_dir.join("coverage.md"), content)?;
        Ok(())
    }

    pub fn write_architecture(&self, content: &str) -> Result<()> {
        fs::write(self.zentra_dir.join("architecture.md"), content)?;
        Ok(())
    }

    pub fn read_architecture(&self) -> String {
        std::fs::read_to_string(self.zentra_dir.join("architecture.md")).unwrap_or_default()
    }

    pub fn architecture_exists(&self) -> bool {
        let p = self.zentra_dir.join("architecture.md");
        p.exists() && std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false)
    }

    pub fn project_root(&self) -> &std::path::Path {
        self.zentra_dir
            .parent()
            .expect("zentra_dir always has a parent")
    }
}

/// Neutralize a value before it is written into the line-oriented findings
/// markdown. Finding fields are dominated by untrusted scanned content (the LLM
/// quotes the vulnerable file into title/description/etc.). The on-disk format
/// separates findings with `\n\n---\n` and parses fields by line prefix, so any
/// embedded newline would let scanned content split the block, forge a new
/// `## [SEV]` finding, or overwrite a sibling `**Field:**`. Collapsing every line
/// break to a space keeps each field on the single line the parser expects.
fn sanitize_field(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

fn format_finding_block(finding: &Finding, cwe_template: &str) -> String {
    let location_line = finding
        .location
        .as_deref()
        .map(|l| format!("**Location:** {}\n", sanitize_field(l)))
        .unwrap_or_default();

    // Emitted only when present, so singleton findings produce identical output.
    let corroborated_line = if finding.corroborated_by.is_empty() {
        String::new()
    } else {
        format!(
            "**Corroborated by:** {}\n",
            sanitize_field(&finding.corroborated_by.join(", "))
        )
    };

    let cwe_line = finding
        .cwe
        .as_deref()
        .map(|id| {
            let id = sanitize_field(id);
            format!(
                "**CWE:** [{}]({})\n",
                id,
                crate::config::cwe_link(&id, cwe_template)
            )
        })
        .unwrap_or_default();

    let secondary_line = if finding.secondary_cwe.is_empty() {
        String::new()
    } else {
        format!(
            "**Secondary CWE:** {}\n",
            sanitize_field(&finding.secondary_cwe.join(", "))
        )
    };

    // CVSS line only when a score was computed (vector parsed).
    let cvss_line = match (finding.cvss_score, finding.cvss_vector.as_deref()) {
        (Some(score), Some(vector)) => format!(
            "**CVSS:** {:.1} {} ({})\n",
            score,
            crate::state::cvss::rating(score),
            vector
        ),
        _ => String::new(),
    };

    let owasp_line = finding
        .owasp
        .as_deref()
        .map(|o| format!("**OWASP:** {}\n", sanitize_field(o)))
        .unwrap_or_default();

    // Emitted only once the audit pass has run, so an unscreened finding keeps
    // byte-identical output to before this field existed.
    let screening_line = match (finding.screening, finding.confidence) {
        (Some(verdict), Some(confidence)) => {
            format!("**Screening:** {verdict} ({confidence}% confidence)\n")
        }
        (Some(verdict), None) => format!("**Screening:** {verdict}\n"),
        (None, _) => String::new(),
    };

    // The screening evidence is the pass's one-sentence reason, captured from
    // the `report_screening` tool call. Emitted only when present so an
    // unscreened or reason-less finding keeps byte-identical output.
    let evidence_line = finding
        .evidence
        .as_deref()
        .map(|e| format!("**Evidence:** {}\n", sanitize_field(e)))
        .unwrap_or_default();

    format!(
        "## [{}] {}\n**Scanner:** {}\n{}{}{}{}{}{}{}{}**Description:** {}\n**Recommendation:** {}\n\n---\n",
        finding.severity,
        sanitize_field(&finding.title),
        sanitize_field(&finding.scanner),
        screening_line,
        evidence_line,
        corroborated_line,
        cwe_line,
        secondary_line,
        cvss_line,
        owasp_line,
        location_line,
        sanitize_field(&finding.description),
        sanitize_field(&finding.recommendation),
    )
}

/// Parse the markdown produced by [`format_finding_block`] back into findings.
/// Inverse of `format_finding_block`; kept beside it so the on-disk format has a
/// single owner. Blocks missing required fields are skipped; a missing
/// `**Corroborated by:**` line (legacy files) yields an empty `corroborated_by`.
pub fn parse_findings(raw: &str) -> Vec<Finding> {
    raw.split("\n\n---\n")
        .map(str::trim)
        .filter(|block| block.contains("## ["))
        .filter_map(parse_finding_block)
        .collect()
}

fn parse_finding_block(block: &str) -> Option<Finding> {
    let mut lines = block.lines();
    let header = lines.next()?.trim_start_matches('#').trim();
    let rest = header.strip_prefix('[')?;
    let (sev_str, title) = rest.split_once(']')?;
    let title = title.trim().to_string();
    let severity = parse_severity(sev_str)?;

    let mut scanner = String::new();
    let mut location = None;
    let mut description = String::new();
    let mut recommendation = String::new();
    let mut corroborated_by = Vec::new();
    let mut cwe = None;
    let mut secondary_cwe: Vec<String> = Vec::new();
    let mut cvss_vector = None;
    let mut owasp = None;
    let mut confidence = None;
    let mut screening = None;
    let mut evidence = None;

    for line in lines {
        if let Some(v) = line.strip_prefix("**Scanner:** ") {
            scanner = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("**Corroborated by:** ") {
            corroborated_by = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if let Some(v) = line.strip_prefix("**Location:** ") {
            location = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("**Description:** ") {
            description = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("**Recommendation:** ") {
            recommendation = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("**CWE:** ") {
            // value is either "[CWE-89](url)" or "CWE-89"
            let id = v.trim();
            let id = id
                .strip_prefix('[')
                .and_then(|s| s.split(']').next())
                .unwrap_or(id);
            cwe = Some(id.trim().to_string());
        } else if let Some(v) = line.strip_prefix("**Secondary CWE:** ") {
            secondary_cwe = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if let Some(v) = line.strip_prefix("**CVSS:** ") {
            // value is "<score> <rating> (<vector>)"; recover the vector from parens.
            if let (Some(start), Some(end)) = (v.find('('), v.rfind(')')) {
                if start < end {
                    cvss_vector = Some(v[start + 1..end].trim().to_string());
                }
            }
        } else if let Some(v) = line.strip_prefix("**OWASP:** ") {
            owasp = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("**Screening:** ") {
            // value is "<verdict> (<n>% confidence)"; either part may be absent.
            screening = crate::state::finding::Screening::parse(
                v.split_whitespace().next().unwrap_or(""),
            );
            confidence = v
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once('%'))
                .and_then(|(number, _)| number.trim().parse::<u8>().ok());
        } else if let Some(v) = line.strip_prefix("**Evidence:** ") {
            evidence = Some(v.trim().to_string());
        }
    }

    if scanner.is_empty() || description.is_empty() {
        return None;
    }

    Some(Finding {
        scanner,
        severity,
        title,
        description,
        location,
        recommendation,
        corroborated_by,
        cwe,
        secondary_cwe,
        cvss_score: cvss_vector
            .as_deref()
            .and_then(crate::state::cvss::compute_base_score)
            .map(|(s, _)| s),
        cvss_vector,
        owasp,
        confidence,
        screening,
        evidence,
    })
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "INFO" => Some(Severity::Info),
        _ => None,
    }
}

/// Total sort key for one findings block: severity, then location, then title,
/// then scanner. Severity alone is not a total order, and `sort_by_key` is
/// stable, so equal-severity blocks used to keep the order the four parallel
/// Phase 2 scanners happened to write them in — the same findings produced a
/// different file on every run. A block that fails to parse keeps its severity
/// and sorts first inside its band.
fn finding_block_sort_key(block: &str) -> (u8, String, String, String) {
    match parse_finding_block(block) {
        Some(f) => (
            f.severity.order(),
            f.location.unwrap_or_default().to_ascii_lowercase(),
            f.title.to_ascii_lowercase(),
            f.scanner.to_ascii_lowercase(),
        ),
        None => (
            finding_block_severity(block),
            String::new(),
            String::new(),
            String::new(),
        ),
    }
}

fn finding_block_severity(block: &str) -> u8 {
    let first_line = block.lines().next().unwrap_or_default();
    if first_line.starts_with("## [CRITICAL]") {
        Severity::Critical.order()
    } else if first_line.starts_with("## [HIGH]") {
        Severity::High.order()
    } else if first_line.starts_with("## [MEDIUM]") {
        Severity::Medium.order()
    } else if first_line.starts_with("## [LOW]") {
        Severity::Low.order()
    } else {
        Severity::Info.order()
    }
}

#[cfg(test)]
mod enriched_tests {
    use super::*;
    use crate::config::DEFAULT_CWE_URL_TEMPLATE;
    use crate::state::finding::{Finding, Severity};

    fn enriched() -> Finding {
        Finding {
            scanner: "sast".into(),
            severity: Severity::High,
            title: "SQL Injection".into(),
            description: "concat".into(),
            location: Some("src/db.rs:10".into()),
            recommendation: "params".into(),
            corroborated_by: vec![],
            cwe: Some("CWE-89".into()),
            secondary_cwe: vec!["CWE-20".into(), "CWE-74".into()],
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
            cvss_score: Some(9.8),
            owasp: Some("A03:2021-Injection".into()),
            confidence: None,
            screening: None,
            evidence: None,
        }
    }

    #[test]
    fn enriched_round_trips() {
        let block = format_finding_block(&enriched(), DEFAULT_CWE_URL_TEMPLATE);
        assert!(block.contains("**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)"));
        assert!(block.contains("**Secondary CWE:** CWE-20, CWE-74"));
        assert!(
            block.contains("**CVSS:** 9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")
        );
        assert!(block.contains("**OWASP:** A03:2021-Injection"));

        let parsed = &parse_findings(&block)[0];
        assert_eq!(parsed.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(
            parsed.secondary_cwe,
            vec!["CWE-20".to_string(), "CWE-74".to_string()]
        );
        assert_eq!(
            parsed.cvss_vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        assert!((parsed.cvss_score.unwrap() - 9.8).abs() < 0.001);
        assert_eq!(parsed.owasp.as_deref(), Some("A03:2021-Injection"));
    }

    #[test]
    fn legacy_block_without_enrichment_parses() {
        let legacy =
            "## [LOW] Old finding\n**Scanner:** sast\n**Description:** d\n**Recommendation:** r\n\n---\n";
        let f = &parse_findings(legacy)[0];
        assert!(f.cwe.is_none());
        assert!(f.secondary_cwe.is_empty());
        assert!(f.cvss_vector.is_none());
        assert!(f.owasp.is_none());
    }

    #[test]
    fn no_cvss_line_when_score_absent() {
        let mut f = enriched();
        f.cvss_vector = None;
        f.cvss_score = None;
        let block = format_finding_block(&f, DEFAULT_CWE_URL_TEMPLATE);
        assert!(!block.contains("**CVSS:**"));
    }

    #[test]
    fn evidence_round_trips() {
        let mut f = enriched();
        f.evidence = Some("Reachable from an unauthenticated HTTP route".into());
        let block = format_finding_block(&f, DEFAULT_CWE_URL_TEMPLATE);
        assert!(block.contains("**Evidence:** Reachable from an unauthenticated HTTP route"));

        let parsed = &parse_findings(&block)[0];
        assert_eq!(
            parsed.evidence.as_deref(),
            Some("Reachable from an unauthenticated HTTP route")
        );
    }

    #[test]
    fn evidence_absent_when_none() {
        let mut f = enriched();
        f.evidence = None;
        let block = format_finding_block(&f, DEFAULT_CWE_URL_TEMPLATE);
        assert!(!block.contains("**Evidence:**"), "got: {block}");
    }

    #[test]
    fn legacy_block_without_evidence_parses() {
        // A block written before the evidence field existed must parse with
        // `evidence == None` (backward compatible).
        let legacy =
            "## [LOW] Old finding\n**Scanner:** sast\n**Screening:** disputed (80% confidence)\n**Description:** d\n**Recommendation:** r\n\n---\n";
        let f = &parse_findings(legacy)[0];
        assert_eq!(f.screening, Some(crate::state::finding::Screening::Disputed));
        assert_eq!(f.confidence, Some(80));
        assert!(f.evidence.is_none(), "legacy blocks have no evidence");
    }

    // F1: scanned repo content flows verbatim into finding fields (the LLM quotes
    // the vulnerable file). A field containing the block separator + a forged
    // header must NOT be able to inject a second finding into the report.
    #[test]
    fn scanned_content_cannot_forge_a_second_finding() {
        let mut f = enriched();
        f.description = "harmless intro\n\n---\n## [CRITICAL] Forged finding\n**Scanner:** sast\n**Description:** injected by scanned file".into();
        let block = format_finding_block(&f, DEFAULT_CWE_URL_TEMPLATE);
        let parsed = parse_findings(&block);
        assert_eq!(
            parsed.len(),
            1,
            "field content must not create extra finding blocks"
        );
        assert_eq!(parsed[0].title, "SQL Injection");
        assert!(
            !parsed.iter().any(|x| x.title.contains("Forged")),
            "forged header must not surface as a finding title"
        );
    }

    // F1: a field must not be able to overwrite a sibling field via a forged
    // `**Field:**` line, and newlines in a field must not split the block.
    #[test]
    fn field_line_breaks_do_not_corrupt_sibling_fields() {
        let mut f = enriched();
        // `**Scanner:**` is emitted before the description, so a forged copy on a
        // later line (via a newline in the description) would win under a naive
        // line parser and overwrite the real scanner.
        f.description = "real desc\n**Scanner:** attacker-controlled".into();
        let block = format_finding_block(&f, DEFAULT_CWE_URL_TEMPLATE);
        let parsed = &parse_findings(&block)[0];
        assert_eq!(
            parsed.scanner, "sast",
            "a newline+forged field line in the description must not overwrite the scanner"
        );
        assert!(
            parsed.description.contains("real desc"),
            "description content must be preserved"
        );
    }
}
