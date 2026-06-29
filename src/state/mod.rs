pub mod cvss;
pub mod finding;
pub use finding::{Finding, Severity};

use anyhow::Result;
use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct StateWriter {
    zentra_dir: PathBuf,
    cwe_template: String,
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
        })
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<()> {
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

    /// Replace the entire findings file with the given set, then re-sort by
    /// severity. Used by the correlation pass to write back the deduped findings.
    pub fn rewrite_findings(&self, findings: &[Finding]) -> Result<()> {
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

        blocks.sort_by_key(|block| finding_block_order(block));

        let sorted = if blocks.is_empty() {
            String::new()
        } else {
            format!("{}\n\n---\n", blocks.join("\n\n---\n"))
        };

        std::fs::write(path, sorted)?;
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

fn format_finding_block(finding: &Finding, cwe_template: &str) -> String {
    let location_line = finding
        .location
        .as_deref()
        .map(|l| format!("**Location:** {}\n", l))
        .unwrap_or_default();

    // Emitted only when present, so singleton findings produce identical output.
    let corroborated_line = if finding.corroborated_by.is_empty() {
        String::new()
    } else {
        format!(
            "**Corroborated by:** {}\n",
            finding.corroborated_by.join(", ")
        )
    };

    let cwe_line = finding
        .cwe
        .as_deref()
        .map(|id| {
            format!(
                "**CWE:** [{}]({})\n",
                id,
                crate::config::cwe_link(id, cwe_template)
            )
        })
        .unwrap_or_default();

    let secondary_line = if finding.secondary_cwe.is_empty() {
        String::new()
    } else {
        format!("**Secondary CWE:** {}\n", finding.secondary_cwe.join(", "))
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
        .map(|o| format!("**OWASP:** {}\n", o))
        .unwrap_or_default();

    format!(
        "## [{}] {}\n**Scanner:** {}\n{}{}{}{}{}{}**Description:** {}\n**Recommendation:** {}\n\n---\n",
        finding.severity,
        finding.title,
        finding.scanner,
        corroborated_line,
        cwe_line,
        secondary_line,
        cvss_line,
        owasp_line,
        location_line,
        finding.description,
        finding.recommendation,
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

fn finding_block_order(block: &str) -> u8 {
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
}
