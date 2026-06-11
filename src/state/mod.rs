pub mod finding;
pub use finding::{Finding, Severity};

use anyhow::Result;
use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct StateWriter {
    zentra_dir: PathBuf,
}

impl StateWriter {
    pub fn new(project_root: &Path) -> Result<Self> {
        let zentra_dir = project_root.join(".zentra");
        fs::create_dir_all(&zentra_dir)?;
        fs::create_dir_all(zentra_dir.join("reports"))?;
        // Truncate only findings — architecture.md persists across scans
        let findings_path = zentra_dir.join("detailed-findings.md");
        if findings_path.exists() {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&findings_path)?;
        }
        Ok(Self { zentra_dir })
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<()> {
        let path = self.zentra_dir.join("detailed-findings.md");
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        write!(file, "{}", format_finding_block(finding))?;
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
        let body: String = findings.iter().map(format_finding_block).collect();
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

fn format_finding_block(finding: &Finding) -> String {
    let location_line = finding
        .location
        .as_deref()
        .map(|l| format!("**Location:** {}\n", l))
        .unwrap_or_default();

    // Emitted only when present, so singleton findings produce identical output.
    let corroborated_line = if finding.corroborated_by.is_empty() {
        String::new()
    } else {
        format!("**Corroborated by:** {}\n", finding.corroborated_by.join(", "))
    };

    format!(
        "## [{}] {}\n**Scanner:** {}\n{}{}**Description:** {}\n**Recommendation:** {}\n\n---\n",
        finding.severity,
        finding.title,
        finding.scanner,
        corroborated_line,
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
