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

    format!(
        "## [{}] {}\n**Scanner:** {}\n{}**Description:** {}\n**Recommendation:** {}\n\n---\n",
        finding.severity,
        finding.title,
        finding.scanner,
        location_line,
        finding.description,
        finding.recommendation,
    )
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
