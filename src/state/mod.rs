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
        Ok(Self { zentra_dir })
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<()> {
        let path = self.zentra_dir.join("detailed-findings.md");
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        let location_line = finding.location.as_deref()
            .map(|l| format!("**Location:** {}\n", l))
            .unwrap_or_default();

        writeln!(
            file,
            "## [{}] {}\n**Scanner:** {}\n{}**Description:** {}\n**Recommendation:** {}\n\n---\n",
            finding.severity,
            finding.title,
            finding.scanner,
            location_line,
            finding.description,
            finding.recommendation,
        )?;
        Ok(())
    }

    pub fn write_report(&self, content: &str) -> Result<()> {
        let date = Local::now().format("%Y%m%d").to_string();
        let path = self.zentra_dir.join("reports").join(format!("{}-report.md", date));
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
}
