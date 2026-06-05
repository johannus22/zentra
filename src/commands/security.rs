use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::security::{AuditLog, VerifyResult};

/// Verify the tamper-evident hash chain of one session, or every session if
/// `session` is None.
pub async fn verify_audit(session: Option<String>) -> Result<()> {
    let audit_dir = Path::new(".zentra").join("audit");
    if !audit_dir.exists() {
        anyhow::bail!("No audit logs found at {}", audit_dir.display());
    }

    let files: Vec<PathBuf> = match session {
        Some(id) => vec![audit_dir.join(format!("{}.jsonl", id))],
        None => {
            let mut v = Vec::new();
            for entry in std::fs::read_dir(&audit_dir).context("Failed to read audit directory")? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                    v.push(path);
                }
            }
            v.sort();
            v
        }
    };

    if files.is_empty() {
        anyhow::bail!("No audit log sessions found in {}", audit_dir.display());
    }

    let mut all_ok = true;
    for path in files {
        if !path.exists() {
            println!("✗ {}: file not found", path.display());
            all_ok = false;
            continue;
        }
        let label = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        match AuditLog::verify_chain(&path)? {
            VerifyResult::Ok { entries } => {
                println!("✓ {}: OK — {} entries verified", label, entries);
            }
            VerifyResult::Tampered { at_seq, reason } => {
                println!("✗ {}: TAMPERED at entry {} ({})", label, at_seq, reason);
                all_ok = false;
            }
        }
    }

    if !all_ok {
        anyhow::bail!("One or more audit logs failed verification");
    }
    Ok(())
}
