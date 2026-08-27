use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use uuid::Uuid;

/// A validated SHA-256 hex digest. Its inner value is private so chat audit
/// variants cannot accidentally be constructed with raw transcript content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDigest(String);

impl AuditDigest {
    fn hash(value: &str) -> Self {
        Self(sha256_str(value))
    }
}

impl Serialize for AuditDigest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AuditDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom("expected SHA-256 hex digest"))
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind")]
pub enum AuditEvent {
    SessionStart {
        provider_kind: String,
        model: String,
        scanner: String,
    },
    LlmRequest {
        request_id: u64,
        /// SHA-256 of the full prompt; secrets are never stored in plaintext.
        prompt_hash: String,
    },
    LlmResponse {
        request_id: u64,
        nonce_verified: bool,
        tool_call_count: usize,
    },
    /// Hash-only record of a chat request. Chat transcripts never enter the
    /// tamper-evident audit stream.
    ChatRequest {
        request_id_hash: AuditDigest,
        request_hash: AuditDigest,
    },
    /// Hash-only record of a chat response. Chat transcripts never enter the
    /// tamper-evident audit stream.
    ChatResponse {
        request_id_hash: AuditDigest,
        response_hash: AuditDigest,
    },
    /// Hash-only record of an operator-confirmed typed chat action.
    ChatActionConfirmed {
        proposal_id_hash: AuditDigest,
        action_hash: AuditDigest,
    },
    ToolDispatched {
        tool: String,
        /// SHA-256 of the JSON-serialised arguments.
        arg_hash: String,
    },
    ToolResult {
        tool: String,
        /// SHA-256 of the result string.
        result_hash: String,
    },
    SecurityViolation {
        category: String,
        detail: String,
    },
    SessionEnd {
        reason: String,
    },
}

impl AuditEvent {
    pub fn chat_request(request_id: Uuid, request: &str) -> Self {
        Self::ChatRequest {
            request_id_hash: AuditDigest::hash(&request_id.to_string()),
            request_hash: AuditDigest::hash(request),
        }
    }

    pub fn chat_response(request_id: Uuid, response: &str) -> Self {
        Self::ChatResponse {
            request_id_hash: AuditDigest::hash(&request_id.to_string()),
            response_hash: AuditDigest::hash(response),
        }
    }

    pub fn chat_action_confirmed(
        proposal_id: Uuid,
        action: &crate::agent::chat::ChatAction,
    ) -> Result<Self> {
        let action = serde_json::to_string(action)?;
        Ok(Self::ChatActionConfirmed {
            proposal_id_hash: AuditDigest::hash(&proposal_id.to_string()),
            action_hash: AuditDigest::hash(&action),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp_ms: i64,
    pub session_id: String,
    pub event: AuditEvent,
    /// SHA-256 hex of the previous entry (genesis = SHA-256 of session_id).
    pub prev_hash: String,
    /// SHA-256 hex of this entry's canonical JSON (excluding the entry_hash field itself).
    pub entry_hash: String,
}

pub struct AuditLog {
    /// None when auditing is disabled.
    writer: Option<BufWriter<File>>,
    prev_hash: String,
    seq: u64,
    pub session_id: String,
}

pub enum VerifyResult {
    Ok { entries: u64 },
    Tampered { at_seq: u64, reason: String },
}

impl AuditLog {
    pub fn new(zentra_dir: &Path, session_id: &str, enabled: bool) -> Result<Self> {
        crate::agent::chat::validate_session_id(session_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let writer = if enabled {
            let audit_dir = zentra_dir.join("audit");
            fs::create_dir_all(&audit_dir)?;
            let path = audit_dir.join(format!("{}.jsonl", session_id));
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            Some(BufWriter::new(file))
        } else {
            None
        };

        Ok(Self {
            writer,
            prev_hash: sha256_str(session_id),
            seq: 0,
            session_id: session_id.to_string(),
        })
    }

    /// Reopen an existing verified session without restarting its hash chain.
    /// This is intentionally separate from `new`, whose fresh-session behavior
    /// remains compatible with existing scan startup code.
    pub fn open_existing(zentra_dir: &Path, session_id: &str, enabled: bool) -> Result<Self> {
        crate::agent::chat::validate_session_id(session_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !enabled {
            return Self::new(zentra_dir, session_id, false);
        }
        let path = zentra_dir.join("audit").join(format!("{session_id}.jsonl"));
        let (seq, prev_hash) = continuation_state(&path, session_id)?;
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            writer: Some(BufWriter::new(file)),
            prev_hash,
            seq,
            session_id: session_id.to_string(),
        })
    }

    pub fn record(&mut self, event: AuditEvent) -> Result<()> {
        let Some(ref mut writer) = self.writer else {
            return Ok(());
        };

        let seq = self.seq;
        self.seq += 1;
        let timestamp_ms = Utc::now().timestamp_millis();

        // Hash the partial entry (without entry_hash) to form the chain link.
        let partial = serde_json::json!({
            "seq": seq,
            "timestamp_ms": timestamp_ms,
            "session_id": &self.session_id,
            "event": &event,
            "prev_hash": &self.prev_hash,
        });
        let entry_hash = sha256_str(&partial.to_string());

        let entry = AuditEntry {
            seq,
            timestamp_ms,
            session_id: self.session_id.clone(),
            event,
            prev_hash: self.prev_hash.clone(),
            entry_hash: entry_hash.clone(),
        };

        writeln!(writer, "{}", serde_json::to_string(&entry)?)?;
        writer.flush()?;
        self.prev_hash = entry_hash;
        Ok(())
    }

    /// Re-read the log file and verify every hash link. O(n) in entry count.
    pub fn verify_chain(path: &Path) -> Result<VerifyResult> {
        let content = fs::read_to_string(path)?;
        let mut prev_hash: Option<String> = None;
        let mut session_id: Option<String> = None;
        let mut count = 0u64;

        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!("Line {}: {}", line_num + 1, e))?;

            if entry.seq != count {
                return Ok(VerifyResult::Tampered {
                    at_seq: entry.seq,
                    reason: "sequence mismatch".to_string(),
                });
            }
            let expected = if let Some(ref previous) = prev_hash {
                previous.clone()
            } else {
                session_id = Some(entry.session_id.clone());
                sha256_str(&entry.session_id)
            };
            if entry.prev_hash != expected {
                return Ok(VerifyResult::Tampered {
                    at_seq: entry.seq,
                    reason: "prev_hash mismatch".to_string(),
                });
            }
            if session_id.as_deref() != Some(entry.session_id.as_str()) {
                return Ok(VerifyResult::Tampered {
                    at_seq: entry.seq,
                    reason: "session_id mismatch".to_string(),
                });
            }

            let partial = serde_json::json!({
                "seq": entry.seq,
                "timestamp_ms": entry.timestamp_ms,
                "session_id": &entry.session_id,
                "event": &entry.event,
                "prev_hash": &entry.prev_hash,
            });
            let expected_hash = sha256_str(&partial.to_string());
            if expected_hash != entry.entry_hash {
                return Ok(VerifyResult::Tampered {
                    at_seq: entry.seq,
                    reason: "entry_hash mismatch".to_string(),
                });
            }

            prev_hash = Some(entry.entry_hash.clone());
            count += 1;
        }

        Ok(VerifyResult::Ok { entries: count })
    }
}

fn continuation_state(path: &Path, session_id: &str) -> Result<(u64, String)> {
    match AuditLog::verify_chain(path)? {
        VerifyResult::Ok { .. } => {}
        VerifyResult::Tampered { at_seq, reason } => {
            anyhow::bail!("refusing to resume tampered audit log at sequence {at_seq}: {reason}")
        }
    }
    let content = fs::read_to_string(path)?;
    let mut last: Option<AuditEntry> = None;
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        last = Some(serde_json::from_str(line)?);
    }
    match last {
        Some(entry) if entry.session_id == session_id => Ok((entry.seq + 1, entry.entry_hash)),
        Some(_) => anyhow::bail!("refusing to resume audit log for a different session"),
        None => Ok((0, sha256_str(session_id))),
    }
}

pub fn sha256_str(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

pub fn sha256_json(v: &serde_json::Value) -> String {
    sha256_str(&v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_n_entries(dir: &Path, session: &str, n: u64) -> std::path::PathBuf {
        let mut log = AuditLog::new(dir, session, true).unwrap();
        for i in 0..n {
            log.record(AuditEvent::ToolDispatched {
                tool: format!("tool_{}", i),
                arg_hash: sha256_str(&format!("arg_{}", i)),
            })
            .unwrap();
        }
        dir.join("audit").join(format!("{}.jsonl", session))
    }

    #[test]
    fn intact_chain_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_n_entries(tmp.path(), "sess", 10);
        match AuditLog::verify_chain(&path).unwrap() {
            VerifyResult::Ok { entries } => assert_eq!(entries, 10),
            VerifyResult::Tampered { .. } => panic!("intact chain reported tampered"),
        }
    }

    #[test]
    fn tampered_entry_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_n_entries(tmp.path(), "sess", 10);

        // Corrupt the event payload of entry 5 without fixing its hashes.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[5] = lines[5].replace("tool_5", "tool_EVIL");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "{}", lines.join("\n")).unwrap();

        match AuditLog::verify_chain(&path).unwrap() {
            VerifyResult::Tampered { at_seq, .. } => assert_eq!(at_seq, 5),
            VerifyResult::Ok { .. } => panic!("tampering not detected"),
        }
    }

    #[test]
    fn disabled_log_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = AuditLog::new(tmp.path(), "sess", false).unwrap();
        log.record(AuditEvent::SessionEnd {
            reason: "done".to_string(),
        })
        .unwrap();
        assert!(!tmp.path().join("audit").exists());
    }

    #[test]
    fn secrets_are_never_stored_in_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = AuditLog::new(tmp.path(), "sess", true).unwrap();
        let secret = "sk-ant-SUPERSECRETKEY12345";
        log.record(AuditEvent::ToolDispatched {
            tool: "read_file".to_string(),
            arg_hash: sha256_str(secret),
        })
        .unwrap();
        let path = tmp.path().join("audit").join("sess.jsonl");
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.contains(secret), "secret leaked into audit log");
    }

    #[test]
    fn chat_audit_events_contain_hashes_only() {
        let request = "please inspect password=hunter2";
        let response = "found token=topsecret";
        let request_id = Uuid::new_v4();
        let action = crate::agent::chat::ChatAction::prioritize(
            crate::agent::chat::VulnerabilityCategory::Injection,
        );
        let event = AuditEvent::chat_request(request_id, request);
        let response_event = AuditEvent::chat_response(request_id, response);
        let action_event = AuditEvent::chat_action_confirmed(Uuid::new_v4(), &action).unwrap();

        let json = format!(
            "{}{}{}",
            serde_json::to_string(&event).unwrap(),
            serde_json::to_string(&response_event).unwrap(),
            serde_json::to_string(&action_event).unwrap()
        );
        assert!(!json.contains(request));
        assert!(!json.contains(response));
        assert!(!json.contains("prioritize_vulnerability"));
        assert!(json.contains("request_hash"));
        assert!(json.contains("response_hash"));
        assert!(json.contains("action_hash"));
    }

    #[test]
    fn existing_verified_session_continues_its_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = AuditLog::new(tmp.path(), "session", true).unwrap();
        first
            .record(AuditEvent::SessionEnd {
                reason: "pause".into(),
            })
            .unwrap();
        drop(first);

        let mut resumed = AuditLog::open_existing(tmp.path(), "session", true).unwrap();
        resumed
            .record(AuditEvent::SessionEnd {
                reason: "done".into(),
            })
            .unwrap();
        drop(resumed);
        let path = tmp.path().join("audit").join("session.jsonl");
        assert!(matches!(
            AuditLog::verify_chain(&path).unwrap(),
            VerifyResult::Ok { entries: 2 }
        ));
    }

    #[test]
    fn corrupt_existing_session_refuses_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_n_entries(tmp.path(), "session", 1);
        std::fs::write(&path, "corrupt\n").unwrap();
        assert!(AuditLog::open_existing(tmp.path(), "session", true).is_err());
    }

    #[test]
    fn audit_constructors_reject_path_traversal_session_ids() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(AuditLog::new(tmp.path(), "../../../x", true).is_err());
        assert!(AuditLog::open_existing(tmp.path(), "../../../x", true).is_err());
    }
}
