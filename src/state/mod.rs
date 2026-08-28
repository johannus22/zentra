pub mod cvss;
pub mod finding;
pub mod html;
pub mod sarif;
pub use finding::{Finding, Severity};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Local;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

const FINDINGS_RERUN_JOURNAL: &str = "findings-rerun.journal";
const FINDINGS_RERUN_JOURNAL_VERSION: u8 = 2;
const MAX_FINDINGS_RERUN_BYTES: usize = 8 * 1024 * 1024;
const MAX_FINDINGS_RERUN_PROPOSALS: usize = 128;
// A committed journal stores both the old and new byte streams as base64.
const MAX_FINDINGS_RERUN_JOURNAL_BYTES: usize = MAX_FINDINGS_RERUN_BYTES * 3 + 4096;

pub struct StateWriter {
    zentra_dir: PathBuf,
    cwe_template: String,
    /// Serializes the findings-file read-modify-write. Phase 2 runs the SAST,
    /// SupplyChain, ApiScan and IaCScan scanners on separate runtime threads,
    /// all sharing one `Arc<StateWriter>`. The lock covers each full read-modify-
    /// atomic-write operation so concurrent writers cannot silently lose updates.
    findings_lock: std::sync::Mutex<()>,
    #[cfg(test)]
    fail_next_journal_cleanup: std::sync::atomic::AtomicBool,
}

/// An in-process transaction for replacing one scanner's findings after a rerun.
///
/// The snapshot retains the original bytes so a failed rerun can restore the
/// exact pre-rerun file. The matching fixed journal makes the transaction
/// recoverable across a process crash; callers still finish it in-process.
#[derive(Debug, Clone)]
pub(crate) struct FindingsRerun {
    scanner: String,
    pre_rerun_raw: String,
    pre_rerun_existed: bool,
    pre_rerun_findings: Vec<Finding>,
    proposal_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FindingsRerunJournalState {
    Staged,
    Committed,
}

/// A fixed, versioned recovery record. Original and committed data are base64
/// rather than line-oriented fields so arbitrary valid UTF-8 findings bytes are
/// preserved exactly and cannot forge journal metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingsRerunJournal {
    version: u8,
    state: FindingsRerunJournalState,
    scanner: String,
    proposal_ids: Vec<uuid::Uuid>,
    original_existed: bool,
    original_base64: String,
    #[serde(default)]
    committed_base64: Option<String>,
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
            #[cfg(test)]
            fail_next_journal_cleanup: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<()> {
        // Hold the lock across read + modify + atomic replacement. Rerun staging
        // uses only short critical sections and never retains this over async work.
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.zentra_dir.join("detailed-findings.md");
        let mut raw = read_findings_file(&path)?;
        raw.push_str(&format_finding_block(finding, &self.cwe_template));
        self.write_findings_body_locked(&raw)
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
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.write_findings_set_locked(findings)
    }

    /// Snapshot and stage one scanner's rerun without permanently discarding its
    /// old findings. After the scanner writes its new output through
    /// `write_finding`, call `commit_findings_rerun_pending_progress`, persist
    /// strict checkpoint progress, then call `finalize_findings_rerun`. Call
    /// `rollback_findings_rerun` for every failure or cancellation before that.
    ///
    /// Before staging, this durably writes a bounded recovery journal. On the
    /// next startup/resume, `recover_interrupted_findings_rerun` restores a
    /// staged transaction or finalizes a committed one.
    pub(crate) fn begin_findings_rerun(
        &self,
        scanner: &str,
        proposal_ids: &[uuid::Uuid],
    ) -> Result<FindingsRerun> {
        let scanner = validated_scanner_name(scanner)?;
        let proposal_ids = canonical_proposal_ids(proposal_ids)?;
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.rerun_journal_exists_locked()? {
            bail!("an interrupted findings rerun journal is already active");
        }
        let path = self.zentra_dir.join("detailed-findings.md");
        let (pre_rerun_raw, pre_rerun_existed) =
            read_findings_file_with_existence_bounded(&path, MAX_FINDINGS_RERUN_BYTES)?;
        let pre_rerun_findings = parse_findings(&pre_rerun_raw);
        let retained: Vec<_> = pre_rerun_findings
            .iter()
            .filter(|finding| finding.scanner != scanner)
            .cloned()
            .collect();

        // Do not alter the original until its exact bytes are durably journaled.
        // A journal persistence failure leaves the live file untouched.
        self.write_rerun_journal_locked(&FindingsRerunJournal::staged(
            scanner,
            &proposal_ids,
            pre_rerun_existed,
            &pre_rerun_raw,
        )?)?;
        self.write_findings_set_locked(&retained)?;
        Ok(FindingsRerun {
            scanner: scanner.to_owned(),
            pre_rerun_raw,
            pre_rerun_existed,
            pre_rerun_findings,
            proposal_ids,
        })
    }

    /// Replace the target's pre-rerun set with target findings emitted since
    /// staging. Parsed `Finding::scanner` identity, not markdown text matching,
    /// decides ownership. This preserves every previous non-target finding once,
    /// plus any new non-target finding written concurrently during the rerun.
    ///
    /// Commit is journaled before its live-file replacement, but the journal is
    /// deliberately retained until `finalize_findings_rerun` observes a separate
    /// strict checkpoint-progress success.
    pub(crate) fn commit_findings_rerun_pending_progress(
        &self,
        staging: &FindingsRerun,
    ) -> Result<()> {
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let journal = self
            .read_rerun_journal_locked()?
            .ok_or_else(|| anyhow::anyhow!("no active findings rerun journal exists for commit"))?;
        ensure_journal_matches_staging(&journal, staging)?;
        if journal.state == FindingsRerunJournalState::Committed {
            // Strict checkpoint progress has not been confirmed to this layer, so
            // retain the marker. The caller must finalize only after persistence.
            return Ok(());
        }
        let path = self.zentra_dir.join("detailed-findings.md");
        let current = parse_findings(&read_findings_file(&path)?);
        let mut replacement: Vec<Finding> = staging
            .pre_rerun_findings
            .iter()
            .filter(|finding| finding.scanner != staging.scanner)
            .cloned()
            .collect();

        for finding in current
            .iter()
            .filter(|finding| finding.scanner != staging.scanner)
        {
            if !replacement
                .iter()
                .any(|existing| findings_identical(existing, finding, &self.cwe_template))
            {
                replacement.push(finding.clone());
            }
        }
        replacement.extend(
            current
                .into_iter()
                .filter(|finding| finding.scanner == staging.scanner),
        );
        deduplicate_findings(&mut replacement, &self.cwe_template);
        let committed_raw = self.findings_set_body(&replacement);
        let committed_journal = journal.committed(&committed_raw)?;

        // Persist the desired final bytes first. If the process stops before the
        // next write, recovery applies these bytes instead of accepting a
        // target-free staged file.
        self.write_rerun_journal_locked(&committed_journal)?;
        self.write_findings_raw_locked(&committed_raw)?;
        Ok(())
    }

    /// Remove a matching committed journal only after strict checkpoint progress
    /// (scanner completion and proposal advancement) has persisted successfully.
    pub(crate) fn finalize_findings_rerun(&self, staging: &FindingsRerun) -> Result<()> {
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let journal = self.read_rerun_journal_locked()?.ok_or_else(|| {
            anyhow::anyhow!("no active findings rerun journal exists for finalization")
        })?;
        ensure_journal_matches_staging(&journal, staging)?;
        if journal.state != FindingsRerunJournalState::Committed {
            bail!("cannot finalize a findings rerun before its committed marker exists");
        }
        self.remove_rerun_journal_locked()
    }

    /// Restore exact original bytes/absence unless the caller has already
    /// finalized after strict checkpoint progress. This compensates a committed
    /// marker whose live replacement failed before progress was persisted.
    pub(crate) fn rollback_findings_rerun(&self, staging: &FindingsRerun) -> Result<()> {
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let journal = self.read_rerun_journal_locked()?.ok_or_else(|| {
            anyhow::anyhow!("no active findings rerun journal exists for rollback")
        })?;
        ensure_journal_matches_staging(&journal, staging)?;
        self.restore_journal_original_locked(&journal)?;
        self.remove_rerun_journal_locked()
    }

    /// Recover the one fixed rerun journal at startup/resume before callers read
    /// findings. A staged record restores the exact old file; a committed record
    /// applies its durable replacement only when checkpoint scanner/proposal
    /// progress confirms it, otherwise it restores the old file. Invalid,
    /// mismatched, non-regular, or symlinked journals fail closed without
    /// touching the live findings file.
    pub(crate) fn recover_interrupted_findings_rerun(
        &self,
        checkpoint: &crate::agent::checkpoint::Checkpoint,
    ) -> Result<()> {
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(journal) = self.read_rerun_journal_locked()? else {
            return Ok(());
        };
        match journal.state {
            FindingsRerunJournalState::Staged => self.restore_journal_original_locked(&journal)?,
            FindingsRerunJournalState::Committed => {
                if checkpoint_confirms_rerun_progress(checkpoint, &journal) {
                    self.write_findings_raw_locked(&journal.committed_raw()?)?
                } else {
                    self.restore_journal_original_locked(&journal)?;
                }
            }
        }
        self.remove_rerun_journal_locked()
    }

    pub fn read_findings_raw(&self) -> Result<String> {
        let _guard = self.findings_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.zentra_dir.join("detailed-findings.md");
        read_findings_file(&path)
    }

    fn rerun_journal_path(&self) -> PathBuf {
        self.zentra_dir.join(FINDINGS_RERUN_JOURNAL)
    }

    fn rerun_journal_exists_locked(&self) -> Result<bool> {
        safe_regular_file_exists(&self.rerun_journal_path())
    }

    fn read_rerun_journal_locked(&self) -> Result<Option<FindingsRerunJournal>> {
        let path = self.rerun_journal_path();
        if !safe_regular_file_exists(&path)? {
            return Ok(None);
        }
        let metadata = fs::metadata(&path)?;
        if metadata.len() > MAX_FINDINGS_RERUN_JOURNAL_BYTES as u64 {
            bail!("findings rerun journal exceeds the recovery size limit");
        }
        let raw = fs::read(&path)?;
        if raw.len() > MAX_FINDINGS_RERUN_JOURNAL_BYTES {
            bail!("findings rerun journal exceeds the recovery size limit");
        }
        let journal: FindingsRerunJournal = serde_json::from_slice(&raw)
            .map_err(|error| anyhow::anyhow!("invalid findings rerun journal: {error}"))?;
        journal.validate()?;
        Ok(Some(journal))
    }

    fn write_rerun_journal_locked(&self, journal: &FindingsRerunJournal) -> Result<()> {
        journal.validate()?;
        let raw = serde_json::to_vec(journal)?;
        if raw.len() > MAX_FINDINGS_RERUN_JOURNAL_BYTES {
            bail!("findings rerun journal exceeds the recovery size limit");
        }
        let path = self.rerun_journal_path();
        // Do not let the fixed destination or its fixed temp sibling follow an
        // attacker-controlled symlink. `write_atomic` then fsyncs and renames the
        // sibling temp file in `.zentra`.
        safe_regular_file_exists(&path)?;
        safe_regular_file_exists(&path.with_file_name(format!("{FINDINGS_RERUN_JOURNAL}.tmp")))?;
        crate::config::write_atomic(&path, &raw)?;
        Ok(())
    }

    fn remove_rerun_journal_locked(&self) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_journal_cleanup
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            bail!("injected findings rerun journal cleanup failure");
        }
        let path = self.rerun_journal_path();
        if !safe_regular_file_exists(&path)? {
            return Ok(());
        }
        fs::remove_file(path)?;
        Ok(())
    }

    fn restore_journal_original_locked(&self, journal: &FindingsRerunJournal) -> Result<()> {
        if journal.original_existed {
            self.write_findings_raw_locked(&journal.original_raw()?)
        } else {
            let path = self.zentra_dir.join("detailed-findings.md");
            if safe_regular_file_exists(&path)? {
                fs::remove_file(path)?;
            }
            Ok(())
        }
    }

    fn write_findings_set_locked(&self, findings: &[Finding]) -> Result<()> {
        let body = self.findings_set_body(findings);
        self.write_findings_body_locked(&body)
    }

    fn findings_set_body(&self, findings: &[Finding]) -> String {
        let raw: String = findings
            .iter()
            .map(|finding| format_finding_block(finding, &self.cwe_template))
            .collect();
        sorted_findings_body(&raw)
    }

    fn write_findings_body_locked(&self, raw: &str) -> Result<()> {
        self.write_findings_raw_locked(&sorted_findings_body(raw))
    }

    fn write_findings_raw_locked(&self, body: &str) -> Result<()> {
        crate::config::write_atomic(
            &self.zentra_dir.join("detailed-findings.md"),
            body.as_bytes(),
        )?;
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

impl FindingsRerunJournal {
    fn staged(
        scanner: &str,
        proposal_ids: &[uuid::Uuid],
        original_existed: bool,
        original_raw: &str,
    ) -> Result<Self> {
        let journal = Self {
            version: FINDINGS_RERUN_JOURNAL_VERSION,
            state: FindingsRerunJournalState::Staged,
            scanner: scanner.to_owned(),
            proposal_ids: proposal_ids.to_vec(),
            original_existed,
            original_base64: BASE64.encode(original_raw.as_bytes()),
            committed_base64: None,
        };
        journal.validate()?;
        Ok(journal)
    }

    fn committed(&self, committed_raw: &str) -> Result<Self> {
        let journal = Self {
            version: self.version,
            state: FindingsRerunJournalState::Committed,
            scanner: self.scanner.clone(),
            proposal_ids: self.proposal_ids.clone(),
            original_existed: self.original_existed,
            original_base64: self.original_base64.clone(),
            committed_base64: Some(BASE64.encode(committed_raw.as_bytes())),
        };
        journal.validate()?;
        Ok(journal)
    }

    fn original_raw(&self) -> Result<String> {
        decode_journal_contents(&self.original_base64, "original")
    }

    fn committed_raw(&self) -> Result<String> {
        decode_journal_contents(
            self.committed_base64
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("committed journal lacks replacement bytes"))?,
            "committed",
        )
    }

    fn validate(&self) -> Result<()> {
        if self.version != FINDINGS_RERUN_JOURNAL_VERSION {
            bail!("unsupported findings rerun journal version");
        }
        validated_scanner_name(&self.scanner)?;
        if canonical_proposal_ids(&self.proposal_ids)? != self.proposal_ids {
            bail!("findings rerun journal proposal IDs are not canonical");
        }
        self.original_raw()?;
        match self.state {
            FindingsRerunJournalState::Staged if self.committed_base64.is_some() => {
                bail!("staged findings rerun journal contains committed bytes")
            }
            FindingsRerunJournalState::Committed => {
                self.committed_raw()?;
            }
            FindingsRerunJournalState::Staged => {}
        }
        Ok(())
    }
}

fn ensure_journal_matches_staging(
    journal: &FindingsRerunJournal,
    staging: &FindingsRerun,
) -> Result<()> {
    if journal.scanner != staging.scanner
        || journal.proposal_ids != staging.proposal_ids
        || journal.original_existed != staging.pre_rerun_existed
        || journal.original_raw()? != staging.pre_rerun_raw
    {
        bail!("findings rerun journal does not match the active transaction");
    }
    Ok(())
}

fn canonical_proposal_ids(proposal_ids: &[uuid::Uuid]) -> Result<Vec<uuid::Uuid>> {
    if proposal_ids.len() > MAX_FINDINGS_RERUN_PROPOSALS {
        bail!("findings rerun proposal membership exceeds the recovery limit");
    }
    let canonical: BTreeSet<_> = proposal_ids.iter().copied().collect();
    if canonical.len() != proposal_ids.len() {
        bail!("duplicate findings rerun proposal membership");
    }
    Ok(canonical.into_iter().collect())
}

fn checkpoint_confirms_rerun_progress(
    checkpoint: &crate::agent::checkpoint::Checkpoint,
    journal: &FindingsRerunJournal,
) -> bool {
    checkpoint.completed.contains(&journal.scanner)
        && journal.proposal_ids.iter().all(|proposal_id| {
            match checkpoint
                .confirmed_chat_actions
                .iter()
                .find(|action| action.proposal_id == *proposal_id)
            {
                None => true,
                Some(action) => !action
                    .remaining_scanners
                    .iter()
                    .any(|remaining| remaining.name() == journal.scanner),
            }
        })
}

fn decode_journal_contents(encoded: &str, field: &str) -> Result<String> {
    let bytes = BASE64.decode(encoded).map_err(|error| {
        anyhow::anyhow!("invalid {field} findings rerun journal bytes: {error}")
    })?;
    if bytes.len() > MAX_FINDINGS_RERUN_BYTES {
        bail!("{field} findings rerun journal bytes exceed the recovery size limit");
    }
    String::from_utf8(bytes).map_err(|error| {
        anyhow::anyhow!("{field} findings rerun journal bytes are not UTF-8: {error}")
    })
}

/// Return false for an absent path, but never operate through a symlink or a
/// non-regular file. The journal has a fixed name, so fail closed instead of
/// accepting a substituted FIFO, directory, or link.
fn safe_regular_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("unsafe symlink at {}", path.display())
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("unsafe non-regular file at {}", path.display())
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn sorted_findings_body(raw: &str) -> String {
    let mut blocks: Vec<String> = raw
        .split("\n\n---\n")
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(|b| b.to_string())
        .collect();

    blocks.sort_by_key(|block| finding_block_sort_key(block));
    if blocks.is_empty() {
        String::new()
    } else {
        format!("{}\n\n---\n", blocks.join("\n\n---\n"))
    }
}

fn read_findings_file(path: &Path) -> Result<String> {
    safe_regular_file_exists(path)?;
    match fs::read_to_string(path) {
        Ok(raw) => Ok(raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error.into()),
    }
}

fn read_findings_file_with_existence_bounded(
    path: &Path,
    maximum_bytes: usize,
) -> Result<(String, bool)> {
    if !safe_regular_file_exists(path)? {
        return Ok((String::new(), false));
    }
    if fs::metadata(path)?.len() > maximum_bytes as u64 {
        bail!("findings file exceeds the rerun recovery size limit");
    }
    match fs::read_to_string(path) {
        Ok(raw) if raw.len() <= maximum_bytes => Ok((raw, true)),
        Ok(_) => bail!("findings file exceeds the rerun recovery size limit"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A race with deletion is an absent original; no live bytes were
            // staged yet, and the journal will accurately record that state.
            Ok((String::new(), false))
        }
        Err(error) => Err(error.into()),
    }
}

/// Scanner names come from a closed internal enum today, but rejecting blank and
/// multiline names keeps the transaction key aligned with the single-line
/// formatter/parser format if that ever changes.
fn validated_scanner_name(scanner: &str) -> Result<&str> {
    if scanner.is_empty() || scanner != scanner.trim() || scanner.contains(['\r', '\n']) {
        bail!("scanner name must be non-empty and single-line");
    }
    Ok(scanner)
}

/// The canonical formatter is the identity boundary for persisted findings: it
/// applies the same newline neutralization and parser-compatible representation
/// used for on-disk output.
fn findings_identical(left: &Finding, right: &Finding, cwe_template: &str) -> bool {
    format_finding_block(left, cwe_template) == format_finding_block(right, cwe_template)
}

fn deduplicate_findings(findings: &mut Vec<Finding>, cwe_template: &str) {
    let mut unique = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        if !unique
            .iter()
            .any(|existing| findings_identical(existing, &finding, cwe_template))
        {
            unique.push(finding);
        }
    }
    *findings = unique;
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
            screening =
                crate::state::finding::Screening::parse(v.split_whitespace().next().unwrap_or(""));
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
        assert_eq!(
            f.screening,
            Some(crate::state::finding::Screening::Disputed)
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        chat::{ChatAction, ConfirmedChatAction, FocusFragment, FocusScope},
        ScannerType,
    };
    use tempfile::TempDir;

    fn finding(scanner: &str, title: &str) -> Finding {
        Finding {
            scanner: scanner.into(),
            severity: Severity::High,
            title: title.into(),
            description: format!("description for {title}"),
            location: Some(format!("src/{title}.rs:1")),
            recommendation: "fix it".into(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_score: None,
            cvss_vector: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        }
    }

    fn seeded_writer() -> (TempDir, StateWriter) {
        let root = tempfile::tempdir().unwrap();
        let writer = StateWriter::open(root.path(), true).unwrap();
        writer.write_finding(&finding("api", "old target")).unwrap();
        writer
            .write_finding(&finding("sast", "other scanner"))
            .unwrap();
        let mut carried = finding("incremental", "carried correlated");
        carried.corroborated_by = vec!["api".into(), "sast".into()];
        writer.write_finding(&carried).unwrap();
        (root, writer)
    }

    fn checkpoint_with_remaining_sast_proposal(
        proposal_id: uuid::Uuid,
    ) -> crate::agent::checkpoint::Checkpoint {
        let action = ConfirmedChatAction::new(
            proposal_id,
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        let mut checkpoint = crate::agent::checkpoint::Checkpoint::default();
        checkpoint.completed.insert("sast".into());
        checkpoint.confirmed_chat_actions.push(action);
        checkpoint
    }

    #[test]
    fn rerun_rollback_restores_exact_pre_rerun_file() {
        let (_root, writer) = seeded_writer();
        let before = writer.read_findings_raw().unwrap();

        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        assert!(parse_findings(&writer.read_findings_raw().unwrap())
            .iter()
            .all(|finding| finding.scanner != "api"));
        writer
            .write_finding(&finding("api", "partial replacement"))
            .unwrap();

        writer.rollback_findings_rerun(&staging).unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), before);
        assert_eq!(parse_findings(&before).len(), 3);
    }

    #[test]
    fn rerun_commit_replaces_only_target_and_deduplicates_emitted_output() {
        let (_root, writer) = seeded_writer();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        let replacement = finding("api", "new target");
        writer.write_finding(&replacement).unwrap();
        writer.write_finding(&replacement).unwrap();

        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        let findings = parse_findings(&writer.read_findings_raw().unwrap());
        let titles: Vec<_> = findings
            .iter()
            .map(|finding| finding.title.as_str())
            .collect();
        assert_eq!(
            titles
                .iter()
                .filter(|&&title| title == "new target")
                .count(),
            1
        );
        assert!(!titles.contains(&"old target"));
        assert!(titles.contains(&"other scanner"));
        assert!(titles.contains(&"carried correlated"));
        assert_eq!(findings.len(), 3, "no target or sibling duplicates");
        assert_eq!(
            findings
                .iter()
                .find(|finding| finding.title == "carried correlated")
                .unwrap()
                .corroborated_by,
            vec!["api".to_string(), "sast".to_string()]
        );
    }

    #[test]
    fn committed_rerun_rollback_restores_exact_pre_rerun_snapshot() {
        let (_root, writer) = seeded_writer();
        let before = writer.read_findings_raw().unwrap();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer
            .write_finding(&finding("api", "replacement"))
            .unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        assert_ne!(writer.read_findings_raw().unwrap(), before);

        writer.rollback_findings_rerun(&staging).unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), before);
    }

    #[test]
    fn committed_marker_live_write_failure_rolls_back_exact_original() {
        let (root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer.write_finding(&finding("api", "new target")).unwrap();
        let staged = writer.read_findings_raw().unwrap();

        // `write_atomic` writes a fixed sibling temp file. Occupying it with a
        // directory makes the persistence phase fail after commit has read and
        // reconstructed its candidate, without changing the staged findings file.
        let temp_path = root.path().join(".zentra/detailed-findings.md.tmp");
        fs::create_dir(&temp_path).unwrap();
        assert!(writer
            .commit_findings_rerun_pending_progress(&staging)
            .is_err());
        assert_eq!(writer.read_findings_raw().unwrap(), staged);
        fs::remove_dir(&temp_path).unwrap();
        writer.rollback_findings_rerun(&staging).unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), original);
    }

    #[test]
    fn rerun_keys_reject_ambiguous_names_and_support_multibyte_names() {
        let (_root, writer) = seeded_writer();
        assert!(writer.begin_findings_rerun("", &[]).is_err());
        assert!(writer
            .begin_findings_rerun("api\n**Scanner:** forged", &[])
            .is_err());
        let duplicate_proposal = uuid::Uuid::new_v4();
        assert!(writer
            .begin_findings_rerun("api", &[duplicate_proposal, duplicate_proposal])
            .is_err());

        writer
            .write_finding(&finding("sást", "old multibyte"))
            .unwrap();
        let staging = writer.begin_findings_rerun("sást", &[]).unwrap();
        writer
            .write_finding(&finding("sást", "new multibyte"))
            .unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        let findings = parse_findings(&writer.read_findings_raw().unwrap());
        assert!(findings
            .iter()
            .any(|finding| finding.title == "new multibyte"));
        assert!(!findings
            .iter()
            .any(|finding| finding.title == "old multibyte"));
    }

    #[test]
    fn staged_crash_recovery_restores_original_and_cleans_journal() {
        let (_root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let _staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer
            .write_finding(&finding("api", "partial after crash"))
            .unwrap();

        writer
            .recover_interrupted_findings_rerun(&crate::agent::checkpoint::Checkpoint::default())
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), original);
        assert!(!writer.rerun_journal_path().exists());
    }

    #[test]
    fn committed_crash_recovery_preserves_new_findings_before_cleanup() {
        let (_root, writer) = seeded_writer();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer.write_finding(&finding("api", "new target")).unwrap();
        let committed = writer.read_findings_raw().unwrap();

        // Simulate the durable committed marker immediately before the live-file
        // replacement/cleanup boundary. Recovery must finalize this state rather
        // than restoring the old target finding.
        let journal = FindingsRerunJournal::staged(
            &staging.scanner,
            &staging.proposal_ids,
            staging.pre_rerun_existed,
            &staging.pre_rerun_raw,
        )
        .unwrap()
        .committed(&committed)
        .unwrap();
        writer.write_rerun_journal_locked(&journal).unwrap();
        fs::write(
            writer.project_root().join(".zentra/detailed-findings.md"),
            "interrupted live replacement",
        )
        .unwrap();

        let mut checkpoint = crate::agent::checkpoint::Checkpoint::default();
        checkpoint.completed.insert("api".into());
        writer
            .recover_interrupted_findings_rerun(&checkpoint)
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), committed);
        assert!(!writer.rerun_journal_path().exists());
    }

    #[test]
    fn committed_journal_without_checkpoint_progress_restores_original() {
        let (_root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer.write_finding(&finding("api", "new target")).unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        assert!(writer.rerun_journal_path().exists());

        writer
            .recover_interrupted_findings_rerun(&crate::agent::checkpoint::Checkpoint::default())
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), original);
        assert!(!writer.rerun_journal_path().exists());
    }

    #[test]
    fn checkpoint_completion_with_remaining_proposal_restores_original() {
        let (_root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let proposal_id = uuid::Uuid::new_v4();
        let staging = writer.begin_findings_rerun("sast", &[proposal_id]).unwrap();
        writer
            .write_finding(&finding("sast", "new sast target"))
            .unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();

        writer
            .recover_interrupted_findings_rerun(&checkpoint_with_remaining_sast_proposal(
                proposal_id,
            ))
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), original);
    }

    #[test]
    fn finalize_requires_matching_committed_journal_token_and_proposals() {
        let (_root, writer) = seeded_writer();
        let proposal_id = uuid::Uuid::new_v4();
        let staging = writer.begin_findings_rerun("api", &[proposal_id]).unwrap();
        writer.write_finding(&finding("api", "new target")).unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        let mut mismatched = staging.clone();
        mismatched.proposal_ids = vec![uuid::Uuid::new_v4()];

        assert!(writer.finalize_findings_rerun(&mismatched).is_err());
        assert!(writer.rerun_journal_path().exists());
        writer.finalize_findings_rerun(&staging).unwrap();
        assert!(!writer.rerun_journal_path().exists());
    }

    #[test]
    fn finalize_cleanup_failure_leaves_recoverable_journal() {
        use std::sync::atomic::Ordering;

        let (_root, writer) = seeded_writer();
        let staging = writer.begin_findings_rerun("api", &[]).unwrap();
        writer.write_finding(&finding("api", "new target")).unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        let committed = writer.read_findings_raw().unwrap();
        let mut checkpoint = crate::agent::checkpoint::Checkpoint::default();
        checkpoint.completed.insert("api".into());
        writer
            .fail_next_journal_cleanup
            .store(true, Ordering::SeqCst);

        assert!(writer.finalize_findings_rerun(&staging).is_err());
        assert_eq!(writer.read_findings_raw().unwrap(), committed);
        assert!(writer.rerun_journal_path().exists());

        writer
            .recover_interrupted_findings_rerun(&checkpoint)
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), committed);
        assert!(!writer.rerun_journal_path().exists());
    }

    #[test]
    fn malformed_journal_fails_closed_without_changing_findings() {
        let (_root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        fs::write(writer.rerun_journal_path(), b"not a rerun journal").unwrap();

        assert!(writer
            .recover_interrupted_findings_rerun(&crate::agent::checkpoint::Checkpoint::default())
            .is_err());
        assert_eq!(writer.read_findings_raw().unwrap(), original);
    }

    #[test]
    fn second_begin_refuses_active_journal() {
        let (_root, writer) = seeded_writer();
        let _staging = writer.begin_findings_rerun("api", &[]).unwrap();
        assert!(writer.begin_findings_rerun("sast", &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_journal_fails_closed_without_changing_findings() {
        use std::os::unix::fs::symlink;

        let (root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let target = root.path().join("journal-target");
        fs::write(&target, b"not used").unwrap();
        symlink(&target, writer.rerun_journal_path()).unwrap();

        assert!(writer
            .recover_interrupted_findings_rerun(&crate::agent::checkpoint::Checkpoint::default())
            .is_err());
        assert_eq!(writer.read_findings_raw().unwrap(), original);
    }

    #[cfg(windows)]
    #[test]
    fn symlinked_journal_fails_closed_without_changing_findings() {
        use std::os::windows::fs::symlink_file;

        let (root, writer) = seeded_writer();
        let original = writer.read_findings_raw().unwrap();
        let target = root.path().join("journal-target");
        fs::write(&target, b"not used").unwrap();
        // Some Windows CI runners disable symlink creation for unprivileged
        // processes; the Unix test still exercises the fail-closed branch.
        if symlink_file(&target, writer.rerun_journal_path()).is_err() {
            return;
        }

        assert!(writer
            .recover_interrupted_findings_rerun(&crate::agent::checkpoint::Checkpoint::default())
            .is_err());
        assert_eq!(writer.read_findings_raw().unwrap(), original);
    }
}
