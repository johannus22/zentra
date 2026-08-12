use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::checkpoint::Checkpoint;
use crate::agent::scanner::ScannerAgent;
use crate::agent::{ScanEvent, ScannerType};
use crate::incremental::{is_arch_significant, reconcile, ChangeSet, ScanDelta};
use crate::provider::LLMProvider;
use crate::security::SecurityContext;
use crate::state::{Finding, StateWriter};
use crate::tools::ToolRegistry;

struct IncrementalCtx {
    prior: Vec<Finding>,
    change_set: ChangeSet,
}

pub struct RunSummary {
    pub failed: Vec<ScannerType>,
    pub delta: Option<ScanDelta>,
    /// What the agents actually read. A scan that read almost nothing must not
    /// be indistinguishable from a scan that found nothing.
    pub coverage: crate::agent::coverage::CoverageSummary,
}

const PARALLEL_SCANNERS: &[ScannerType] = &[
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
];

/// Which files a given scanner is restricted to on an incremental run.
/// SupplyChain is deliberately exempt: dependency CVE status can change with
/// zero local code changes, so scoping it to the diff would silently miss
/// newly-disclosed vulnerabilities in unchanged manifests.
fn incremental_scope_for(scanner_type: ScannerType, change_set: &ChangeSet) -> Option<Vec<String>> {
    match scanner_type {
        ScannerType::Sast | ScannerType::ApiScan | ScannerType::IacScan => {
            Some(change_set.impact.clone())
        }
        _ => None,
    }
}

pub struct OrchestratorAgent {
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,
    focus_context: Option<String>,
    security: SecurityContext,
    incremental: Option<IncrementalCtx>,
    /// The whole filtered repository, when pack mode is on. Every scanner opens
    /// with it instead of navigating, so it is shared behind one Arc.
    pack: Option<Arc<String>>,
    /// Resume checkpoint. `None` means start fresh and write one as the scan
    /// progresses (so a crash enables future resume). `Some(cp)` means skip
    /// scanners that the checkpoint records as completed.
    resume: Option<Checkpoint>,
    board: crate::agent::board::ObservationBoard,
}

impl OrchestratorAgent {
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            provider,
            tool_registry,
            state_writer,
            tx,
            cancel_token,
            focus_context: None,
            pack: None,
            security: SecurityContext::disabled(),
            incremental: None,
            resume: None,
            board: crate::agent::board::ObservationBoard::new(),
        }
    }

    pub fn with_focus_context(mut self, focus_context: Option<String>) -> Self {
        self.focus_context = focus_context;
        self
    }

    pub fn with_security(mut self, security: SecurityContext) -> Self {
        self.security = security;
        self
    }

    pub fn with_incremental(mut self, prior: Vec<Finding>, change_set: ChangeSet) -> Self {
        self.incremental = Some(IncrementalCtx { prior, change_set });
        self
    }

    /// Open every scanner with the whole filtered repository instead of a
    /// navigation prompt. The caller checks the budget first — by the time the
    /// pack reaches here it has already been shown to fit.
    pub fn with_pack(mut self, pack: Option<Arc<String>>) -> Self {
        self.pack = pack;
        self
    }

    /// Set the resume checkpoint. Pass `None` for a fresh scan (the orchestrator
    /// creates an empty checkpoint and writes to it as scanners complete). Pass
    /// `Some(cp)` to skip scanners that the checkpoint records as completed.
    pub fn with_resume(mut self, checkpoint: Option<Checkpoint>) -> Self {
        self.resume = checkpoint;
        self
    }

    pub async fn run(mut self, scanners: &[ScannerType]) -> Result<RunSummary> {
        let mut failed: Vec<ScannerType> = Vec::new();

        if self.resume.is_some() && self.incremental.is_some() {
            anyhow::bail!("--resume cannot be combined with incremental scanning");
        }
        let is_resume = self.resume.is_some();

        // Resolve the resume checkpoint. When `resume` is `None` (no --resume
        // flag), create a fresh empty one and write it as scanners complete, so
        // a crash enables a future resume. When `Some(cp)`, use the loaded
        // checkpoint and skip completed scanners.
        let zentra_dir = self.state_writer.project_root().join(".zentra");
        let mut checkpoint = self.resume.take().unwrap_or_default();

        // Record the scanner set for the current run in the checkpoint.
        if checkpoint.scanner_set.is_empty() {
            checkpoint.scanner_set = scanners.iter().map(|s| s.name().to_string()).collect();
            checkpoint.save(&zentra_dir);
        }

        // Phase 0: FrameworkAnalysis — builds .zentra/architecture.md for all subsequent scanners.
        // Skip on resume when the checkpoint marks "framework" and the architecture file exists.
        let skip_framework = checkpoint.is_completed(ScannerType::FrameworkAnalysis.name())
            && self.state_writer.architecture_exists();

        // A completed report is stale when any requested scanner before it will
        // run again. Invalidate it before replaying skipped events so the report
        // is regenerated from the current findings.
        let rerunning_pre_report = [
            ScannerType::FrameworkAnalysis,
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
        ]
        .iter()
        .any(|&scanner| {
            scanners.contains(&scanner)
                && match scanner {
                    ScannerType::FrameworkAnalysis => !skip_framework,
                    _ => !checkpoint.is_completed(scanner.name()),
                }
        });
        if scanners.contains(&ScannerType::Report)
            && rerunning_pre_report
            && checkpoint.completed.remove(ScannerType::Report.name())
        {
            checkpoint.updated_at = chrono::Utc::now().to_rfc3339();
            checkpoint.save(&zentra_dir);
        }

        // On resume, remove findings for every scanner that will run again.
        // An empty, valid checkpoint means no scanner completed, so it starts
        // with a clean findings set rather than appending to stale output.
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let all_findings = crate::state::parse_findings(&raw);
        let will_run = |scanner: ScannerType| match scanner {
            ScannerType::FrameworkAnalysis => {
                scanners.contains(&scanner) && !skip_framework
            }
            _ => scanners.contains(&scanner) && !checkpoint.is_completed(scanner.name()),
        };
        let kept: Vec<Finding> = if is_resume && checkpoint.completed.is_empty() {
            Vec::new()
        } else if is_resume {
            all_findings
                .iter()
                .filter(|finding| {
                    ![ScannerType::FrameworkAnalysis, ScannerType::ThreatModel,
                        ScannerType::Sast, ScannerType::SupplyChain, ScannerType::ApiScan,
                        ScannerType::IacScan, ScannerType::Report]
                        .iter()
                        .any(|&scanner| scanner.name() == finding.scanner && will_run(scanner))
                })
                .cloned()
                .collect()
        } else {
            all_findings.clone()
        };
        if (is_resume && checkpoint.completed.is_empty()) || kept.len() != all_findings.len() {
            let _ = self.state_writer.rewrite_findings(&kept);
        }

        // Replay skipped scanners through the same event channel as active
        // scanners. This keeps the TUI's terminal state and finding counters
        // complete during a resume.
        let skipped = [
            (
                ScannerType::FrameworkAnalysis,
                scanners.contains(&ScannerType::FrameworkAnalysis) && skip_framework,
            ),
            (
                ScannerType::ThreatModel,
                scanners.contains(&ScannerType::ThreatModel)
                    && checkpoint.is_completed(ScannerType::ThreatModel.name()),
            ),
            (
                ScannerType::Sast,
                scanners.contains(&ScannerType::Sast)
                    && checkpoint.is_completed(ScannerType::Sast.name()),
            ),
            (
                ScannerType::SupplyChain,
                scanners.contains(&ScannerType::SupplyChain)
                    && checkpoint.is_completed(ScannerType::SupplyChain.name()),
            ),
            (
                ScannerType::ApiScan,
                scanners.contains(&ScannerType::ApiScan)
                    && checkpoint.is_completed(ScannerType::ApiScan.name()),
            ),
            (
                ScannerType::IacScan,
                scanners.contains(&ScannerType::IacScan)
                    && checkpoint.is_completed(ScannerType::IacScan.name()),
            ),
            (
                ScannerType::Report,
                scanners.contains(&ScannerType::Report)
                    && checkpoint.is_completed(ScannerType::Report.name()),
            ),
        ];
        for (scanner, is_skipped) in skipped {
            if !is_skipped {
                continue;
            }
            self.tx.send(ScanEvent::ScannerStarted(scanner)).await.ok();
            for finding in &kept {
                if finding.scanner == scanner.name() {
                    self.tx
                        .send(ScanEvent::FindingAdded(finding.clone()))
                        .await
                        .ok();
                }
            }
            self.tx.send(ScanEvent::ScannerCompleted(scanner)).await.ok();
        }

        if !skip_framework && scanners.contains(&ScannerType::FrameworkAnalysis) {
            if self
                .run_llm_scanner(ScannerType::FrameworkAnalysis, None)
                .await
                .is_ok() && !self.cancel_token.is_cancelled()
            {
                checkpoint.mark_completed(&zentra_dir, ScannerType::FrameworkAnalysis.name());
            } else {
                failed.push(ScannerType::FrameworkAnalysis);
            }

            // Safety net: if the agent exhausted iterations without calling write_architecture,
            // write a minimal placeholder so Phase 0 won't re-trigger on the next scan.
            if self.state_writer.read_architecture().is_empty() {
                let _ = self.state_writer.write_architecture(
                    "# Framework Architecture Analysis\n\nAnalysis incomplete. \
                    Delete this file and re-run the scan to retry.",
                );
            }
        }

        // After Phase 0, post a summary observation for later scanners.
        let arch = self.state_writer.read_architecture();
        if !arch.is_empty() {
            self.board.post(crate::agent::board::Observation {
                scanner: "framework".to_string(),
                category: "architecture".to_string(),
                text: "Framework analysis completed. See .zentra/architecture.md for details."
                    .to_string(),
            });
        }

        // Read produced architecture; inject into every LLM scanner that follows
        let context = self.state_writer.read_architecture();
        let context_opt: Option<String> = if context.is_empty() {
            None
        } else {
            Some(context)
        };

        // Phase 1: ThreatModel — sequential. On incremental, skip unless
        // architecturally-significant files changed (carried forward otherwise).
        let skip_threat_model = checkpoint.is_completed(ScannerType::ThreatModel.name());
        let run_threat_model = !skip_threat_model
            && scanners.contains(&ScannerType::ThreatModel)
            && match &self.incremental {
                Some(ctx) => is_arch_significant(&ctx.change_set.changed),
                None => true,
            };
        if run_threat_model {
            if self
                .run_llm_scanner(ScannerType::ThreatModel, context_opt.as_deref())
                .await
                .is_ok() && !self.cancel_token.is_cancelled()
            {
                checkpoint.mark_completed(&zentra_dir, ScannerType::ThreatModel.name());
            } else {
                failed.push(ScannerType::ThreatModel);
            }
        }

        // After the threat model completes, post its findings as observations
        // for later scanners (SAST, API, IaC, Report).
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let threat_findings = crate::state::parse_findings(&raw)
            .into_iter()
            .filter(|f| f.scanner == "threat_model")
            .collect::<Vec<_>>();
        for f in &threat_findings {
            self.board.post(crate::agent::board::Observation {
                scanner: "threat_model".to_string(),
                category: "threat".to_string(),
                text: format!(
                    "{}: {}",
                    f.title,
                    f.description.chars().take(200).collect::<String>()
                ),
            });
        }

        // Phase 2: parallel scanners (SAST, SCA, API, IaC).
        // Skip scanners that the checkpoint records as completed.
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS
            .iter()
            .filter(|s| scanners.contains(s))
            .filter(|s| !checkpoint.is_completed(s.name()))
            .copied()
            .collect();

        if !parallel.is_empty() {
            let mut handles = Vec::new();
            let cancel_token = self.cancel_token.clone();
            for scanner_type in parallel {
                let provider = Arc::clone(&self.provider);
                let registry = Arc::clone(&self.tool_registry);
                let writer = Arc::clone(&self.state_writer);
                let tx = self.tx.clone();
                let ctx = context_opt.clone();
                let focus_ctx = self.focus_context.clone();
                let token = cancel_token.clone();
                let security = self.security.clone();
                let pack = self.pack.clone();
                let board = self.board.clone();
                let incremental_scope = self
                    .incremental
                    .as_ref()
                    .and_then(|ic| incremental_scope_for(scanner_type, &ic.change_set));
                handles.push((
                    scanner_type,
                    tokio::spawn(async move {
                        ScannerAgent::new_with_contexts(
                            scanner_type,
                            provider,
                            registry,
                            writer,
                            tx,
                            ctx,
                            focus_ctx,
                            token,
                        )
                        .with_security(security)
                        .with_incremental_scope(incremental_scope)
                        .with_pack(pack)
                        .with_board(board)
                        .run()
                        .await
                    }),
                ));
            }
            for (scanner_type, handle) in handles {
                match handle.await {
                    Ok(Ok(())) => {
                        if !self.cancel_token.is_cancelled() {
                            checkpoint.mark_completed(&zentra_dir, scanner_type.name());
                        } else {
                            failed.push(scanner_type);
                        }
                    }
                    Ok(Err(_)) => {
                        failed.push(scanner_type);
                    }
                    Err(e) => {
                        crate::logging::error(
                            "scan",
                            format!("scanner={scanner_type:?} task failed: {e}"),
                        );
                        self.tx
                            .send(ScanEvent::Error {
                                scanner: scanner_type,
                                message: format!("Scanner task failed: {}", e),
                            })
                            .await
                            .ok();
                        self.tx
                            .send(ScanEvent::ScannerCompleted(scanner_type))
                            .await
                            .ok();
                        failed.push(scanner_type);
                    }
                }
            }
        }

        // After Phase 2, post all findings so the report scanner can see the
        // full picture across every scanner.
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let all_findings = crate::state::parse_findings(&raw);
        for f in &all_findings {
            self.board.post(crate::agent::board::Observation {
                scanner: f.scanner.clone(),
                category: "finding".to_string(),
                text: format!(
                    "{}: {}",
                    f.title,
                    f.description.chars().take(200).collect::<String>()
                ),
            });
        }

        // Incremental reconciliation: merge fresh findings (just written by the
        // focused scanners) with the prior set, before correlation/report read them.
        let mut delta = None;
        if !is_resume {
            if let Some(ctx) = self.incremental.take() {
                let raw = self.state_writer.read_findings_raw().unwrap_or_default();
                let fresh = crate::state::parse_findings(&raw);
                let (merged, d) = reconcile(ctx.prior, fresh, &ctx.change_set);
                if let Err(e) = self.state_writer.rewrite_findings(&merged) {
                    crate::logging::warn(
                        "orchestrator",
                        format!("incremental reconcile: failed to rewrite findings: {e}"),
                    );
                }
                delta = Some(d);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 2.5: correlate/dedup findings before the report consumes them.
        // Best-effort — never fatal, and never drops findings on failure.
        // Never skipped on resume: it may need to process findings from re-run scanners.
        if scanners.contains(&ScannerType::Report) {
            let raw = self.state_writer.read_findings_raw().unwrap_or_default();
            let parsed = crate::state::parse_findings(&raw);
            if parsed.len() > 1 {
                let merged =
                    crate::agent::correlation::correlate(&self.provider, parsed, Some(&self.cancel_token))
                        .await;
                let _ = self.state_writer.rewrite_findings(&merged);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 2.6: screen the deduplicated set for reachability, so the report
        // consumes findings that carry a verdict. After correlation on purpose:
        // screening a duplicate twice would pay for the same issue twice.
        // Best-effort and annotate-only, like 2.5.
        // Never skipped on resume: it may need to process findings from re-run scanners.
        if scanners.contains(&ScannerType::Report) {
            let raw = self.state_writer.read_findings_raw().unwrap_or_default();
            let parsed = crate::state::parse_findings(&raw);
            if !parsed.is_empty() {
                let screened = crate::agent::screening::screen(
                    &self.provider,
                    self.state_writer.project_root(),
                    parsed,
                    Some(&self.cancel_token),
                )
                .await;
                let _ = self.state_writer.rewrite_findings(&screened);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 3: Report — sequential, runs last
        if !checkpoint.is_completed(ScannerType::Report.name())
            && scanners.contains(&ScannerType::Report)
        {
            if self
                .run_llm_scanner(ScannerType::Report, context_opt.as_deref())
                .await
                .is_ok() && !self.cancel_token.is_cancelled()
            {
                checkpoint.mark_completed(&zentra_dir, ScannerType::Report.name());
            } else {
                failed.push(ScannerType::Report);
            }
        }

        // Coverage ledger, written last so it reflects every scanner. Reports
        // only — a thin scan never fails the run here, it just stops looking
        // like a clean one.
        let candidates =
            crate::tools::fs_tools::source_file_paths(self.state_writer.project_root());
        let coverage = self.tool_registry.coverage_snapshot(candidates.len());
        let never_read = self.tool_registry.never_read_snapshot(&candidates);
        if let Err(e) = self
            .state_writer
            .write_coverage(&crate::agent::coverage::render_markdown(
                &coverage,
                &never_read,
            ))
        {
            crate::logging::warn("orchestrator", format!("failed to write coverage.md: {e}"));
        }

        // A complete scan leaves no checkpoint behind. A scan with failures
        // leaves the checkpoint so the operator can resume the missing scanners.
        if failed.is_empty() && !self.cancel_token.is_cancelled() {
            Checkpoint::clear(&zentra_dir);
        }

        Ok(RunSummary {
            failed,
            delta,
            coverage,
        })
    }

    async fn run_llm_scanner(
        &self,
        scanner_type: ScannerType,
        context: Option<&str>,
    ) -> Result<()> {
        ScannerAgent::new_with_contexts(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
            context.map(str::to_string),
            self.focus_context.clone(),
            self.cancel_token.clone(),
        )
        .with_security(self.security.clone())
        .with_pack(self.pack.clone())
        .with_board(self.board.clone())
        .run()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change_set(impact: &[&str]) -> ChangeSet {
        ChangeSet {
            changed: vec![],
            impact: impact.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn scopes_sast_api_and_iac_but_not_supply_chain_or_others() {
        let cs = change_set(&["src/a.rs", "src/b.rs"]);
        let expected = Some(vec!["src/a.rs".to_string(), "src/b.rs".to_string()]);

        assert_eq!(incremental_scope_for(ScannerType::Sast, &cs), expected);
        assert_eq!(incremental_scope_for(ScannerType::ApiScan, &cs), expected);
        assert_eq!(incremental_scope_for(ScannerType::IacScan, &cs), expected);

        assert_eq!(incremental_scope_for(ScannerType::SupplyChain, &cs), None);
        assert_eq!(incremental_scope_for(ScannerType::ThreatModel, &cs), None);
        assert_eq!(incremental_scope_for(ScannerType::Report, &cs), None);
        assert_eq!(incremental_scope_for(ScannerType::FrameworkAnalysis, &cs), None);
    }
}
