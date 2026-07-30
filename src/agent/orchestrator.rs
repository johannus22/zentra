use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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
            security: SecurityContext::disabled(),
            incremental: None,
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

    pub async fn run(mut self, scanners: &[ScannerType]) -> Result<RunSummary> {
        let mut failed: Vec<ScannerType> = Vec::new();

        // Phase 0: FrameworkAnalysis — builds .zentra/architecture.md for all subsequent scanners
        if scanners.contains(&ScannerType::FrameworkAnalysis) {
            if self
                .run_llm_scanner(ScannerType::FrameworkAnalysis, None)
                .await
                .is_err()
            {
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

        // Read produced architecture; inject into every LLM scanner that follows
        let context = self.state_writer.read_architecture();
        let context_opt: Option<String> = if context.is_empty() {
            None
        } else {
            Some(context)
        };

        // Phase 1: ThreatModel — sequential. On incremental, skip unless
        // architecturally-significant files changed (carried forward otherwise).
        let run_threat_model = scanners.contains(&ScannerType::ThreatModel)
            && match &self.incremental {
                Some(ctx) => is_arch_significant(&ctx.change_set.changed),
                None => true,
            };
        if run_threat_model {
            if self
                .run_llm_scanner(ScannerType::ThreatModel, context_opt.as_deref())
                .await
                .is_err()
            {
                failed.push(ScannerType::ThreatModel);
            }
        }

        // Phase 2: parallel scanners (SAST, SCA, API, IaC)
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS
            .iter()
            .filter(|s| scanners.contains(s))
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
                        .run()
                        .await
                    }),
                ));
            }
            for (scanner_type, handle) in handles {
                match handle.await {
                    Ok(Ok(())) => {}
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

        // Incremental reconciliation: merge fresh findings (just written by the
        // focused scanners) with the prior set, before correlation/report read them.
        let mut delta = None;
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

        // Phase 2.5: correlate/dedup findings before the report consumes them.
        // Best-effort — never fatal, and never drops findings on failure.
        if scanners.contains(&ScannerType::Report) {
            let raw = self.state_writer.read_findings_raw().unwrap_or_default();
            let parsed = crate::state::parse_findings(&raw);
            if parsed.len() > 1 {
                let merged = crate::agent::correlation::correlate(&self.provider, parsed).await;
                let _ = self.state_writer.rewrite_findings(&merged);
            }
        }

        // Phase 3: Report — sequential, runs last
        if scanners.contains(&ScannerType::Report) {
            if self
                .run_llm_scanner(ScannerType::Report, context_opt.as_deref())
                .await
                .is_err()
            {
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
