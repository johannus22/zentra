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
}

const PARALLEL_SCANNERS: &[ScannerType] = &[
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
];

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
            let _ = self.state_writer.rewrite_findings(&merged);
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

        Ok(RunSummary { failed, delta })
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
