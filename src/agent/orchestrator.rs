use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::scanner::ScannerAgent;
use crate::agent::{ScanEvent, ScannerType};
use crate::provider::LLMProvider;
use crate::state::StateWriter;
use crate::tools::ToolRegistry;

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
        }
    }

    pub async fn run(self, scanners: &[ScannerType]) -> Result<()> {
        // Phase 0: FrameworkAnalysis — builds .zentra/architecture.md for all subsequent scanners
        if scanners.contains(&ScannerType::FrameworkAnalysis) {
            let _ = self
                .run_llm_scanner(ScannerType::FrameworkAnalysis, None)
                .await;

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

        // Phase 1: ThreatModel — sequential
        if scanners.contains(&ScannerType::ThreatModel) {
            let _ = self
                .run_llm_scanner(ScannerType::ThreatModel, context_opt.as_deref())
                .await;
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
                let token = cancel_token.clone();
                handles.push((
                    scanner_type,
                    tokio::spawn(async move {
                        ScannerAgent::new(scanner_type, provider, registry, writer, tx, ctx, token)
                            .run()
                            .await
                    }),
                ));
            }
            for (scanner_type, handle) in handles {
                match handle.await {
                    Ok(Ok(())) | Ok(Err(_)) => {}
                    Err(e) => {
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
                    }
                }
            }
        }

        // Phase 3: Report — sequential, runs last
        if scanners.contains(&ScannerType::Report) {
            let _ = self
                .run_llm_scanner(ScannerType::Report, context_opt.as_deref())
                .await;
        }

        Ok(())
    }

    async fn run_llm_scanner(
        &self,
        scanner_type: ScannerType,
        context: Option<&str>,
    ) -> Result<()> {
        ScannerAgent::new(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
            context.map(str::to_string),
            self.cancel_token.clone(),
        )
        .run()
        .await
    }
}
