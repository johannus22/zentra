use crate::agent::{ScanEvent, ScannerType};
use crate::agent::scanner::ScannerAgent;
use crate::provider::LLMProvider;
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

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
}

impl OrchestratorAgent {
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
    ) -> Self {
        Self { provider, tool_registry, state_writer, tx }
    }

    pub async fn run(self, scanners: &[ScannerType]) -> Result<()> {
        // Phase 1: ThreatModel — always sequential, runs first
        if scanners.contains(&ScannerType::ThreatModel) {
            self.run_scanner(ScannerType::ThreatModel).await?;
        }

        // Phase 2: SAST, SCA, API, IaC — run in parallel
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS.iter()
            .filter(|s| scanners.contains(s))
            .copied()
            .collect();

        if !parallel.is_empty() {
            let mut handles = Vec::new();
            for scanner_type in parallel {
                let provider = Arc::clone(&self.provider);
                let registry = Arc::clone(&self.tool_registry);
                let writer = Arc::clone(&self.state_writer);
                let tx = self.tx.clone();
                handles.push(tokio::spawn(async move {
                    ScannerAgent::new(scanner_type, provider, registry, writer, tx).run().await
                }));
            }
            for handle in handles {
                handle.await??;
            }
        }

        // Phase 3: Report — always sequential, runs last
        if scanners.contains(&ScannerType::Report) {
            self.run_scanner(ScannerType::Report).await?;
        }

        Ok(())
    }

    async fn run_scanner(&self, scanner_type: ScannerType) -> Result<()> {
        ScannerAgent::new(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
        )
        .run()
        .await
    }
}
