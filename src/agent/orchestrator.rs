use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{ScanEvent, ScannerType};
use crate::agent::scanner::ScannerAgent;
use crate::provider::LLMProvider;
use crate::scanners::secrets::{HistoryDepth, SecretScanner};
use crate::state::StateWriter;
use crate::tools::ToolRegistry;

const PARALLEL_SCANNERS: &[ScannerType] = &[
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
    ScannerType::SecretsScan,
];

pub struct OrchestratorAgent {
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
    depth: HistoryDepth,
}

impl OrchestratorAgent {
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        depth: HistoryDepth,
    ) -> Self {
        Self { provider, tool_registry, state_writer, tx, depth }
    }

    pub async fn run(self, scanners: &[ScannerType]) -> Result<()> {
        // Phase 0: FrameworkAnalysis — builds .zentra/context.md for all subsequent scanners
        if scanners.contains(&ScannerType::FrameworkAnalysis) {
            self.run_llm_scanner(ScannerType::FrameworkAnalysis, None).await?;
        }

        // Read the produced context; inject into every LLM scanner that follows
        let context = self.state_writer.read_context();
        let context_opt: Option<String> = if context.is_empty() { None } else { Some(context) };

        // Phase 1: ThreatModel — sequential
        if scanners.contains(&ScannerType::ThreatModel) {
            self.run_llm_scanner(ScannerType::ThreatModel, context_opt.as_deref()).await?;
        }

        // Phase 2: parallel scanners (SAST, SCA, API, IaC, Secrets)
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS
            .iter()
            .filter(|s| scanners.contains(s))
            .copied()
            .collect();

        if !parallel.is_empty() {
            let mut handles = Vec::new();
            for scanner_type in parallel {
                if scanner_type == ScannerType::SecretsScan {
                    // Secrets scanner is deterministic — no context injection needed
                    let writer = Arc::clone(&self.state_writer);
                    let tx = self.tx.clone();
                    let depth = self.depth.clone();
                    let root = writer.project_root().to_path_buf();
                    handles.push(tokio::spawn(async move {
                        SecretScanner::new(root, depth, tx)
                            .run(&writer)
                            .await
                            .map(|_| ())
                    }));
                } else {
                    let provider = Arc::clone(&self.provider);
                    let registry = Arc::clone(&self.tool_registry);
                    let writer = Arc::clone(&self.state_writer);
                    let tx = self.tx.clone();
                    let ctx = context_opt.clone();
                    handles.push(tokio::spawn(async move {
                        ScannerAgent::new(scanner_type, provider, registry, writer, tx, ctx)
                            .run()
                            .await
                    }));
                }
            }
            for handle in handles {
                handle.await??;
            }
        }

        // Phase 3: Report — sequential, runs last
        if scanners.contains(&ScannerType::Report) {
            self.run_llm_scanner(ScannerType::Report, context_opt.as_deref()).await?;
        }

        Ok(())
    }

    async fn run_llm_scanner(&self, scanner_type: ScannerType, context: Option<&str>) -> Result<()> {
        ScannerAgent::new(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
            context.map(str::to_string),
        )
        .run()
        .await
    }
}
