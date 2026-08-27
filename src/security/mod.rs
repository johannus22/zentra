pub mod audit_log;
pub mod dual_provider;
pub mod prompt_guard;
pub mod response_binding;
pub mod tool_gate;

pub use audit_log::{AuditEvent, AuditLog, VerifyResult};
pub use prompt_guard::PromptGuard;
pub use tool_gate::SecurityGate;

use crate::provider::{
    AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, ToolDefinition,
};
use anyhow::Result;
use async_trait::async_trait;
use rand::RngCore;
use response_binding::ResponseBindingVerifier;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Feature flags controlling the security envelope. Cloneable and cheap to pass
/// through agent construction.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Tamper-evident hash-chain audit log of all LLM/tool activity.
    pub audit_log: bool,
    /// Nonce echo verification on LLM responses (MITM / replay defense).
    pub response_binding: bool,
    /// When true, a tool-call-only response with empty text is rejected if it
    /// cannot carry the nonce. When false, that case is logged but allowed.
    pub response_binding_strict: bool,
    pub nonce_max_age_secs: u64,
    /// Per-scanner allowlist, rate limit, behavioral checks, and arg validation.
    pub tool_gate: bool,
    /// Tag external tool output and scan it for injection patterns.
    pub prompt_guard: bool,
    /// Abort the scan once the injection-attempt count crosses the threshold.
    pub prompt_guard_abort: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::load()
    }
}

impl SecurityConfig {
    /// Balanced defaults: strong defense-in-depth that won't break a legitimate
    /// scan. Audit + tool gate + prompt-guard tagging are on; the higher-friction
    /// controls (nonce binding, abort-on-injection) are opt-in.
    ///
    /// Overridable via the `ZENTRA_SECURITY` env var: `off`, `hardened`.
    pub fn load() -> Self {
        match std::env::var("ZENTRA_SECURITY").ok().as_deref() {
            Some("off") => Self::trusted_local(),
            Some("hardened") => Self::hardened(),
            _ => Self {
                audit_log: true,
                response_binding: false,
                response_binding_strict: false,
                nonce_max_age_secs: 120,
                tool_gate: true,
                prompt_guard: true,
                prompt_guard_abort: false,
            },
        }
    }

    /// Everything on, strictest settings. For high-assurance / untrusted networks.
    pub fn hardened() -> Self {
        Self {
            audit_log: true,
            response_binding: true,
            response_binding_strict: true,
            nonce_max_age_secs: 120,
            tool_gate: true,
            prompt_guard: true,
            prompt_guard_abort: true,
        }
    }

    /// Everything off — minimal overhead for trusted local development.
    pub fn trusted_local() -> Self {
        Self {
            audit_log: false,
            response_binding: false,
            response_binding_strict: false,
            nonce_max_age_secs: 120,
            tool_gate: false,
            prompt_guard: false,
            prompt_guard_abort: false,
        }
    }
}

/// Shared security state threaded through the orchestrator into each scanner.
#[derive(Clone)]
pub struct SecurityContext {
    pub config: SecurityConfig,
    pub audit: Arc<Mutex<AuditLog>>,
}

impl SecurityContext {
    pub fn new(config: SecurityConfig, audit: AuditLog) -> Self {
        Self {
            config,
            audit: Arc::new(Mutex::new(audit)),
        }
    }

    /// A disabled context that allocates no audit file. Used by call paths that
    /// have not yet opted into the security envelope.
    pub fn disabled() -> Self {
        let cfg = SecurityConfig::trusted_local();
        let audit = AuditLog::new(std::path::Path::new("."), "disabled", false)
            .expect("disabled audit log never touches the filesystem");
        Self::new(cfg, audit)
    }

    pub fn record(&self, event: AuditEvent) {
        if let Ok(mut log) = self.audit.lock() {
            let _ = log.record(event);
        }
    }

    pub fn gate(&self, scanner: crate::agent::ScannerType) -> SecurityGate {
        SecurityGate::new(scanner, self.config.tool_gate)
    }

    /// Dedicated least-privilege policy for interactive chat. It never maps chat
    /// to a scanner type, so scanner write/process capabilities cannot leak.
    pub fn chat_gate(&self) -> SecurityGate {
        SecurityGate::chat(self.config.tool_gate)
    }

    pub fn prompt_guard(&self) -> PromptGuard {
        PromptGuard::new(self.config.prompt_guard)
    }
}

/// Generate a random hex session identifier.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Wraps any `LLMProvider` to add nonce binding and audit logging around each
/// agent-mode completion. Transparent to callers — it *is* an `LLMProvider`.
pub struct GuardedProvider {
    inner: Arc<dyn LLMProvider>,
    verifier: Mutex<ResponseBindingVerifier>,
    audit: Arc<Mutex<AuditLog>>,
    request_counter: AtomicU64,
    config: SecurityConfig,
}

impl GuardedProvider {
    /// Wrap `inner`. Returns the inner provider unchanged if no provider-level
    /// control is enabled, avoiding needless overhead.
    pub fn wrap(inner: Arc<dyn LLMProvider>, ctx: &SecurityContext) -> Arc<dyn LLMProvider> {
        if !ctx.config.audit_log && !ctx.config.response_binding && !ctx.config.prompt_guard {
            return inner;
        }
        Arc::new(Self {
            inner,
            verifier: Mutex::new(ResponseBindingVerifier::new(
                ctx.config.nonce_max_age_secs,
                ctx.config.response_binding,
            )),
            audit: Arc::clone(&ctx.audit),
            request_counter: AtomicU64::new(0),
            config: ctx.config.clone(),
        })
    }

    fn record(&self, event: AuditEvent) {
        if let Ok(mut log) = self.audit.lock() {
            let _ = log.record(event);
        }
    }
}

#[async_trait]
impl LLMProvider for GuardedProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        self.inner.complete(req).await
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        let request_id = self.request_counter.fetch_add(1, Ordering::SeqCst);

        // Build the effective system prompt: trust-boundary instructions first,
        // then a per-request nonce the model is asked to echo back.
        let mut effective_system = system.to_string();
        if self.config.prompt_guard {
            effective_system.push_str(PromptGuard::system_addendum());
        }
        if self.config.response_binding {
            let nonce = self
                .verifier
                .lock()
                .expect("nonce verifier mutex poisoned")
                .issue_nonce(request_id);
            effective_system = response_binding::inject_into_system(&nonce, &effective_system);
        }

        self.record(AuditEvent::LlmRequest {
            request_id,
            prompt_hash: audit_log::sha256_str(&format!("{}|{:?}", system, messages)),
        });

        let resp = self
            .inner
            .complete_with_tools(&effective_system, messages, tools, max_tokens, cancel_token)
            .await?;

        // Verify the nonce echo. A tool-call-only response often has empty text
        // and cannot carry the nonce: reject only in strict mode.
        let nonce_verified = if self.config.response_binding {
            if resp.content.trim().is_empty() && !resp.tool_calls.is_empty() {
                if self.config.response_binding_strict {
                    self.record(AuditEvent::SecurityViolation {
                        category: "response_binding".to_string(),
                        detail: "tool-call-only response carried no nonce (strict)".to_string(),
                    });
                    self.record(AuditEvent::LlmResponse {
                        request_id,
                        nonce_verified: false,
                        tool_call_count: resp.tool_calls.len(),
                    });
                    anyhow::bail!(
                        "Response binding failed: tool-call-only response carried no nonce"
                    );
                }
                self.record(AuditEvent::SecurityViolation {
                    category: "response_binding".to_string(),
                    detail: "tool-call-only response carried no nonce (allowed)".to_string(),
                });
                false
            } else {
                match self
                    .verifier
                    .lock()
                    .expect("nonce verifier mutex poisoned")
                    .verify(request_id, &resp.content)
                {
                    Ok(()) => true,
                    Err(e) => {
                        self.record(AuditEvent::SecurityViolation {
                            category: "response_binding".to_string(),
                            detail: e.to_string(),
                        });
                        self.record(AuditEvent::LlmResponse {
                            request_id,
                            nonce_verified: false,
                            tool_call_count: resp.tool_calls.len(),
                        });
                        anyhow::bail!("Response binding verification failed: {}", e);
                    }
                }
            }
        } else {
            false
        };

        self.record(AuditEvent::LlmResponse {
            request_id,
            nonce_verified,
            tool_call_count: resp.tool_calls.len(),
        });

        Ok(resp)
    }

    fn context_window(&self) -> u32 {
        self.inner.context_window()
    }

    fn model_name(&self) -> &str {
        self.inner.model_name()
    }
}
