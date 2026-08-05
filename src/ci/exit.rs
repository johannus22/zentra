use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::config::ProjectConfig;
use crate::state::{Finding, Severity};

/// Env var name for the CI fail threshold override. Read directly (rather than
/// through `resolve_fail_threshold`'s caller) by headless runners that have no
/// `.zentra/config.json` at all — mirrors the `ZENTRA_PROVIDER_*` convention.
pub const FAIL_THRESHOLD_ENV: &str = "ZENTRA_CI_FAIL_THRESHOLD";

pub fn should_fail_ci(findings: &[Finding], fail_threshold: Severity) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity.order() <= fail_threshold.order())
}

/// Resolve the minimum severity that blocks the PR/MR. `ZENTRA_CI_FAIL_THRESHOLD`
/// (env) overrides `fail_threshold` in `.zentra/config.json`, which overrides the
/// default of High (blocks High and Critical findings) — same precedence order
/// as the provider env vars in `commands::ci::provider_config_from_env`, so a
/// config value is never silently masked without an explicit override.
pub fn resolve_fail_threshold(
    env: &HashMap<String, String>,
    project_config: &ProjectConfig,
) -> Result<Severity> {
    if let Some(raw) = env
        .get(FAIL_THRESHOLD_ENV)
        .filter(|value| !value.trim().is_empty())
    {
        return Severity::parse(raw).ok_or_else(|| {
            anyhow!(
                "invalid {FAIL_THRESHOLD_ENV} '{raw}'. Use one of: critical, high, medium, low, info"
            )
        });
    }

    if let Some(raw) = project_config
        .fail_threshold
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return Severity::parse(raw).ok_or_else(|| {
            anyhow!(
                "invalid fail_threshold '{raw}' in .zentra/config.json. \
                 Use one of: critical, high, medium, low, info"
            )
        });
    }

    Ok(Severity::High)
}
