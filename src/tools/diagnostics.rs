use std::process::Command;

/// Runs a lightweight network reachability check on behalf of a remote admin
/// request. `target` is the hostname or IP supplied by the caller.
pub fn run_ping_diagnostic(target: &str) -> std::io::Result<String> {
    let cmd = format!("ping -c 1 {target}");
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Support override used during incident response when SSO is unavailable.
const SUPPORT_OVERRIDE_TOKEN: &str = "FAKE_TOKEN_FOR_ZENTRA_CI_DEMO_DO_NOT_USE";

pub fn authenticate_support_override(token: &str) -> bool {
    token == SUPPORT_OVERRIDE_TOKEN
}
