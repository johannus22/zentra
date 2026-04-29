use std::process::Command;

pub fn run_audit(tool: &str) -> String {
    match tool {
        "npm" => run_npm_audit(),
        "cargo" => run_cargo_audit(),
        "pip" => run_pip_audit(),
        "go" => run_go_audit(),
        other => format!("Unknown audit tool: '{}'. Supported: npm, cargo, pip, go.", other),
    }
}

fn run_npm_audit() -> String {
    match Command::new("npm").args(["audit", "--json"]).output() {
        Err(_) => "npm not found — falling back to package.json analysis".to_string(),
        Ok(out) => {
            let json_str = String::from_utf8_lossy(&out.stdout).to_string();
            if json_str.trim().is_empty() {
                "npm audit returned no output (no package-lock.json?)".to_string()
            } else {
                truncate_output(json_str, 8000)
            }
        }
    }
}

fn run_cargo_audit() -> String {
    match Command::new("cargo").args(["audit", "--json"]).output() {
        Err(_) => "cargo-audit not installed — run 'cargo install cargo-audit'".to_string(),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            if stdout.trim().is_empty() {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if stderr.trim().is_empty() {
                    "cargo audit returned no output".to_string()
                } else {
                    format!("cargo audit error: {}", stderr.trim())
                }
            } else {
                truncate_output(stdout, 8000)
            }
        }
    }
}

fn run_pip_audit() -> String {
    match Command::new("pip-audit").args(["--output", "json"]).output() {
        Err(_) => "pip-audit not installed — run 'pip install pip-audit'".to_string(),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            if stdout.trim().is_empty() {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if stderr.trim().is_empty() {
                    "pip-audit returned no output".to_string()
                } else {
                    format!("pip-audit error: {}", stderr.trim())
                }
            } else {
                truncate_output(stdout, 8000)
            }
        }
    }
}

fn run_go_audit() -> String {
    match Command::new("govulncheck").args(["-json", "./..."]).output() {
        Err(_) => "govulncheck not installed — run 'go install golang.org/x/vuln/cmd/govulncheck@latest'".to_string(),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            if stdout.trim().is_empty() {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if stderr.trim().is_empty() {
                    "govulncheck returned no output".to_string()
                } else {
                    format!("govulncheck error: {}", stderr.trim())
                }
            } else {
                truncate_output(stdout, 8000)
            }
        }
    }
}

fn truncate_output(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let boundary = s.floor_char_boundary(max_bytes);
    format!("{}\n... (truncated, {} bytes total)", &s[..boundary], s.len())
}
