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
            let output = String::from_utf8_lossy(&out.stdout).to_string();
            truncate_output(output, 8000)
        }
    }
}

fn run_pip_audit() -> String {
    match Command::new("pip-audit").args(["--output", "json"]).output() {
        Err(_) => "pip-audit not installed — run 'pip install pip-audit'".to_string(),
        Ok(out) => {
            let output = String::from_utf8_lossy(&out.stdout).to_string();
            truncate_output(output, 8000)
        }
    }
}

fn run_go_audit() -> String {
    match Command::new("go").args(["list", "-json", "-m", "all"]).output() {
        Err(_) => "go not found in PATH".to_string(),
        Ok(out) => {
            let output = String::from_utf8_lossy(&out.stdout).to_string();
            truncate_output(output, 8000)
        }
    }
}

fn truncate_output(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    format!("{}\n... (truncated, {} bytes total)", &s[..max_bytes], s.len())
}
