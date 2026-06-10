use std::process::Command;

pub fn git_log(n: u32) -> String {
    run_git(&[
        "log",
        &format!("--max-count={}", n),
        "--oneline",
        "--no-color",
    ])
}

pub fn git_diff(since: &str) -> String {
    if since.len() > 100 {
        return "Error: 'since' argument too long (max 100)".to_string();
    }
    // Conservative git-revision charset — holds even when the tool gate is off.
    let allowed = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | '~' | '^' | '@' | ':')
    };
    if !since.chars().all(allowed) {
        return "Error: 'since' contains characters outside the allowed revision charset (alphanumeric and . - _ / ~ ^ @ :)".to_string();
    }
    run_git(&["diff", since, "--stat", "--no-color"])
}

pub fn git_blame(file: &str, line: u32) -> String {
    run_git(&[
        "blame",
        "-L",
        &format!("{},{}", line, line),
        "--porcelain",
        "--",
        file,
    ])
}

pub fn git_status() -> String {
    run_git(&["status", "--short", "--no-color"])
}

fn run_git(args: &[&str]) -> String {
    match Command::new("git").args(args).output() {
        Err(_) => "git not found in PATH".to_string(),
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                if stdout.trim().is_empty() {
                    "(no output)".to_string()
                } else {
                    stdout
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                if stderr.contains("not a git repository") {
                    "Not a git repository".to_string()
                } else {
                    format!("git error: {}", stderr.trim())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_diff_rejects_metacharacters() {
        let out = git_diff("HEAD;rm -rf /");
        assert!(out.starts_with("Error:"), "got: {out}");
    }

    #[test]
    fn git_diff_rejects_overlong() {
        let out = git_diff(&"a".repeat(200));
        assert!(out.starts_with("Error:"), "got: {out}");
    }
}
