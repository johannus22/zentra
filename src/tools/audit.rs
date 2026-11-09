use serde_json::{json, Value};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn run_audit(tool: &str) -> String {
    match tool {
        "npm" => run_npm_audit(),
        "cargo" => run_cargo_audit(),
        "pip" => run_pip_audit(),
        "go" => run_go_audit(),
        other => format!(
            "Unknown audit tool: '{}'. Supported: npm, cargo, pip, go.",
            other
        ),
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
    match std::env::current_dir() {
        Ok(root) => run_cargo_audit_at(&root),
        Err(err) => audit_error(format!("Cannot determine project root: {err}"), None).to_string(),
    }
}

/// Audit only the existing lockfile, without invoking Cargo or loading project configuration.
pub fn run_cargo_audit_at(project_root: &Path) -> String {
    let result = (|| -> Result<Value, String> {
        let root = project_root.canonicalize().map_err(|e| e.to_string())?;
        let workspace = prepare_audit(&root)?;
        let binary = resolve_audit(&root, std::env::var_os("PATH").as_deref())?;
        let output = audit_command(&binary, workspace.path())
            .output()
            .map_err(|e| format!("Cannot execute cargo-audit: {e}"))?;
        Ok(handle_audit_output(&root, &output))
    })();
    result
        .unwrap_or_else(|err| audit_error(err, None))
        .to_string()
}

fn audit_result(status: &str, artifact: Option<&Path>) -> Value {
    json!({
        "status": status,
        "applicability": "lockfile-only: all recorded dependencies; not target, feature, or reachability analysis",
        "limitations": ["Yanked-crate checks disabled (--no-yanked)", "Uses the public RustSec advisory database",
            "Configuration isolation is not an OS sandbox; concurrent hostile filesystem mutation can race path checks"],
        "artifact_path": artifact.map(|p| p.to_string_lossy()),
        "coverage": "Agent context may truncate this response. The full raw artifact is authoritative; persisted matches are not guaranteed to become agent findings.",
    })
}

fn audit_error(message: String, artifact: Option<&Path>) -> Value {
    let mut result = audit_result("error", artifact);
    result["error"] = json!(message);
    result
}

fn prepare_audit(root: &Path) -> Result<tempfile::TempDir, String> {
    let lock = root.join("Cargo.lock");
    let meta = fs::symlink_metadata(&lock)
        .map_err(|e| format!("Existing regular Cargo.lock required: {e}"))?;
    if !meta.file_type().is_file() {
        return Err("Cargo.lock must be a regular file, not a symlink".into());
    }
    let bytes = fs::read(&lock).map_err(|e| format!("Cannot read Cargo.lock: {e}"))?;
    let workspace = tempfile::Builder::new()
        .prefix("zentra-audit-")
        .tempdir()
        .map_err(|e| format!("Cannot create isolated audit directory: {e}"))?;
    let isolated = workspace.path().canonicalize().map_err(|e| e.to_string())?;
    if isolated.starts_with(root) {
        return Err("Audit temporary directory must be outside the project".into());
    }
    for name in ["home", "config", "cargo", "tmp"] {
        fs::create_dir(workspace.path().join(name)).map_err(|e| e.to_string())?;
    }
    fs::write(workspace.path().join("gitconfig"), b"").map_err(|e| e.to_string())?;
    fs::write(workspace.path().join("Cargo.lock"), bytes).map_err(|e| e.to_string())?;
    Ok(workspace)
}

fn resolve_audit(root: &Path, path: Option<&OsStr>) -> Result<PathBuf, String> {
    if let Some(path) = path {
        for directory in std::env::split_paths(path) {
            if !directory.is_absolute() {
                continue;
            }
            let Ok(directory) = directory.canonicalize() else {
                continue;
            };
            if directory.starts_with(root) {
                continue;
            }
            let name = if cfg!(windows) {
                "cargo-audit.exe"
            } else {
                "cargo-audit"
            };
            let Ok(binary) = directory.join(name).canonicalize() else {
                continue;
            };
            if binary.starts_with(root) || !binary.is_file() {
                continue;
            }
            #[cfg(windows)]
            if !binary
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&binary)
                    .map(|m| m.permissions().mode() & 0o111 == 0)
                    .unwrap_or(true)
                {
                    continue;
                }
            }
            return Ok(binary);
        }
    }
    Err(
        "No trusted cargo-audit executable found on absolute PATH entries outside the project"
            .into(),
    )
}

fn audit_command(binary: &Path, workspace: &Path) -> Command {
    let mut command = Command::new(binary);
    command.current_dir(workspace).env_clear();
    #[cfg(windows)]
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("HOME", workspace.join("home"))
        .env("USERPROFILE", workspace.join("home"))
        .env("XDG_CONFIG_HOME", workspace.join("config"))
        .env("CARGO_HOME", workspace.join("cargo"))
        .env("TMPDIR", workspace.join("tmp"))
        .env("TMP", workspace.join("tmp"))
        .env("TEMP", workspace.join("tmp"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", workspace.join("gitconfig"))
        .args(["audit", "--json", "--color", "never", "--file"])
        .arg(workspace.join("Cargo.lock"))
        .arg("--db")
        .arg(workspace.join("advisory-db"))
        .args([
            "--url",
            "https://github.com/RustSec/advisory-db",
            "--no-yanked",
        ]);
    command
}

fn persist_audit(root: &Path, output: &Output) -> Result<PathBuf, String> {
    let mut directory = root.to_path_buf();
    for name in [".zentra", "reports"] {
        directory.push(name);
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        let meta = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !meta.file_type().is_dir()
            || directory.canonicalize().map_err(|e| e.to_string())? != directory
        {
            return Err("Report directory is a symlink or escapes the project".into());
        }
    }
    let mut file = tempfile::Builder::new()
        .prefix("cargo-audit-")
        .suffix(".json")
        .tempfile_in(&directory)
        .map_err(|e| e.to_string())?;
    // Byte arrays are authoritative, including non-UTF-8 output. Text fields aid inspection.
    let raw = json!({"exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
        "stdout_bytes": output.stdout, "stderr_bytes": output.stderr});
    serde_json::to_writer(&mut file, &raw).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.keep().map(|(_, path)| path).map_err(|e| e.to_string())
}

fn validate_finding(entry: &Value, vulnerability: bool) -> Result<(), String> {
    let object = entry.as_object().ok_or("Finding must be an object")?;
    let package = object
        .get("package")
        .and_then(Value::as_object)
        .ok_or("Missing package object")?;
    if !package.get("name").is_some_and(Value::is_string)
        || !package.get("version").is_some_and(Value::is_string)
    {
        return Err("Package name/version must be strings".into());
    }
    if vulnerability || object.get("advisory").is_some_and(|v| !v.is_null()) {
        let advisory = object
            .get("advisory")
            .and_then(Value::as_object)
            .ok_or("Missing advisory object")?;
        if !advisory.get("id").is_some_and(Value::is_string) {
            return Err("Missing advisory id".into());
        }
    }
    if vulnerability || object.get("versions").is_some_and(|v| !v.is_null()) {
        let versions = object
            .get("versions")
            .and_then(Value::as_object)
            .ok_or("Missing versions object")?;
        for key in ["patched", "unaffected"] {
            let ranges = versions
                .get(key)
                .and_then(Value::as_array)
                .ok_or("Missing version ranges")?;
            if !ranges.iter().all(Value::is_string) {
                return Err("Version ranges must be strings".into());
            }
        }
    }
    if object.get("denied").is_some_and(|v| !v.is_boolean()) {
        return Err("denied must be boolean".into());
    }
    Ok(())
}

fn validate_report(report: &Value) -> Result<bool, String> {
    let database = report
        .get("database")
        .and_then(Value::as_object)
        .ok_or("Missing database object")?;
    if !database.get("advisory-count").is_some_and(Value::is_u64) {
        return Err("Missing database advisory count".into());
    }
    for key in ["last-commit", "last-updated"] {
        if !database
            .get(key)
            .is_some_and(|v| v.is_null() || v.is_string())
        {
            return Err(format!("Missing or invalid database {key}"));
        }
    }
    if !report
        .get("lockfile")
        .and_then(|v| v.get("dependency-count"))
        .is_some_and(Value::is_u64)
    {
        return Err("Missing lockfile dependency count".into());
    }
    let settings = report
        .get("settings")
        .and_then(Value::as_object)
        .ok_or("Missing settings object")?;
    // These flags are deliberately absent from our invocation. A filtered report
    // would contradict the advertised all-lockfile coverage.
    for key in ["target_arch", "target_os", "ignore"] {
        if !settings
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return Err(format!("Missing or unexpectedly filtered setting: {key}"));
        }
    }
    if !settings.get("severity").is_some_and(Value::is_null) {
        return Err("Missing or unexpectedly filtered severity".into());
    }
    let informational = settings
        .get("informational_warnings")
        .and_then(Value::as_array)
        .ok_or("Missing informational warning settings")?;
    if !informational.iter().all(Value::is_string)
        || !["unsound", "unmaintained", "notice"]
            .iter()
            .all(|kind| informational.iter().any(|v| v.as_str() == Some(kind)))
    {
        return Err("Incomplete informational warning coverage".into());
    }
    let vulnerabilities = report
        .get("vulnerabilities")
        .and_then(Value::as_object)
        .ok_or("Missing vulnerabilities object")?;
    let found = vulnerabilities
        .get("found")
        .and_then(Value::as_bool)
        .ok_or("Missing found boolean")?;
    let count = vulnerabilities
        .get("count")
        .and_then(Value::as_u64)
        .ok_or("Missing unsigned count")?;
    let list = vulnerabilities
        .get("list")
        .and_then(Value::as_array)
        .ok_or("Missing vulnerability list")?;
    if count != list.len() as u64 || found == list.is_empty() {
        return Err("Inconsistent vulnerability count/found/list".into());
    }
    for entry in list {
        validate_finding(entry, true)?;
    }
    let warnings = report
        .get("warnings")
        .and_then(Value::as_object)
        .ok_or("Missing warnings object")?;
    let mut evidence = found;
    for entries in warnings.values() {
        for entry in entries
            .as_array()
            .ok_or("Warning categories must contain arrays")?
        {
            validate_finding(entry, false)?;
            evidence |= entry.get("denied").and_then(Value::as_bool) == Some(true);
        }
    }
    Ok(evidence)
}

fn handle_audit_output(root: &Path, output: &Output) -> Value {
    let artifact = match persist_audit(root, output) {
        Ok(path) => path,
        Err(e) => return audit_error(format!("Cannot persist full cargo-audit output: {e}"), None),
    };
    let parsed = serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| format!("Invalid cargo-audit JSON: {e}"))
        .and_then(|report| validate_report(&report).map(|evidence| (report, evidence)));
    match parsed {
        Err(e) => audit_error(e, Some(&artifact)),
        Ok((report, evidence)) => {
            let accepted = (output.status.code() == Some(0) && !evidence)
                || (output.status.code() == Some(1) && evidence);
            let mut result = if accepted {
                audit_result("complete", Some(&artifact))
            } else {
                audit_error(
                    format!("Unaccepted cargo-audit exit status: {}", output.status),
                    Some(&artifact),
                )
            };
            result["exit_code"] = json!(output.status.code());
            result["counts"] = json!({"vulnerabilities": report["vulnerabilities"]["count"],
                "warnings": report["warnings"].as_object().unwrap().values().map(|v| v.as_array().unwrap().len()).sum::<usize>()});
            result["vulnerabilities"] = report["vulnerabilities"].clone();
            result["vulnerabilities"]["list"] = Value::Array(
                report["vulnerabilities"]["list"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(compact_finding)
                    .collect(),
            );
            result["warnings"] = Value::Object(
                report["warnings"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(category, entries)| {
                        (
                            category.clone(),
                            Value::Array(
                                entries
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(compact_finding)
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            );
            result
        }
    }
}

fn compact_finding(entry: &Value) -> Value {
    let mut compact = entry.clone();
    // Long prose is available in the raw artifact. Keep all findings and their
    // identifiers, package metadata, and exact version ranges in the response.
    if let Some(advisory) = compact.get_mut("advisory").and_then(Value::as_object_mut) {
        advisory.remove("description");
    }
    compact
}

fn run_pip_audit() -> String {
    match Command::new("pip-audit")
        .args(["--output", "json"])
        .output()
    {
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
    match Command::new("govulncheck")
        .args(["-json", "./..."])
        .output()
    {
        Err(_) => {
            "govulncheck not installed — run 'go install golang.org/x/vuln/cmd/govulncheck@latest'"
                .to_string()
        }
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
    format!(
        "{}\n... (truncated, {} bytes total)",
        &s[..boundary],
        s.len()
    )
}

#[cfg(test)]
mod cargo_tests {
    use super::*;

    fn output(code: u32, value: &[u8]) -> Output {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;
        #[cfg(windows)]
        let status = std::process::ExitStatus::from_raw(code);
        #[cfg(unix)]
        let status = std::process::ExitStatus::from_raw((code as i32) << 8);
        Output {
            status,
            stdout: value.to_vec(),
            stderr: b"diagnostic\xff".to_vec(),
        }
    }

    fn clean() -> Value {
        json!({"database": {"advisory-count": 1, "last-commit": null, "last-updated": null},
            "lockfile": {"dependency-count": 1},
            "settings": {"target_arch": [], "target_os": [], "severity": null, "ignore": [],
                "informational_warnings": ["unsound", "unmaintained", "notice"]},
            "vulnerabilities": {"found": false, "count": 0, "list": []}, "warnings": {}})
    }

    fn finding() -> Value {
        json!({"advisory": {"id": "RUSTSEC-2026-0001", "title": "Example"},
            "package": {"name": "example", "version": "1.0.0"},
            "versions": {"patched": [">=1.2, <2", ">=3.0"], "unaffected": ["<0.8"]}})
    }

    fn handle(root: &Path, code: u32, value: &Value) -> Value {
        handle_audit_output(root, &output(code, &serde_json::to_vec(value).unwrap()))
    }

    #[test]
    fn lock_required_before_any_command() {
        let root = tempfile::tempdir().unwrap();
        let result: Value = serde_json::from_str(&run_cargo_audit_at(root.path())).unwrap();
        assert_eq!(result["status"], "error");
        assert!(result["error"].as_str().unwrap().contains("Cargo.lock"));
        fs::create_dir(root.path().join("Cargo.lock")).unwrap();
        assert!(prepare_audit(root.path()).is_err());
    }

    #[test]
    fn command_is_isolated_and_direct() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("Cargo.lock"), b"exact lock bytes").unwrap();
        let root = root.path().canonicalize().unwrap();
        let workspace = prepare_audit(&root).unwrap();
        assert!(!workspace.path().canonicalize().unwrap().starts_with(&root));
        assert_eq!(
            fs::read(workspace.path().join("Cargo.lock")).unwrap(),
            b"exact lock bytes"
        );
        let binary = workspace.path().join("cargo-audit");
        let command = audit_command(&binary, workspace.path());
        assert_eq!(command.get_program(), binary.as_os_str());
        assert_eq!(command.get_current_dir(), Some(workspace.path()));
        let args: Vec<_> = command
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &args[..5],
            &["audit", "--json", "--color", "never", "--file"]
        );
        assert_eq!(
            args[5],
            workspace.path().join("Cargo.lock").to_string_lossy()
        );
        assert_eq!(args[6], "--db");
        assert_eq!(
            args[7],
            workspace.path().join("advisory-db").to_string_lossy()
        );
        assert_eq!(
            &args[8..],
            &[
                "--url",
                "https://github.com/RustSec/advisory-db",
                "--no-yanked"
            ]
        );
        for (key, value) in command.get_envs() {
            let key = key.to_string_lossy();
            assert!(
                !key.starts_with("GIT_")
                    || key == "GIT_CONFIG_NOSYSTEM"
                    || key == "GIT_CONFIG_GLOBAL"
            );
            assert_ne!(key, "PATH");
            assert!(!Path::new(value.unwrap()).starts_with(&root));
        }
    }

    #[test]
    fn resolver_rejects_relative_and_repository_paths() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let name = if cfg!(windows) {
            "cargo-audit.exe"
        } else {
            "cargo-audit"
        };
        fs::write(root.join(name), b"untrusted").unwrap();
        let path = std::env::join_paths([Path::new("."), root.as_path()]).unwrap();
        assert!(resolve_audit(&root, Some(&path)).is_err());
    }

    #[test]
    fn statuses_are_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        assert_eq!(handle(&root, 0, &clean())["status"], "complete");
        assert_eq!(handle(&root, 1, &clean())["status"], "error");
        let mut report = clean();
        report["vulnerabilities"] = json!({"found": true, "count": 1, "list": [finding()]});
        assert_eq!(handle(&root, 0, &report)["status"], "error");
        assert_eq!(handle(&root, 1, &report)["status"], "complete");
        assert_eq!(handle(&root, 2, &report)["status"], "error");
        report = clean();
        report["warnings"]["unsound"] = json!([finding()]);
        let result = handle(&root, 0, &report);
        assert_eq!(result["status"], "complete");
        assert_eq!(result["warnings"], report["warnings"]);
        assert_eq!(handle(&root, 1, &report)["status"], "error");
        report["warnings"]["unsound"][0]["denied"] = json!(true);
        assert_eq!(handle(&root, 0, &report)["status"], "error");
        assert_eq!(handle(&root, 1, &report)["status"], "complete");
    }

    #[test]
    fn malformed_reports_are_saved_but_never_complete() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        for raw in [
            b"not json".as_slice(),
            b"{}",
            b"{\"vulnerabilities\":{\"found\":false,\"count\":0,\"list\":[]},\"warnings\":[]}",
        ] {
            let result = handle_audit_output(&root, &output(0, raw));
            assert_eq!(result["status"], "error");
            assert!(Path::new(result["artifact_path"].as_str().unwrap()).is_file());
        }
        let mut report = clean();
        report["vulnerabilities"]["count"] = json!(1);
        assert_eq!(handle(&root, 0, &report)["status"], "error");
        report = clean();
        report["warnings"]["unknown"] = json!([{}]);
        assert_eq!(handle(&root, 0, &report)["status"], "error");
    }

    #[test]
    fn full_output_and_late_findings_are_preserved_uniquely() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let mut report = clean();
        let mut first = finding();
        first["advisory"]["description"] = json!("x".repeat(9000));
        report["vulnerabilities"] = json!({"found": true, "count": 2, "list": [first, finding()]});
        report["warnings"] = json!({"unsound": [finding()], "future-category": [finding()]});
        let raw = serde_json::to_vec(&report).unwrap();
        let out = output(1, &raw);
        let result = handle_audit_output(&root, &out);
        assert_eq!(
            result["vulnerabilities"]["list"].as_array().unwrap().len(),
            2
        );
        assert_eq!(result["vulnerabilities"]["list"][1], finding());
        assert_eq!(
            result["vulnerabilities"]["list"][0]["versions"],
            finding()["versions"]
        );
        assert_eq!(result["warnings"], report["warnings"]);
        let saved: Value =
            serde_json::from_slice(&fs::read(result["artifact_path"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(saved["stdout_bytes"], json!(raw));
        assert_eq!(saved["stderr_bytes"], json!(out.stderr));
        assert_eq!(saved["exit_code"], 1);
        assert_ne!(
            handle_audit_output(&root, &out)["artifact_path"],
            result["artifact_path"]
        );
    }

    #[test]
    fn artifact_failure_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(".zentra"), b"blocked").unwrap();
        let result = handle(&root.path().canonicalize().unwrap(), 0, &clean());
        assert_eq!(result["status"], "error");
        assert!(result["error"].as_str().unwrap().contains("persist"));
    }

    #[test]
    fn incomplete_or_filtered_reports_are_errors() {
        for field in ["database", "lockfile", "settings"] {
            let mut report = clean();
            report.as_object_mut().unwrap().remove(field);
            assert!(validate_report(&report).is_err(), "{field}");
        }
        for field in [
            "target_arch",
            "target_os",
            "ignore",
            "informational_warnings",
        ] {
            let mut report = clean();
            report["settings"][field] = json!(["unexpected"]);
            assert!(validate_report(&report).is_err(), "{field}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_supply_lock_binary_or_artifact_directory() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        fs::write(other.path().join("lock"), b"lock").unwrap();
        symlink(other.path().join("lock"), root.join("Cargo.lock")).unwrap();
        assert!(prepare_audit(&root).is_err());
        fs::write(root.join("cargo-audit"), b"binary").unwrap();
        symlink(root.join("cargo-audit"), other.path().join("cargo-audit")).unwrap();
        assert!(resolve_audit(&root, Some(other.path().as_os_str())).is_err());
        symlink(other.path(), root.join(".zentra")).unwrap();
        assert_eq!(handle(&root, 0, &clean())["status"], "error");
    }
}
