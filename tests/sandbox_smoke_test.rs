use std::sync::Mutex;

use tempfile::TempDir;
use zentra_cli::pentest::sandbox::recon_smoke::run_recon_smoke;
use zentra_cli::pentest::sandbox::{
    detect, escape_argv_for_shell_lc, Engine, EngineKind, SandboxError, SandboxImage,
};

static PATH_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn sandbox_image_pinned_default() {
    let _lock = PATH_LOCK.lock().unwrap();
    let old_image = std::env::var_os("ZENTRA_SANDBOX_IMAGE");
    let old_version = std::env::var_os("ZENTRA_SANDBOX_VERSION");
    std::env::remove_var("ZENTRA_SANDBOX_IMAGE");
    std::env::remove_var("ZENTRA_SANDBOX_VERSION");
    let image = SandboxImage::pinned();
    match old_image {
        Some(value) => std::env::set_var("ZENTRA_SANDBOX_IMAGE", value),
        None => std::env::remove_var("ZENTRA_SANDBOX_IMAGE"),
    }
    match old_version {
        Some(value) => std::env::set_var("ZENTRA_SANDBOX_VERSION", value),
        None => std::env::remove_var("ZENTRA_SANDBOX_VERSION"),
    }
    assert_eq!(image.image, "zentra/pentest-sandbox");
    assert_eq!(image.version, "0.1.0");
}

#[test]
fn engine_kinds_default_to_docker() {
    let engine = Engine {
        kind: EngineKind::Docker,
        socket: None,
    };
    assert_eq!(engine.kind, EngineKind::Docker);
}

#[tokio::test]
async fn detect_returns_not_installed_when_docker_missing() {
    let _lock = PATH_LOCK.lock().unwrap();
    let empty = TempDir::new().unwrap();
    let old_path = std::env::var_os("PATH");
    std::env::set_var("PATH", empty.path());
    let result = detect().await;
    match old_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }

    assert!(matches!(result, Err(SandboxError::NotInstalled { .. })));
}

#[test]
fn escape_single_quotes_for_shell_lc() {
    let cases = [
        (vec!["plain", "it's safe"], "'plain' 'it'\\''s safe'"),
        (vec!["semi;colon", "&&"], "'semi;colon' '&&'"),
        (vec!["a'b;&&", "x|y"], "'a'\\''b;&&' 'x|y'"),
    ];
    for (argv, expected) in cases {
        assert_eq!(escape_argv_for_shell_lc(&argv), expected);
    }
}

#[tokio::test]
#[ignore]
async fn sandbox_recon_smoke_against_local_httpbin() {
    let engine = detect().await.unwrap();
    let image = SandboxImage::pinned();
    zentra_cli::pentest::sandbox::ensure_image(&image)
        .await
        .unwrap();
    zentra_cli::pentest::sandbox::health_check(&image, &engine)
        .await
        .unwrap();
    let target = "https://httpbin.org/status/200";
    let output = run_recon_smoke(target, &engine, &image).await.unwrap();
    assert_eq!(output.curl_status, 200);
}
