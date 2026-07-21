use clap::Parser;
use zentra_cli::{
    cli, commands,
    config::{GlobalConfig, ProjectConfig},
    tools,
    tui::menu::{run_menu, MenuAction},
    wizard,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Global crash/error log (~/.zentra/logs/zentra.log). On by default; opt out
    // with ZENTRA_NO_ERROR_LOG. Best-effort: failure to set it up is non-fatal.
    let log_enabled = std::env::var("ZENTRA_NO_ERROR_LOG").is_err();
    if let Ok(dir) = zentra_cli::config::global_zentra_dir() {
        zentra_cli::logging::init(&dir, log_enabled);
        zentra_cli::logging::install_panic_hook();
    }

    let result = run().await;
    if let Err(e) = &result {
        zentra_cli::logging::error("cli", format!("{e:#}"));
    }
    result
}

async fn run() -> anyhow::Result<()> {
    if std::env::args().len() == 1 {
        let mut last_error: Option<String> = None;

        // These don't change across menu iterations, so compute them once.
        // The git subprocess in particular is expensive to spawn and used to
        // run on every menu re-entry, lengthening the blank-screen gap.
        let project_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "project".to_string());
        let branch_name = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        loop {
            // Reload config every iteration so menu reflects any changes
            let reload_start = std::time::Instant::now();
            let global = match GlobalConfig::load() {
                Ok(g) => g,
                Err(e) => {
                    zentra_cli::logging::error(
                        "config",
                        format!("failed to parse config.toml: {e:#}"),
                    );
                    last_error = Some(format!(
                        "Couldn't read ~/.zentra/config.toml: {e} — your providers are still in the file; fix the syntax (or run `zentra config setup`) and reopen the menu."
                    ));
                    GlobalConfig::default()
                }
            };
            let provider_configured = !global.profiles.is_empty();
            let project_configured =
                ProjectConfig::load_from(&ProjectConfig::default_path()).is_ok();
            let mut profiles: Vec<(String, String)> = global
                .profiles
                .iter()
                .map(|(name, p)| (name.clone(), p.model.clone()))
                .collect();
            profiles.sort_by(|a, b| a.0.cmp(&b.0));
            let active_profile = global.default_profile.clone().unwrap_or_default();
            let active_model = global
                .profiles
                .get(&active_profile)
                .map(|p| p.model.clone())
                .unwrap_or_default();
            if zentra_cli::tui::menu::tui_timing_enabled() {
                zentra_cli::logging::warn(
                    "tui-timing",
                    format!("menu re-entry reload: {} ms", reload_start.elapsed().as_millis()),
                );
            }

            match run_menu(
                provider_configured,
                project_configured,
                profiles,
                active_model,
                active_profile,
                project_name.clone(),
                branch_name.clone(),
                last_error.take(),
            )
            .await?
            {
                MenuAction::RunScan(scanners) => {
                    commands::scan::run_with_scanners(scanners).await?;
                    // loop continues so scan UI q/Esc returns here
                }
                MenuAction::CloneAndScan(url) => {
                    if let Err(e) = commands::clone::run_clone_and_scan(url).await {
                        zentra_cli::logging::error("menu", format!("clone-and-scan failed: {e:#}"));
                        last_error = Some(e.to_string());
                    }
                    // loop continues; error (if any) renders on the next menu draw
                }
                MenuAction::RunPentest => {
                    if let Some(result) =
                        zentra_cli::tui::pentest_setup::run_pentest_setup().await?
                    {
                        commands::pentest::run_config(result.config, result.auth).await?;
                    }
                }
                MenuAction::ViewLastResults => {
                    zentra_cli::tui::results::run_results().await?;
                }
                // Changing/adding a provider is now handled inside the menu loop
                // (see MenuState::apply_provider_change) so the terminal is not
                // torn down and rebuilt just to update the default profile.
                MenuAction::Exit => break,
            }
        }
        return Ok(());
    }

    let cli = cli::Cli::parse();
    match cli.command {
        None => unreachable!(),
        Some(cli::Commands::Init { ci }) => commands::init::run(ci).await?,
        Some(cli::Commands::Ci) => commands::ci::run().await?,
        Some(cli::Commands::Config { action }) => match action {
            cli::ConfigAction::Setup => wizard::run_setup(None).await?,
            cli::ConfigAction::Add => wizard::run_setup(None).await?,
            cli::ConfigAction::List => commands::config::list().await?,
            cli::ConfigAction::Use { name } => commands::config::use_profile(&name).await?,
            cli::ConfigAction::Show => commands::config::show().await?,
            cli::ConfigAction::Remove { name } => commands::config::remove(&name).await?,
        },
        Some(cli::Commands::Scan {
            provider,
            only,
            full,
        }) => commands::scan::run(provider, only, full).await?,
        Some(cli::Commands::Pentest {
            url,
            allow_hosts,
            allow_paths,
            exclude_paths,
            authorized,
            skip_network,
            stealth,
            stealth_delay_ms,
            escalate,
            no_nmap,
            whatweb,
            html_fingerprint,
        }) => {
            commands::pentest::run(
                url,
                allow_hosts,
                allow_paths,
                exclude_paths,
                authorized,
                skip_network,
                stealth,
                stealth_delay_ms,
                escalate,
                no_nmap,
                whatweb,
                html_fingerprint,
            )
            .await?
        }
        Some(cli::Commands::Security { action }) => match action {
            cli::SecurityAction::VerifyAudit { session } => {
                commands::security::verify_audit(session).await?
            }
        },
        Some(cli::Commands::Diagnostics { action }) => match action {
            cli::DiagnosticsAction::Ping { target } => {
                let output = tools::diagnostics::run_ping_diagnostic(&target)?;
                println!("{output}");
            }
        },
        Some(cli::Commands::Update) => {
            eprintln!("zentra update - available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}
