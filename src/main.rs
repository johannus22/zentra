use clap::Parser;
use zentra_cli::{
    cli, commands,
    config::{GlobalConfig, ProjectConfig},
    tui::menu::{run_menu, MenuAction},
    wizard,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().len() == 1 {
        loop {
            // Reload config every iteration so menu reflects any changes
            let global = GlobalConfig::load().unwrap_or_default();
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

            match run_menu(
                provider_configured,
                project_configured,
                profiles,
                active_model,
                active_profile,
                project_name,
                branch_name,
            )
            .await?
            {
                MenuAction::RunScan(scanners) => {
                    commands::scan::run_with_scanners(scanners).await?;
                    // loop continues so scan UI q/Esc returns here
                }
                MenuAction::RunPentest => {
                    if let Some(config) =
                        zentra_cli::tui::pentest_setup::run_pentest_setup().await?
                    {
                        commands::pentest::run_config(config, zentra_cli::pentest::auth::PentestAuth::default()).await?;
                    }
                }
                MenuAction::ViewLastResults => {
                    zentra_cli::tui::results::run_results().await?;
                }
                MenuAction::ChangeProvider(name) | MenuAction::ProviderAdded(name) => {
                    commands::config::use_profile(&name).await?;
                    // loop continues; GlobalConfig reloaded at top of next iteration
                }
                MenuAction::Exit => break,
            }
        }
        return Ok(());
    }

    let cli = cli::Cli::parse();
    match cli.command {
        None => unreachable!(),
        Some(cli::Commands::Init) => commands::init::run().await?,
        Some(cli::Commands::Config { action }) => match action {
            cli::ConfigAction::Setup => wizard::run_setup(None).await?,
            cli::ConfigAction::Add => wizard::run_setup(None).await?,
            cli::ConfigAction::List => commands::config::list().await?,
            cli::ConfigAction::Use { name } => commands::config::use_profile(&name).await?,
            cli::ConfigAction::Show => commands::config::show().await?,
            cli::ConfigAction::Remove { name } => commands::config::remove(&name).await?,
        },
        Some(cli::Commands::Scan { provider, only }) => commands::scan::run(provider, only).await?,
        Some(cli::Commands::Pentest {
            url,
            allow_hosts,
            allow_paths,
            exclude_paths,
            authorized,
        }) => {
            commands::pentest::run(
                url,
                allow_hosts,
                allow_paths,
                exclude_paths,
                authorized,
            )
            .await?
        }
        Some(cli::Commands::Update) => {
            eprintln!("zentra update â€” available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}
