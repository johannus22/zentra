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
            let project_configured = ProjectConfig::load_from(&ProjectConfig::default_path()).is_ok();
            let mut profiles: Vec<(String, String)> = global.profiles
                .iter()
                .map(|(name, p)| (name.clone(), p.model.clone()))
                .collect();
            profiles.sort_by(|a, b| a.0.cmp(&b.0));
            let active_profile = global.default_profile.clone().unwrap_or_default();
            let active_model = global.profiles.get(&active_profile)
                .map(|p| p.model.clone())
                .unwrap_or_default();

            match run_menu(provider_configured, project_configured, profiles, active_model, active_profile).await? {
                MenuAction::RunScan(scanners) => {
                    commands::scan::run_with_scanners(scanners).await?;
                    break;
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
        Some(cli::Commands::Scan { provider, only, depth }) => {
            commands::scan::run(provider, only, depth).await?
        }
        Some(cli::Commands::Update) => {
            eprintln!("zentra update — available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}
