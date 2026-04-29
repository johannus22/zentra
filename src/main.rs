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
        let provider_configured = GlobalConfig::is_configured();
        let project_configured = ProjectConfig::load_from(&ProjectConfig::default_path()).is_ok();

        loop {
            match run_menu(provider_configured, project_configured).await? {
                MenuAction::RunScan(scanners) => {
                    commands::scan::run_with_scanners(scanners).await?;
                    break;
                }
                MenuAction::ViewLastResults => {
                    zentra_cli::tui::results::run_results().await?;
                }
                MenuAction::Config => {
                    wizard::run_setup(None).await?;
                    break;
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
        Some(cli::Commands::Scan { provider, only }) => {
            commands::scan::run(provider, only).await?
        }
        Some(cli::Commands::Update) => {
            eprintln!("zentra update — available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}
