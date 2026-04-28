use clap::Parser;
use zentra_cli::{cli, commands, config::GlobalConfig, wizard};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // No-arg mode: interactive menu (full TUI in Plan 3)
    if std::env::args().len() == 1 {
        if !GlobalConfig::is_configured() {
            print_banner();
            println!("Welcome to Zentra — AI-powered Application Security");
            println!("No configuration found. Let's get you set up.\n");
            eprint!("Press Enter to start setup, or Ctrl+C to exit: ");
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            wizard::run_setup(None).await?;
        } else {
            print_banner();
            println!("Interactive menu — available in Plan 3.");
            println!("Run 'zentra --help' for all commands.\n");
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
        Some(cli::Commands::Scan { .. }) => {
            eprintln!("zentra scan — available in Plan 2 (agent core)");
            std::process::exit(1);
        }
        Some(cli::Commands::Update) => {
            eprintln!("zentra update — available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn print_banner() {
    println!(" ____        _");
    println!("|_  /___ _ _| |_ _ _ __ _");
    println!(" / // -_) ' \\  _| '_/ _` |");
    println!("/___\\___|_||_\\__|_| \\__,_|");
    println!();
}
