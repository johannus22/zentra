use zentra_cli::cli;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().len() == 1 {
        println!("Interactive menu — available in Plan 3. Run 'zentra --help' for commands.");
        return Ok(());
    }
    let cli = cli::Cli::parse();
    match cli.command {
        None => unreachable!(),
        Some(cli::Commands::Init) => todo!("Plan 1 Task 5"),
        Some(cli::Commands::Config { .. }) => todo!("Plan 1 Task 8"),
        Some(cli::Commands::Scan { .. }) => todo!("Plan 2"),
        Some(cli::Commands::Update) => todo!("Plan 4"),
    };
    Ok(())
}
