use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "zentra", version, about = "AI-powered Application Security")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize .zentra/ in the current project
    Init,
    /// Manage LLM provider configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run security scan
    Scan {
        /// Run only a specific scanner (threat-model, sast, supply-chain, api, iac, report)
        #[arg(long)]
        only: Option<String>,
        /// Override the default provider profile for this scan
        #[arg(long)]
        provider: Option<String>,
    },
    /// Upgrade zentra to the latest release
    Update,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Run first-time setup wizard
    Setup,
    /// Add a new provider profile
    Add,
    /// List all configured provider profiles
    List,
    /// Set the default provider profile
    Use { name: String },
    /// Show the active profile details
    Show,
    /// Remove a provider profile and its stored key
    Remove { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_init_command() {
        let cli = Cli::try_parse_from(["zentra", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Init)));
    }

    #[test]
    fn parses_config_setup() {
        let cli = Cli::try_parse_from(["zentra", "config", "setup"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Config { action: ConfigAction::Setup })
        ));
    }

    #[test]
    fn parses_scan_with_only_flag() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--only", "sast"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { only: Some(ref s), .. }) if s == "sast"
        ));
    }

    #[test]
    fn parses_no_args_as_none() {
        let cli = Cli::try_parse_from(["zentra"]).unwrap();
        assert!(cli.command.is_none());
    }
}
