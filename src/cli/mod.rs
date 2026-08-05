use clap::{Parser, Subcommand};

use crate::ci::CiPlatformKind;

#[derive(Parser, Debug)]
#[command(name = "zentra", version, about = "AI-powered Application Security")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize .zentra/ in the current project
    Init {
        /// Generate CI workflow configuration for the selected platform
        #[arg(long, value_enum)]
        ci: Option<CiPlatformKind>,
    },
    /// Run CI security checks without launching the TUI
    Ci {
        /// Regenerate .zentra/architecture.md only. Skips the PR/MR diff, report,
        /// and comment — for refreshing the base-branch cache outside a pull request.
        #[arg(long = "refresh-architecture")]
        refresh_architecture: bool,
        /// Scan the whole resolved target path instead of the PR/MR diff. Skips
        /// changed-file detection. Pair with `--report-only` for a staging job.
        #[arg(long)]
        full: bool,
        /// Never fail the pipeline on findings. Writes artifacts and files a
        /// GitLab triage issue (on GitLab) instead of a sticky MR comment. The
        /// fail threshold is still resolved and shown, but it does not gate the
        /// exit code. Use with `--full` for push-to-staging pipelines.
        #[arg(long = "report-only")]
        report_only: bool,
    },
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
        /// Force a full rescan instead of an incremental one
        #[arg(long)]
        full: bool,
        /// Send the whole filtered repository in one prompt instead of letting the
        /// agent navigate. Refuses when the repository does not fit the context.
        #[arg(long)]
        pack: bool,
        /// With --pack: print the pack size and token estimate, then exit without
        /// calling the provider
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Run dynamic browser pentest against an authorized target
    Pentest {
        /// Target URL to pentest
        #[arg(long)]
        url: String,
        /// Additional allowed host. May be repeated.
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        /// Allowed path prefix. May be repeated.
        #[arg(long = "allow-path")]
        allow_paths: Vec<String>,
        /// Excluded path prefix. May be repeated.
        #[arg(long = "exclude-path")]
        exclude_paths: Vec<String>,
        /// Confirm that you are authorized to test this target
        #[arg(long)]
        authorized: bool,
        /// Skip Stage 0 network recon entirely (nmap, whatweb, HTML fingerprint) — recommended for edge-hosted targets (Vercel/Cloudflare)
        #[arg(long = "skip-network")]
        skip_network: bool,
        /// Use low-concurrency requests to reduce IDS detection risk
        #[arg(long)]
        stealth: bool,
        /// Base delay in ms for stealth-mode request pacing (actual sleep is jittered to [delay, delay*2)); has no effect unless --stealth is set
        #[arg(long = "stealth-delay", default_value_t = 500)]
        stealth_delay_ms: u64,
        /// Reactively spawn escalation agents that chain confirmed High/Critical findings
        #[arg(long)]
        escalate: bool,
        /// Disable nmap in Stage 0 recon (nmap runs by default)
        #[arg(long = "no-nmap")]
        no_nmap: bool,
        /// Run whatweb in Stage 0 recon (requires whatweb installed)
        #[arg(long)]
        whatweb: bool,
        /// Fetch the target's homepage and detect technologies from headers/body in Stage 0 recon
        #[arg(long = "html-fingerprint")]
        html_fingerprint: bool,
    },
    /// Upgrade zentra to the latest release
    Update,
    /// Inspect and verify the security audit trail
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecurityAction {
    /// Verify the tamper-evident hash chain of an audit log session
    VerifyAudit {
        /// Session id (the audit file stem under .zentra/audit/). Omit to verify all sessions.
        session: Option<String>,
    },
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
        assert!(matches!(cli.command, Some(Commands::Init { ci: None })));
    }

    #[test]
    fn parses_init_with_ci_github() {
        let cli = Cli::try_parse_from(["zentra", "init", "--ci", "github"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Init {
                ci: Some(CiPlatformKind::Github)
            })
        ));
    }

    #[test]
    fn parses_ci_command() {
        let cli = Cli::try_parse_from(["zentra", "ci"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Ci {
                refresh_architecture: false,
                ..
            })
        ));
    }

    #[test]
    fn parses_ci_refresh_architecture_flag() {
        let cli = Cli::try_parse_from(["zentra", "ci", "--refresh-architecture"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Ci {
                refresh_architecture: true,
                ..
            })
        ));
    }

    #[test]
    fn parses_ci_full_flag() {
        let cli = Cli::try_parse_from(["zentra", "ci", "--full"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Ci {
                full: true,
                report_only: false,
                ..
            })
        ));
    }

    #[test]
    fn parses_ci_report_only_flag() {
        let cli = Cli::try_parse_from(["zentra", "ci", "--report-only"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Ci {
                full: false,
                report_only: true,
                ..
            })
        ));
    }

    #[test]
    fn parses_ci_full_and_report_only_flags() {
        let cli = Cli::try_parse_from(["zentra", "ci", "--full", "--report-only"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Ci {
                full: true,
                report_only: true,
                ..
            })
        ));
    }

    #[test]
    fn parses_config_setup() {
        let cli = Cli::try_parse_from(["zentra", "config", "setup"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Config {
                action: ConfigAction::Setup
            })
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

    #[test]
    fn parses_scan_defaults() {
        let cli = Cli::try_parse_from(["zentra", "scan"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Scan { .. })));
    }

    #[test]
    fn parses_pentest_required_url() {
        let cli = Cli::try_parse_from(["zentra", "pentest", "--url", "https://app.example.test"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest { ref url, .. }) if url == "https://app.example.test"
        ));
    }

    #[test]
    fn parses_pentest_scope_flags() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--allow-host",
            "app.example.test",
            "--allow-path",
            "/app",
            "--exclude-path",
            "/logout",
            "--authorized",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Some(Commands::Pentest {
                authorized: true,
                ..
            })
        ));
    }

    #[test]
    fn parses_pentest_escalate_flag() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
            "--escalate",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest { escalate: true, .. })
        ));
    }

    #[test]
    fn pentest_escalate_defaults_false() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest {
                escalate: false,
                ..
            })
        ));
    }

    #[test]
    fn parses_pentest_no_nmap_flag() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
            "--no-nmap",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest { no_nmap: true, .. })
        ));
    }

    #[test]
    fn parses_pentest_whatweb_flag() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
            "--whatweb",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest { whatweb: true, .. })
        ));
    }

    #[test]
    fn parses_pentest_html_fingerprint_flag() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
            "--html-fingerprint",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest {
                html_fingerprint: true,
                ..
            })
        ));
    }

    #[test]
    fn pentest_recon_tool_flags_default_false() {
        let cli = Cli::try_parse_from([
            "zentra",
            "pentest",
            "--url",
            "https://app.example.test",
            "--authorized",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pentest {
                no_nmap: false,
                whatweb: false,
                html_fingerprint: false,
                ..
            })
        ));
    }
}
