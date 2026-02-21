mod config;
mod containers;
mod systemd;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sdme", about = "Lightweight systemd-nspawn containers with overlayfs")]
struct Cli {
    /// Enable verbose output (implies non-interactive mode at runtime)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to config file (default: ~/.config/sdme/sdmerc)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage configuration
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Create a new container
    Create {
        /// Container name (generated if not provided)
        #[arg(short, long)]
        name: Option<String>,

        /// Root filesystem to use (host filesystem if not provided)
        #[arg(short, long)]
        rootfs: Option<String>,
    },

    /// Start a container
    Start {
        /// Container name
        name: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Show current configuration
    Get,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_path = cli.config.as_deref();

    if cli.verbose {
        let resolved = config::resolve_path(config_path)?;
        eprintln!("config: {}", resolved.display());
    }

    let cfg = config::load(config_path)?;

    match cli.command {
        Command::Config(cmd) => match cmd {
            ConfigCommand::Get => {
                cfg.display();
            }
            ConfigCommand::Set { key, value } => {
                let mut cfg = cfg;
                match key.as_str() {
                    "interactive" => match value.as_str() {
                        "yes" => cfg.interactive = true,
                        "no" => cfg.interactive = false,
                        _ => bail!("invalid value for interactive: {value} (expected yes or no)"),
                    },
                    "datadir" => {
                        cfg.datadir = PathBuf::from(&value);
                    }
                    _ => bail!("unknown config key: {key}"),
                }
                config::save(&cfg, config_path)?;
            }
        },
        Command::Create { name, rootfs } => {
            let opts = containers::CreateOptions { name, rootfs };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            println!("{name}");
        }
        Command::Start { name } => {
            containers::validate_name(&name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;
            systemd::start(&cfg.datadir, &name, cli.verbose)?;
            println!("started container '{name}'");
        }
    }

    Ok(())
}
