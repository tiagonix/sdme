use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sdme::{config, containers, is_privileged, rootfs, system_check, systemd, validate_name};

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

    /// Enter a running container
    Join {
        /// Container name
        name: String,
        /// Command to run inside the container (default: /bin/sh)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show container logs (journalctl)
    Logs {
        /// Container name
        name: String,
        /// Extra arguments passed to journalctl (e.g. -f, -n 100)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List containers
    Ps,

    /// Remove one or more containers
    Rm {
        /// Container names
        names: Vec<String>,
    },

    /// Stop a running container
    Stop {
        /// Container name
        name: String,
    },

    /// Manage root filesystems
    #[command(subcommand)]
    Rootfs(RootfsCommand),
}

#[derive(Subcommand)]
enum RootfsCommand {
    /// Import a root filesystem from a directory, tar file, or tar stream on stdin
    Import {
        /// Path to rootfs directory or tar file, or "-" for tar on stdin
        source: String,
        /// Name for the imported rootfs
        #[arg(short, long)]
        name: String,
        /// Remove leftover staging directory from a previous failed import
        #[arg(short, long)]
        force: bool,
    },
    /// List imported root filesystems
    Ls,
    /// Remove one or more imported root filesystems
    Rm {
        /// Names of the rootfs entries to remove
        names: Vec<String>,
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
    let privileged = is_privileged();

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
            system_check::check_systemd_version(privileged, 257)?;
            if !privileged {
                system_check::check_kernel_version(5, 11)?;
            }
            let opts = containers::CreateOptions { name, rootfs, privileged };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            println!("{name}");
        }
        Command::Start { name } => {
            system_check::check_systemd_version(privileged, 257)?;
            if !privileged {
                system_check::check_kernel_version(5, 11)?;
            }
            validate_name(&name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;
            systemd::start(&cfg.datadir, &name, cli.verbose, privileged)?;
            println!("started container '{name}'");
        }
        Command::Join { name, command } => {
            validate_name(&name)?;
            containers::join(&cfg.datadir, &name, &command, cli.verbose, privileged)?;
        }
        Command::Logs { name, args } => {
            system_check::check_dependencies(&[
                ("journalctl", "apt install systemd"),
            ], cli.verbose)?;
            validate_name(&name)?;
            let unit = systemd::service_name(&name);
            let mut cmd = std::process::Command::new("journalctl");
            if !privileged {
                cmd.arg("--user");
            }
            cmd.args(["-u", &unit]);
            cmd.args(&args);
            if cli.verbose {
                eprintln!("exec: journalctl {}",
                    cmd.get_args()
                        .map(|a| a.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
            let err = cmd.exec();
            bail!("failed to exec journalctl: {err}");
        }
        Command::Ps => {
            let entries = containers::list(&cfg.datadir, privileged)?;
            if entries.is_empty() {
                println!("no containers found");
            } else {
                let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                let status_w = entries.iter().map(|e| e.status.len()).max().unwrap().max(6);
                let health_w = entries.iter().map(|e| e.health.len()).max().unwrap().max(6);
                println!(
                    "{:<name_w$}  {:<status_w$}  {:<health_w$}  SHARED",
                    "NAME", "STATUS", "HEALTH"
                );
                for e in &entries {
                    println!(
                        "{:<name_w$}  {:<status_w$}  {:<health_w$}  {}",
                        e.name, e.status, e.health, e.shared.display()
                    );
                }
            }
        }
        Command::Rm { names } => {
            let mut failed = false;
            for name in &names {
                if let Err(e) = validate_name(name) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                    continue;
                }
                if let Err(e) = containers::remove(&cfg.datadir, name, cli.verbose, privileged) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                } else {
                    println!("{name}");
                }
            }
            if failed {
                bail!("some containers could not be removed");
            }
        }
        Command::Stop { name } => {
            validate_name(&name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;
            systemd::stop(&name, privileged)?;
            println!("stopped container '{name}'");
        }
        Command::Rootfs(cmd) => match cmd {
            RootfsCommand::Import { source, name, force } => {
                system_check::check_systemd_version(privileged, 257)?;
                if source == "-" {
                    // Tar stream from stdin (rootless only).
                    if privileged {
                        bail!("stdin tar import is for rootless mode; use a directory path as root");
                    }
                    system_check::check_kernel_version(5, 11)?;
                    system_check::check_dependencies(&[
                        ("tar", "apt install tar"),
                        ("newuidmap", "apt install uidmap"),
                        ("newgidmap", "apt install uidmap"),
                    ], cli.verbose)?;
                    rootfs::import_tar(&cfg.datadir, &name, None, cli.verbose, force)?;
                } else {
                    let source = PathBuf::from(&source);
                    if source.is_file() {
                        // Tar file path (rootless only).
                        if privileged {
                            bail!("tar file import is for rootless mode; use a directory path as root");
                        }
                        system_check::check_kernel_version(5, 11)?;
                        system_check::check_dependencies(&[
                            ("tar", "apt install tar"),
                            ("newuidmap", "apt install uidmap"),
                            ("newgidmap", "apt install uidmap"),
                        ], cli.verbose)?;
                        rootfs::import_tar(&cfg.datadir, &name, Some(&source), cli.verbose, force)?;
                    } else {
                        // Directory import (privileged only).
                        if !privileged {
                            bail!(
                                "directory import requires root; use a tar file or pipe via stdin instead:\n  \
                                 sudo tar cf - -C /path/to/rootfs . | sdme rootfs import --name {name} - -f"
                            );
                        }
                        rootfs::import(&cfg.datadir, &source, &name, cli.verbose, privileged, force)?;
                    }
                }
                println!("{name}");
            }
            RootfsCommand::Ls => {
                let entries = rootfs::list(&cfg.datadir)?;
                if entries.is_empty() {
                    println!("no root filesystems found");
                } else {
                    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                    let distro_w = entries.iter().map(|e| e.distro.len()).max().unwrap().max(6);
                    println!("{:<name_w$}  {:<distro_w$}  PATH", "NAME", "DISTRO");
                    for entry in &entries {
                        let path = cfg.datadir.join("rootfs").join(&entry.name);
                        println!("{:<name_w$}  {:<distro_w$}  {}", entry.name, entry.distro, path.display());
                    }
                }
            }
            RootfsCommand::Rm { names } => {
                let mut failed = false;
                for name in &names {
                    if let Err(e) = rootfs::remove(&cfg.datadir, name, cli.verbose) {
                        eprintln!("error: {name}: {e}");
                        failed = true;
                    } else {
                        println!("{name}");
                    }
                }
                if failed {
                    bail!("some rootfs entries could not be removed");
                }
            }
        },
    }

    Ok(())
}
