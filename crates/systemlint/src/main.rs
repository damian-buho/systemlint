// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use systemlint::config::{self, Config};
use systemlint::discovery::{self, Trust};
use systemlint::runner;
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code for an unreadable or invalid configuration.
const EXIT_CONFIG: u8 = 3;

/// Exit code when a plugin was refused or failed to describe itself.
const EXIT_PLUGIN: u8 = 4;

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, arg_required_else_help = true)]
#[command(after_help = "Examples:\n  systemlint plugin list\n  systemlint --config ./systemlint.yaml plugin list --json\n\nDocs: https://kiota.ch/damian-buho/systemlint\nIssues: https://kiota.ch/damian-buho/systemlint/issues")]
struct Cli {
    /// Configuration file [default: /etc/systemlint/config.yaml when it exists]
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Explain each step on stderr
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    verbose: bool,
    /// Print only results and errors
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect the installed plugins
    #[command(subcommand)]
    Plugin(PluginCommand),
}

#[derive(Subcommand)]
enum PluginCommand {
    /// List every trusted plugin and its ops
    #[command(after_help = "Searches ../lib/systemlint/plugins beside the systemlint binary, then the plugins.directories the config names.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md")]
    List {
        /// Print indented JSON
        #[arg(long)]
        json: bool,
    },
}

/// One row of `plugin list --json`.
#[derive(Serialize)]
struct Listed {
    name: String,
    version: String,
    protocol: u32,
    path: PathBuf,
    ops: Vec<OpSpec>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Off };
    env_logger::Builder::new().filter_level(level).init();
    let config = match load_config(cli.config.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    match cli.command {
        Command::Plugin(PluginCommand::List { json }) => ExitCode::from(plugin_list(&config, json, cli.quiet)),
    }
}

fn load_config(explicit: Option<&Path>) -> Result<Config, String> {
    if let Some(path) = explicit {
        return Config::load(path);
    }
    let system = Path::new(config::SYSTEM);
    if system.exists() {
        return Config::load(system);
    }
    log::debug!("no --config and no {}, using defaults", system.display());
    Ok(Config::default())
}

fn plugin_list(config: &Config, json: bool, quiet: bool) -> u8 {
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).unwrap_or_else(|_| PathBuf::from("/usr/local/bin/systemlint"));
    let dirs = discovery::directories(&exe, &config.plugins.directories);
    let (plugins, refusals) = discovery::discover(&dirs, &Trust::invoking_user());
    let mut problems: Vec<String> = refusals.iter().map(|r| format!("refused {}: {}", r.path.display(), r.reason)).collect();
    let mut listed = Vec::new();
    for plugin in plugins {
        match runner::describe(&plugin.name, &plugin.path, runner::DESCRIBE_TIMEOUT) {
            Ok(d) => listed.push(Listed { name: d.name, version: d.version, protocol: d.protocol, path: plugin.path, ops: d.ops }),
            Err(error) => problems.push(format!("plugin {} at {}: {error}", plugin.name, plugin.path.display())),
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&listed).unwrap_or_default());
    } else {
        for row in &listed {
            println!("{} {} {}", row.name, row.version, row.path.display());
            for op in &row.ops {
                if op.needs.is_empty() {
                    println!("  {}", op.op);
                } else {
                    println!("  {} (needs {})", op.op, op.needs.join(", "));
                }
            }
        }
    }
    if listed.is_empty() && problems.is_empty() && !quiet {
        let searched: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        eprintln!("No plugins found. Searched: {}", searched.join(", "));
    }
    for problem in &problems {
        eprintln!("{problem}");
    }
    if problems.is_empty() { 0 } else { EXIT_PLUGIN }
}
