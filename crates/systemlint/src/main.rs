// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use systemlint::collect::{self, Options};
use systemlint::config::{self, Config};
use systemlint::discovery::{self, Trust};
use systemlint::source::Root;
use systemlint::{collector, document, runner};
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code for an unreadable or invalid configuration.
const EXIT_CONFIG: u8 = 3;

/// Exit code when a plugin was refused or failed to describe itself.
const EXIT_PLUGIN: u8 = 4;

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, arg_required_else_help = true)]
#[command(after_help = "Examples:\n  systemlint facts\n  systemlint facts --root /mnt/image --save image.facts.yaml\n  systemlint lint image.facts.yaml\n  systemlint plugin list\n\nDocs: https://kiota.ch/damian-buho/systemlint\nIssues: https://kiota.ch/damian-buho/systemlint/issues")]
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
    /// Collect facts and print them as YAML
    #[command(after_help = "Runs every collector from ../share/systemlint/collectors beside the binary and from collect.directories in the config.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/collectors.md")]
    Facts {
        /// Read this root filesystem instead of the live host; commands do not run
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Write the document to PATH instead of stdout: JSON when it ends in .json, else YAML
        #[arg(long, value_name = "PATH")]
        save: Option<PathBuf>,
        /// Print JSON instead of YAML
        #[arg(long)]
        json: bool,
    },
    /// Lint a saved facts document, or facts collected now
    Lint {
        /// A facts document from `systemlint facts --save`, or - for stdin [default: collect now]
        #[arg(value_name = "FACTS", conflicts_with = "root")]
        facts: Option<PathBuf>,
        /// Collect from this root filesystem instead of the live host
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
    },
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
        Command::Facts { root, save, json } => ExitCode::from(facts(&config, root.as_deref(), save.as_deref(), json, cli.quiet)),
        Command::Lint { facts, root } => ExitCode::from(lint(&config, facts.as_deref(), root.as_deref(), cli.quiet)),
        Command::Plugin(PluginCommand::List { json }) => ExitCode::from(plugin_list(&config, json, cli.quiet)),
    }
}

fn exe() -> PathBuf {
    std::env::current_exe().and_then(|p| p.canonicalize()).unwrap_or_else(|_| PathBuf::from("/usr/local/bin/systemlint"))
}

fn gather(config: &Config, root: Option<&Path>, quiet: bool) -> Result<(Value, bool), u8> {
    let trust = Trust::invoking_user();
    let (collectors, mut refusals) = collector::load(&collector::directories(&exe(), &config.collect.directories), &trust);
    let (plugins, plugin_refusals) = discovery::discover(&discovery::directories(&exe(), discovery::BESIDE, &config.plugins.directories), &trust);
    refusals.extend(plugin_refusals);
    for refusal in &refusals {
        eprintln!("refused {}: {}", refusal.path.display(), refusal.reason);
    }
    let live = root.is_none();
    let root = Root::open(root.unwrap_or(Path::new("/"))).map_err(|error| {
        eprintln!("{error}");
        EXIT_CONFIG
    })?;
    log::debug!("collecting {} collectors with {} plugins from {} (live {live})", collectors.len(), plugins.len(), root.path().display());
    let options = Options { root, live, now: SystemTime::now(), timeout: collect::TIMEOUT };
    let document = collect::collect(&collectors, &plugins, &options);
    if collectors.is_empty() && !quiet {
        eprintln!("No collectors found. Searched: {}", collector::directories(&exe(), &config.collect.directories).iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "));
    }
    if let Some(outcomes) = document["collectors"].as_object() {
        for (id, outcome) in outcomes.iter().filter(|(_, o)| o["status"] == "error") {
            eprintln!("collector {id}: {}", outcome["reason"].as_str().unwrap_or_default());
        }
    }
    Ok((document, refusals.is_empty()))
}

fn facts(config: &Config, root: Option<&Path>, save: Option<&Path>, json: bool, quiet: bool) -> u8 {
    let (document, trusted) = match gather(config, root, quiet) {
        Ok(gathered) => gathered,
        Err(code) => return code,
    };
    let written = match save {
        Some(path) => document::save(&document, path),
        None => document::render(&document, json).map(|text| print!("{text}")),
    };
    if let Err(error) = written {
        eprintln!("{error}");
        return EXIT_CONFIG;
    }
    if trusted { 0 } else { EXIT_PLUGIN }
}

fn lint(config: &Config, facts: Option<&Path>, root: Option<&Path>, quiet: bool) -> u8 {
    let document = match facts {
        Some(path) => document::load(path).map_err(|error| {
            eprintln!("{error}");
            EXIT_CONFIG
        }),
        None => gather(config, root, quiet).map(|(document, _)| document),
    };
    let document = match document {
        Ok(document) => document,
        Err(code) => return code,
    };
    log::debug!("linting facts of {} collected at {}", document["meta"]["subject"], document["meta"]["collected-at"]);
    if !quiet {
        eprintln!("No rules to apply to the facts collected at {}.", document["meta"]["collected-at"].as_str().unwrap_or("an unknown time"));
    }
    0
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
    let dirs = discovery::directories(&exe(), discovery::BESIDE, &config.plugins.directories);
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
