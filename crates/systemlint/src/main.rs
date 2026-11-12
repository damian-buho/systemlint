// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode, Stdio};
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use systemlint::collect::{self, Options};
use systemlint::config::{self, Config};
use systemlint::discovery::{self, Trust};
use systemlint::judge::{self, Rule};
use systemlint::report::{self, Colour, FailOn};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint::{collector, comply, document, rules, runner};
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code when `lint` finds failures at `--fail-on` or a `--standard` is not complied with, or a `facts` collector failed.
const EXIT_FAIL: u8 = 1;

/// Exit code for an unreadable or invalid configuration, ruleset or facts document.
const EXIT_CONFIG: u8 = 2;

/// Exit code when a plugin was refused or failed to describe itself.
const EXIT_PLUGIN: u8 = 4;

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, arg_required_else_help = true)]
#[command(after_help = "Examples:\n  systemlint facts\n  systemlint facts --root /mnt/image --save image.facts.yaml\n  systemlint lint --root rootfs --image-config config.json --tags env\n  systemlint lint image.facts.yaml\n  systemlint lint --standard dev-sec-ssh-baseline\n  systemlint plugin list\n\nDocs: https://kiota.ch/damian-buho/systemlint\nIssues: https://kiota.ch/damian-buho/systemlint/issues")]
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
        /// Also read this OCI image config or docker inspect JSON, for the image’s environment
        #[arg(long, value_name = "PATH")]
        image_config: Option<PathBuf>,
        /// Write the document to PATH instead of stdout, - for stdout: JSON when it ends in .json, else YAML
        #[arg(long, value_name = "PATH")]
        save: Option<PathBuf>,
        /// Print JSON instead of YAML
        #[arg(long)]
        json: bool,
    },
    /// Lint a saved facts document, or facts collected now
    #[command(after_help = "Exit codes: 0 clean, 1 failures at --fail-on, 2 bad arguments, config or rules, 4 a plugin was refused.\nWith --standard: 0 compliant, 1 non-compliant, 3 indeterminate, whatever --fail-on says.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/rules.md")]
    Lint {
        #[command(flatten)]
        input: Input,
        /// Rules to run, comma-separated: rulesets, rule IDs and tags, globs allowed, !x removes [default: lint.tags, else every rule]
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        tags: Vec<String>,
        /// Also run the rules tagged STANDARD:<control> and answer per control; repeatable
        #[arg(long, value_name = "STANDARD")]
        standard: Vec<String>,
        /// Exit 1 on a failure at error, warning, info, a score from 0.1 to 9.9, or never [default: lint.fail-on, else error]
        #[arg(long, value_name = "LEVEL")]
        fail_on: Option<FailOn>,
        #[command(flatten)]
        look: Look,
        /// Write the report to PATH atomically, mode 0644, instead of stdout, - for stdout
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
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

/// Where the facts to judge come from.
#[derive(clap::Args)]
struct Input {
    /// A facts document from `systemlint facts --save`, or - for stdin [default: collect now]
    #[arg(value_name = "FACTS", conflicts_with = "root")]
    facts: Option<PathBuf>,
    /// Collect from this root filesystem instead of the live host
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Also read this OCI image config or docker inspect JSON, for the image’s environment
    #[arg(long, value_name = "PATH", conflicts_with = "facts")]
    image_config: Option<PathBuf>,
}

/// How `lint` lays out its report.
#[derive(clap::Args)]
struct Look {
    /// Output format: human, json, sarif (SARIF 2.1.0) or textfile (node-exporter metrics)
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// One finding per tab-separated line, undecorated, for grep and screen readers
    #[arg(long, conflicts_with = "format")]
    plain: bool,
    /// Colour the human report: auto, always or never; auto is off under NO_COLOR, SYSTEMLINT_NO_COLOR, TERM=dumb or off a terminal
    #[arg(long, value_enum, value_name = "WHEN", default_value_t = Colour::Auto)]
    color: Colour,
}

/// How `lint` prints its report.
#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
    Textfile,
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
        Command::Facts { root, image_config, save, json } => ExitCode::from(facts(&config, root.as_deref(), image_config, save.as_deref(), json, cli.quiet)),
        Command::Lint { input, tags, standard, fail_on, look, output } => ExitCode::from(lint(&config, &input, &Selection { tags, standards: standard }, fail_on, &look, output.as_deref(), cli.quiet)),
        Command::Plugin(PluginCommand::List { json }) => ExitCode::from(plugin_list(&config, json, cli.quiet)),
    }
}

fn exe() -> PathBuf {
    std::env::current_exe().and_then(|p| p.canonicalize()).unwrap_or_else(|_| PathBuf::from("/usr/local/bin/systemlint"))
}

fn gather(config: &Config, root: Option<&Path>, image_config: Option<PathBuf>, quiet: bool) -> Result<(Value, bool), u8> {
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
    let hash_key = match &config.collect.hash_key {
        Some(text) => collect::HashKey::configured(text),
        None => collect::HashKey::random().map_err(|error| {
            eprintln!("{error}");
            EXIT_CONFIG
        })?,
    };
    let options = Options { root, live, privileged: rustix::process::geteuid().is_root(), now: SystemTime::now(), timeout: collect::TIMEOUT, hash_key, image_config };
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

fn facts(config: &Config, root: Option<&Path>, image_config: Option<PathBuf>, save: Option<&Path>, json: bool, quiet: bool) -> u8 {
    let (document, trusted) = match gather(config, root, image_config, quiet) {
        Ok(gathered) => gathered,
        Err(code) => return code,
    };
    let written = match save.filter(|p| *p != Path::new("-")) {
        Some(path) => document::save(&document, path),
        None => document::render(&document, json).map(|text| print!("{text}")),
    };
    if let Err(error) = written {
        eprintln!("{error}");
        return EXIT_CONFIG;
    }
    let failed = document["collectors"].as_object().map_or(0, |o| o.values().filter(|c| c["status"] == "error").count());
    log::debug!("facts done: {failed} collectors failed, trusted {trusted}");
    if failed > 0 {
        EXIT_FAIL
    } else if trusted {
        0
    } else {
        EXIT_PLUGIN
    }
}

fn facts_for(config: &Config, input: &Input, quiet: bool) -> Result<(Value, bool), u8> {
    match &input.facts {
        Some(path) => document::load(path).map(|d| (d, true)).map_err(|error| {
            eprintln!("{error}");
            EXIT_CONFIG
        }),
        None => gather(config, input.root.as_deref(), input.image_config.clone(), quiet),
    }
}

fn library(config: &Config) -> Result<Library, u8> {
    let dirs = rules::directories(&exe(), &config.lint.directories);
    let (library, refusals) = Library::load(&dirs, &Trust::invoking_user(), &config.lint.rulesets);
    for refusal in &refusals {
        eprintln!("refused {}: {}", refusal.path.display(), refusal.reason);
    }
    let library = library.map_err(|error| {
        eprintln!("{error}");
        EXIT_CONFIG
    })?;
    log::debug!("{} rulesets define {} rules, searched {}", library.rulesets.len(), library.definitions.len(), dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "));
    if refusals.is_empty() { Ok(library) } else { Err(EXIT_CONFIG) }
}

fn compiled(library: &Library, selection: &Selection, config: &Config) -> Result<Vec<Rule>, u8> {
    let base = if selection.tags.is_empty() { &config.lint.tags } else { &selection.tags };
    let selected = library.select_for(base, &selection.standards).and_then(|specs| specs.into_iter().map(|(id, spec)| judge::compile(&id, spec)).collect::<Result<Vec<_>, _>>());
    selected.map_err(|error| {
        eprintln!("{error}");
        EXIT_CONFIG
    })
}

fn today() -> String {
    collect::rfc3339(SystemTime::now())[..10].to_owned()
}

/// Shows `text` through `$PAGER`, else `less` with `LESS=FIRX` unless `LESS` is set; prints it when no pager runs.
fn page(text: &str) {
    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".to_owned());
    let less = std::env::var("LESS").unwrap_or_else(|_| "FIRX".to_owned());
    let child = (!pager.is_empty()).then(|| Process::new("sh").arg("-c").arg(&pager).env("LESS", less).stdin(Stdio::piped()).spawn());
    let Some(Ok(mut child)) = child else {
        log::debug!("no pager from PAGER {pager:?}, printing");
        return print!("{text}");
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.as_bytes());
    }
    let status = child.wait();
    log::debug!("pager {pager:?} ended {status:?}");
    if status.ok().and_then(|s| s.code()) == Some(127) {
        print!("{text}");
    }
}

/// What `lint` runs: the `--tags` selectors and the standards to answer.
struct Selection {
    tags: Vec<String>,
    standards: Vec<String>,
}

/// The catalog of each standard, from the rules directories or their `standards` siblings.
fn catalogs(config: &Config, standards: &[String]) -> Result<Vec<Option<comply::Catalog>>, u8> {
    let dirs = comply::directories(&rules::directories(&exe(), &config.lint.directories));
    let mut out = Vec::new();
    for standard in standards {
        let (catalog, refusals) = comply::catalog(&dirs, &Trust::invoking_user(), standard);
        for refusal in &refusals {
            eprintln!("refused {}: {}", refusal.path.display(), refusal.reason);
        }
        let catalog = catalog.map_err(|error| {
            eprintln!("{error}");
            EXIT_CONFIG
        })?;
        if !refusals.is_empty() {
            return Err(EXIT_CONFIG);
        }
        log::debug!("standard {standard} has a catalog: {}", catalog.is_some());
        out.push(catalog);
    }
    Ok(out)
}

fn lint(config: &Config, input: &Input, selection: &Selection, fail_on: Option<FailOn>, look: &Look, output: Option<&Path>, quiet: bool) -> u8 {
    let run = || -> Result<u8, u8> {
        let library = library(config)?;
        let rules = if library.definitions.is_empty() { Vec::new() } else { compiled(&library, selection, config)? };
        let catalogs = catalogs(config, &selection.standards)?;
        let fail_on = fail_on.or_else(|| config.lint.fail_on.as_deref().and_then(|t| t.parse().ok())).unwrap_or(FailOn::Level(rules::Severity::Error));
        let (document, trusted) = facts_for(config, input, quiet)?;
        log::debug!("linting facts of {} collected at {} with {} rules", document["meta"]["subject"], document["meta"]["collected-at"], rules.len());
        if rules.is_empty() && !quiet {
            eprintln!("No rules selected. Searched: {}", rules::directories(&exe(), &config.lint.directories).iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "));
        }
        let checks = judge::lint(&document, &rules, &config.lint.waivers, &today());
        let compliance: Vec<comply::Report> = selection.standards.iter().zip(&catalogs).map(|(standard, catalog)| comply::comply(standard, &rules, &checks, catalog.as_ref())).collect();
        let terminal = output.is_none_or(|p| p == Path::new("-")) && std::io::stdout().is_terminal();
        let text = match look.format {
            Format::Human if look.plain => report::lint_plain(&document, &checks, &compliance, quiet),
            Format::Human => report::lint_human(&document, &checks, &compliance, quiet, report::colour(look.color, |n| std::env::var(n).ok(), terminal)),
            Format::Json => report::lint_json(&document, &checks, &compliance),
            Format::Sarif => report::lint_sarif(&document, &checks, &compliance),
            Format::Textfile => report::lint_textfile(&document, &checks, &compliance),
        };
        match output {
            Some(path) => document::write(path, &text, 0o644).map_err(|error| {
                eprintln!("{error}");
                EXIT_CONFIG
            })?,
            None if matches!(look.format, Format::Human) && !look.plain && terminal && std::io::stdin().is_terminal() => page(&text),
            None => print!("{text}"),
        }
        let failed = if compliance.is_empty() {
            u8::from(fail_on.reached(&checks)) * EXIT_FAIL
        } else {
            comply::overall(&compliance).code()
        };
        log::debug!("lint exits on {failed} from {} standards, trusted {trusted}", compliance.len());
        Ok(if failed != 0 { failed } else if trusted { 0 } else { EXIT_PLUGIN })
    };
    run().unwrap_or_else(|code| code)
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
        eprintln!("No plugins found. Searched: {}. A bare binary has none beside it: unpack the release archive, which puts plugins in lib/systemlint/plugins next to bin/systemlint, or name a directory in plugins.directories.", searched.join(", "));
    }
    for problem in &problems {
        eprintln!("{problem}");
    }
    if problems.is_empty() { 0 } else { EXIT_PLUGIN }
}
