// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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
use systemlint::{collector, comply, crash, document, rules, runner};
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code when `lint` finds failures at `--fail-on` or a `--standard` is not complied with, or a `facts` collector failed.
const EXIT_FAIL: u8 = 1;

/// Exit code for an unreadable, invalid or refused configuration, ruleset or catalog; 2 stays clap’s usage error.
const EXIT_CONFIG: u8 = 5;

/// Exit code for an unreadable or invalid facts document, or a `--root` that can’t be opened.
const EXIT_INPUT: u8 = 6;

/// Exit code when the facts or the report can’t be written.
const EXIT_OUTPUT: u8 = 7;

/// Exit code when the operating system can’t give a random hash key.
const EXIT_INTERNAL: u8 = 70;

/// Exit code when a plugin was refused or failed to describe itself.
const EXIT_PLUGIN: u8 = 4;

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, arg_required_else_help = true)]
#[command(after_help = "Examples:\n  systemlint facts\n  systemlint facts --root /mnt/image -o image.facts.yaml\n  systemlint lint --root rootfs --image-config config.json --tags env\n  systemlint lint image.facts.yaml\n  systemlint lint --standard dev-sec-ssh-baseline\n  systemlint plugin list\n\nDocs: https://kiota.ch/damian-buho/systemlint\nIssues: https://kiota.ch/damian-buho/systemlint/issues")]
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
    #[command(after_help = "Runs every collector from ../share/systemlint/collectors beside the binary and from collect.directories in the config.\nExit codes: 0 every collector ok or skipped, 1 a collector failed, 2 bad arguments, 4 a plugin or collector refused, 5 config, 6 --root can’t be opened, 7 --output can’t be written, 70 no random hash key.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/collectors.md")]
    Facts {
        /// Read this root filesystem instead of the live host; commands do not run
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Also read this OCI image config or docker inspect JSON, for the image’s environment
        #[arg(long, value_name = "PATH")]
        image_config: Option<PathBuf>,
        /// Write the document to PATH atomically, mode 0600, instead of stdout, - for stdout
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Document format: yaml or json [default: json when --output ends in .json, else yaml]
        #[arg(long, value_enum)]
        format: Option<FactsFormat>,
    },
    /// Lint a saved facts document, or facts collected now
    #[command(after_help = "Exit codes: 0 clean, 1 failures at --fail-on, 2 bad arguments, 4 a plugin or collector refused, 5 config, rules or catalog, 6 unreadable facts or --root, 7 --output can’t be written, 70 no random hash key.\nWith --standard: 0 compliant, 1 non-compliant, 3 indeterminate, whatever --fail-on says.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/rules.md")]
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
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Inspect the installed plugins
    #[command(subcommand)]
    Plugin(PluginCommand),
}

#[derive(Subcommand)]
enum PluginCommand {
    /// List every trusted plugin and its ops
    #[command(after_help = "Searches ../lib/systemlint/plugins beside the systemlint binary, then the plugins.directories the config names.\nExit codes: 0 every plugin listed, 2 bad arguments, 4 a plugin refused or failed to describe itself, 5 config, 7 stdout can’t be written.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md")]
    List {
        /// Output format: human, or json (indented)
        #[arg(long, value_enum, default_value_t = ListFormat::Human)]
        format: ListFormat,
    },
}

/// Where the facts to judge come from.
#[derive(clap::Args)]
struct Input {
    /// A facts document from `systemlint facts --output`, or - for stdin [default: collect now]
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
    /// Add each failing rule’s rationale and references, from the global `--verbose`
    #[arg(skip)]
    verbose: bool,
}

/// How `lint` prints its report.
#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
    Textfile,
}

/// How `facts` encodes its document.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum FactsFormat {
    Yaml,
    Json,
}

/// How `plugin list` prints its plugins.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ListFormat {
    Human,
    Json,
}

/// One row of `plugin list --format json`.
#[derive(Serialize)]
struct Listed {
    name: String,
    version: String,
    protocol: u32,
    path: PathBuf,
    ops: Vec<OpSpec>,
}

fn main() -> ExitCode {
    // SAFETY: restores the default SIGPIPE action Rust’s runtime set to ignore, before any thread starts, so a closed pipe ends the run silently.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    crash::install();
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
        Command::Facts { root, image_config, output, format } => ExitCode::from(facts(&config, root.as_deref(), image_config, output.as_deref(), format, cli.quiet)),
        Command::Lint { input, tags, standard, fail_on, look, output } => ExitCode::from(lint(&config, &input, &Selection { tags, standards: standard }, fail_on, &Look { verbose: cli.verbose, ..look }, output.as_deref(), cli.quiet)),
        Command::Plugin(PluginCommand::List { format }) => ExitCode::from(plugin_list(&config, format == ListFormat::Json, cli.quiet)),
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
        EXIT_INPUT
    })?;
    log::debug!("collecting {} collectors with {} plugins from {} (live {live})", collectors.len(), plugins.len(), root.path().display());
    let hash_key = match &config.collect.hash_key {
        Some(text) => collect::HashKey::configured(text),
        None => collect::HashKey::random().map_err(|error| {
            eprintln!("{error}");
            EXIT_INTERNAL
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

fn facts(config: &Config, root: Option<&Path>, image_config: Option<PathBuf>, output: Option<&Path>, format: Option<FactsFormat>, quiet: bool) -> u8 {
    let (document, trusted) = match gather(config, root, image_config, quiet) {
        Ok(gathered) => gathered,
        Err(code) => return code,
    };
    let saved = output.filter(|p| *p != Path::new("-"));
    log::debug!("facts to {:?} as {:?}", output, format.map(|f| f == FactsFormat::Json));
    let written = match (saved, format) {
        (Some(path), None) => document::save(&document, path),
        (path, format) => document::render(&document, format == Some(FactsFormat::Json)).and_then(|text| document::write(path.unwrap_or(Path::new("-")), &text, 0o600)),
    };
    if let Err(error) = written {
        eprintln!("{error}");
        return EXIT_OUTPUT;
    }
    let failed = document["collectors"].as_object().map_or(0, |o| o.values().filter(|c| c["status"] == "error").count());
    if let Some(path) = saved.filter(|_| !quiet) {
        let ran = document["collectors"].as_object().map_or(0, serde_json::Map::len);
        eprintln!("Saved facts from {} ({}) to {}. Lint them with: systemlint lint {}", plural(ran, "collector"), plural(failed, "error"), path.display(), path.display());
    }
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
            EXIT_INPUT
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

/// `1 collector`, `0 errors`: the count, then the noun, plural unless the count is one.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

fn today() -> String {
    collect::rfc3339(SystemTime::now())[..10].to_owned()
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
            Format::Human => report::lint_human(&document, &checks, &compliance, quiet, look.verbose, report::colour(look.color, |n| std::env::var(n).ok(), terminal)),
            Format::Json => report::lint_json(&document, &checks, &compliance),
            Format::Sarif => report::lint_sarif(&document, &checks, &compliance),
            Format::Textfile => report::lint_textfile(&document, &checks, &compliance),
        };
        document::write(output.unwrap_or(Path::new("-")), &text, 0o644).map_err(|error| {
            eprintln!("{error}");
            EXIT_OUTPUT
        })?;
        if let Some(path) = output.filter(|p| !quiet && *p != Path::new("-")) {
            eprintln!("Wrote {} to {}.", plural(checks.iter().filter(|c| c.is_failing()).count(), "finding"), path.display());
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
    let mut text = String::new();
    if json {
        text = serde_json::to_string_pretty(&listed).unwrap_or_default() + "\n";
    } else {
        for row in &listed {
            text += &format!("{} {} {}\n", row.name, row.version, row.path.display());
            for op in &row.ops {
                if op.needs.is_empty() {
                    text += &format!("  {}\n", op.op);
                } else {
                    text += &format!("  {} (needs {})\n", op.op, op.needs.join(", "));
                }
            }
        }
    }
    if let Err(error) = document::write(Path::new("-"), &text, 0) {
        eprintln!("{error}");
        return EXIT_OUTPUT;
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
