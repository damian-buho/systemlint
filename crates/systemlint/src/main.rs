// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use systemlint::collect::{self, Options};
use systemlint::config::{self, Config, FactsFormat, ListFormat};
use systemlint::discovery::{self, Trust};
use systemlint::judge::{self, Rule};
use systemlint::net;
use systemlint::numbers;
use systemlint::report::{self, Colour, FailOn, Format};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint::{collector, crash, document, progress, rules, runner, targets, trail};
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code when `check` finds failures at `--fail-on`, or a `facts` collector failed.
const EXIT_FAIL: u8 = 1;

/// Exit code for an unreadable, invalid or refused configuration or ruleset; 2 stays clap’s usage error.
const EXIT_CONFIG: u8 = 5;

/// Exit code for an unreadable or invalid facts document, or a `--root` that can’t be opened.
const EXIT_INPUT: u8 = 6;

/// Exit code when the facts or the report can’t be written.
const EXIT_OUTPUT: u8 = 7;

/// Whether a line went to stderr before the report, which then needs a blank line above it.
static NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Prints `line` on stderr ahead of the report, and records that it did.
fn note(line: impl std::fmt::Display) {
    NOTED.store(true, std::sync::atomic::Ordering::Relaxed);
    eprintln!("{line}");
}

/// Exit code when the operating system can’t give a random hash key.
const EXIT_INTERNAL: u8 = 70;

/// Exit code when a plugin was refused or failed to describe itself.
const EXIT_PLUGIN: u8 = 4;

/// Help laid out description, examples, usage, commands and flags, then the notes and links.
const TEMPLATE: &str =
    "{about-with-newline}\n{before-help}{usage-heading} {usage}\n\n{all-args}{after-help}";

/// What `systemlint` with no arguments prints: the description, two examples, the common flags and where the rest is.
const SUMMARY: &str = "Collects operating system facts and lints them with declarative rules.\n\nExamples:\n  systemlint check\n  systemlint facts -o host.facts.yaml\n\nCommands: facts, check, plugin\nCommon flags: --root DIR, --tags LIST, -o PATH, --format FORMAT\nEvery command and flag: systemlint --help, systemlint <command> --help\nDocs: https://kiota.ch/damian-buho/systemlint\n";

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, help_template = TEMPLATE)]
#[command(
    before_help = "Examples:\n  systemlint check\n  systemlint facts --root /mnt/image -o image.facts.yaml\n  systemlint check image.facts.yaml\n  systemlint plugin list"
)]
#[command(
    after_help = "Docs: https://kiota.ch/damian-buho/systemlint\nIssues: https://kiota.ch/damian-buho/systemlint/issues"
)]
struct Cli {
    /// Configuration file over SYSTEMLINT_CONFIG, ./.systemlint.yaml, ~/.config/systemlint/config.yaml and /etc/systemlint/config.yaml, merged key by key
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Skip ./.systemlint.yaml, as for a checkout you do not trust [default: off, or project-config: false in the system or user config]
    #[arg(long, global = true)]
    no_project_config: bool,
    /// Explain each step on stderr
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    verbose: bool,
    /// How --verbose writes each step: text, or json, one object per line naming its collector, plugin or phase as scope
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "FORMAT",
        default_value = "text",
        requires = "verbose"
    )]
    log_format: trail::LogFormat,
    /// Print only results and errors
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Run this many collectors at once, 1 to 64 [default: collect.jobs, else the available CPUs]
    #[arg(short, long, global = true, value_name = "N", value_parser = clap::value_parser!(u64).range(1..=runner::MAX_CHILDREN as u64))]
    jobs: Option<u64>,
    /// Run the network: true collectors, which connect, query DNS and fetch URLs from this host [default: collect.network, else off]
    #[arg(long, global = true)]
    network: bool,
    /// Also check every running container, nested ones included, as root: files through its root, commands in its namespaces [default: collect.containers, else off]
    #[arg(long, global = true)]
    containers: bool,
    /// Check only the containers this glob names, by key (ci/runner), name or short ID, repeatable or comma-separated; implies --containers [default: collect.container]
    #[arg(long, global = true, value_name = "NAME", value_delimiter = ',')]
    container: Vec<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Collect facts and print them as YAML
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint facts\n  sudo systemlint facts -o host.facts.yaml\n  systemlint facts --root /mnt/image --format json")]
    #[command(
        after_help = "Runs every collector from ../share/systemlint/collectors beside the binary and from collect.directories in the config.\nExit codes: 0 every collector ok or skipped, 1 a collector failed, 2 bad arguments, 4 a plugin or collector refused, 5 config, 6 --root can’t be opened, 7 --output can’t be written, 70 no random hash key.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/collectors.md#the-facts-document"
    )]
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
        /// Document format: yaml or json [default: collect.format, else json when --output ends in .json, else yaml]
        #[arg(long, value_enum)]
        format: Option<FactsFormat>,
    },
    /// Check a saved facts document, or facts collected now
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint check\n  systemlint check --all\n  systemlint check host.facts.yaml --tags sshd,apt\n  systemlint check --root rootfs --format sarif -o systemlint.sarif")]
    #[command(
        after_help = "Exit codes: 0 clean, 1 failures at --fail-on, 2 bad arguments, 4 a plugin or collector refused, 5 config or rules, 6 unreadable facts or --root, 7 --output can’t be written, 70 no random hash key.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/rules.md#check-output-and-exit-codes"
    )]
    Check {
        #[command(flatten)]
        input: Input,
        /// Rules to run, comma-separated: rulesets, rule IDs and tags, globs allowed, a standard-only rule by its ID or a standard tag (cis, nist, cis-*:5.*), !x removes [default: check.tags, else default]
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        tags: Vec<String>,
        /// Run every rule, standard-only ones included, as --tags all does
        #[arg(long, conflicts_with = "tags")]
        all: bool,
        /// Settle a conflict for the side holding a tag GLOB matches, comma-separated or repeated (cis, nist) [default: check.prefer]
        #[arg(long, value_name = "GLOB", value_delimiter = ',')]
        prefer: Vec<String>,
        /// Exit 1 on a failure at error, warning, info, advice, a score from 0.1 to 9.9, or never [default: check.fail-on, else error]
        #[arg(long, value_name = "LEVEL")]
        fail_on: Option<FailOn>,
        #[command(flatten)]
        vars: Vars,
        #[command(flatten)]
        look: Look,
        /// Write the report to PATH atomically, mode 0644, instead of stdout, - for stdout
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Check this host or a root filesystem, then make the changes its failing rules declare as a remedy
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint fix --dry-run\n  sudo systemlint fix --all --dry-run\n  sudo systemlint fix --tags files\n  systemlint fix --root rootfs --force")]
    #[command(
        after_help = "A remedy clears permission bits or gives a file to root, never more, and each file is read again right before its change.\nExit codes: 0 every change made or none needed, 1 a change failed or was declined, 2 bad arguments or a change needing --force, 4 a plugin or collector refused, 5 config, rules or fix.enabled: false, 6 the root can’t be opened, 70 no random hash key.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/rules.md#remedies"
    )]
    Fix {
        /// Check and change this root filesystem, such as an image being built, instead of the live host
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Rules to fix, as for check [default: check.tags, else default]
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        tags: Vec<String>,
        /// Fix every rule, standard-only ones included, as --tags all does
        #[arg(long, conflicts_with = "tags")]
        all: bool,
        /// Settle a conflict for the side holding a tag GLOB matches, comma-separated or repeated (cis, nist) [default: check.prefer]
        #[arg(long, value_name = "GLOB", value_delimiter = ',')]
        prefer: Vec<String>,
        #[command(flatten)]
        vars: Vars,
        /// Print each change as its command and make none
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Make the changes without asking
        #[arg(short, long, conflicts_with = "dry_run")]
        force: bool,
        /// Never ask; without --force, fail naming it
        #[arg(long)]
        no_input: bool,
    },
    /// Print the shipped rule catalog, or write one Markdown page per rule
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint rules\n  systemlint rules --format markdown --output book/rules")]
    #[command(
        after_help = "Prints the rulesets built into this binary, the ones its release ships, never an installed or configured one.\nExit codes: 0 printed or written, 2 bad arguments, 5 a built-in ruleset can’t be loaded, 7 a page or stdout can’t be written."
    )]
    Rules {
        /// yaml: the catalog at org.projectfile.pages.rules.items; markdown: a page per rule, ruleset and standard under --output
        #[arg(long, value_enum, default_value = "yaml")]
        format: PagesFormat,
        /// Language of the pages, a BCP 47 tag; rule texts have no translations yet, so every language reads English
        #[arg(long, value_name = "TAG", default_value = "en")]
        lang: String,
        /// With --format markdown, the directory to write the pages in
        #[arg(short, long, value_name = "DIR", required_if_eq("format", "markdown"))]
        output: Option<PathBuf>,
    },
    /// Inspect the installed plugins
    #[command(subcommand, help_template = TEMPLATE, before_help = "Examples:\n  systemlint plugin list")]
    #[command(
        after_help = "Docs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md#discovery-and-trust"
    )]
    Plugin(PluginCommand),
}

/// What `rules` prints: the catalog, or the pages.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PagesFormat {
    Yaml,
    Markdown,
}

#[derive(Subcommand)]
enum PluginCommand {
    /// List every trusted plugin and its ops
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint plugin list\n  systemlint plugin list --format json")]
    #[command(
        after_help = "Searches ../lib/systemlint/plugins beside the systemlint binary, then the plugins.directories the config names.\nExit codes: 0 every plugin listed, 2 bad arguments, 4 a plugin refused or failed to describe itself, 5 config, 7 stdout can’t be written.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md#discovery-and-trust"
    )]
    List {
        /// Output format: human, or json (indented) [default: plugins.format, else human]
        #[arg(long, value_enum)]
        format: Option<ListFormat>,
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

/// Values for the vars rulesets declare.
#[derive(clap::Args)]
struct Vars {
    /// Set a ruleset var, over --vars, its from-env variable, check.vars and its default; repeatable
    #[arg(long = "var", value_name = "NAME=VALUE", value_parser = var)]
    var: Vec<(String, String)>,
    /// Read ruleset vars from this YAML map of name: value pairs, under --var
    #[arg(long = "vars", value_name = "FILE")]
    vars: Option<PathBuf>,
}

fn var(text: &str) -> Result<(String, String), String> {
    text.split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("{text} is not NAME=VALUE"))
}

/// How `check` lays out its report.
#[derive(clap::Args)]
struct Look {
    /// Output format: human, json, sarif (SARIF 2.1.0) or textfile (node-exporter metrics) [default: check.format, else human]
    #[arg(long, value_enum)]
    format: Option<Format>,
    /// One finding per tab-separated line, undecorated, for grep and screen readers [default: check.plain, else off]
    #[arg(long, conflicts_with = "format", overrides_with = "no_plain")]
    plain: bool,
    /// The decorated report even when check.plain is true
    #[arg(long, overrides_with = "plain")]
    no_plain: bool,
    /// Colour the human report: auto, always or never; auto is off under NO_COLOR, SYSTEMLINT_NO_COLOR, TERM=dumb or off a terminal [default: check.color, else auto]
    #[arg(long, value_enum, value_name = "WHEN")]
    color: Option<Colour>,
    /// Add each failing rule’s rationale and references, from the global `--verbose`
    #[arg(skip)]
    verbose: bool,
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

/// Exit code after a Ctrl-C, the shell’s 128 plus SIGINT.
const EXIT_INTERRUPTED: i32 = 130;

/// Waits on its own thread for SIGINT, then says so, kills the running plugins and exits 130.
fn on_interrupt() {
    let mut signals = match signal_hook::iterator::Signals::new([signal_hook::consts::SIGINT]) {
        Ok(signals) => signals,
        Err(error) => return eprintln!("Ctrl-C leaves plugins running: {error}"),
    };
    std::thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            eprintln!("Interrupted, stopping plugins…");
            let stopped = runner::stop_children();
            log::debug!("signal {signal} stopped {stopped} children");
            std::process::exit(EXIT_INTERRUPTED);
        }
    });
}

fn main() -> ExitCode {
    if let Some(code) = runner::helper() {
        return code;
    }
    on_interrupt();
    crash::install();
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        eprint!("{SUMMARY}");
        return ExitCode::from(2);
    };
    trail::install(cli.verbose, cli.log_format);
    numbers::set(numbers::locale(|v| std::env::var(v).ok()));
    let mut config = match trail::scoped(trail::CONFIG, || {
        load_config(cli.config.as_deref(), !cli.no_project_config)
    })
    .map_err(fail(trail::CONFIG, EXIT_CONFIG))
    {
        Ok(config) => config,
        Err(code) => return ExitCode::from(code),
    };
    config.collect.jobs = cli.jobs.or(config.collect.jobs);
    config.collect.network = cli.network.then_some(true).or(config.collect.network);
    if !cli.container.is_empty() {
        config.collect.container = cli.container;
    }
    config.collect.containers = (cli.containers || !config.collect.container.is_empty())
        .then_some(true)
        .or(config.collect.containers);
    match command {
        Command::Facts {
            root,
            image_config,
            output,
            format,
        } => ExitCode::from(facts(
            &config,
            root.as_deref(),
            image_config,
            output.as_deref(),
            format.or(config.collect.format),
            cli.quiet,
        )),
        Command::Check {
            input,
            tags,
            all,
            prefer,
            fail_on,
            vars,
            look,
            output,
        } => ExitCode::from(lint(
            &config,
            &input,
            &Selection {
                tags: if all {
                    vec![rules::ALL.to_owned()]
                } else {
                    tags
                },
                prefer,
                vars,
            },
            fail_on,
            &Look {
                verbose: cli.verbose,
                ..look
            },
            output.as_deref(),
            cli.quiet,
        )),
        Command::Fix {
            root,
            tags,
            all,
            prefer,
            vars,
            dry_run,
            force,
            no_input,
        } => ExitCode::from(fix(
            &config,
            root.as_deref(),
            &Selection {
                tags: if all {
                    vec![rules::ALL.to_owned()]
                } else {
                    tags
                },
                prefer,
                vars,
            },
            Ask {
                dry_run,
                force,
                no_input,
            },
            cli.quiet,
        )),
        Command::Rules {
            format,
            lang,
            output,
        } => ExitCode::from(rule_pages(format, &lang, output.as_deref())),
        Command::Plugin(PluginCommand::List { format }) => ExitCode::from(plugin_list(
            &config,
            format.or(config.plugins.format) == Some(ListFormat::Json),
            cli.quiet,
        )),
    }
}

fn exe() -> PathBuf {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/systemlint"))
}

fn gather(
    config: &Config,
    root: Option<&Path>,
    image_config: Option<PathBuf>,
    quiet: bool,
) -> Result<(Value, bool), u8> {
    let (collectors, plugins, refusals) = trail::scoped(trail::DISCOVERY, || {
        let trust = Trust::invoking_user();
        let (mut collectors, mut refusals) = collector::load(
            &collector::directories(&exe(), &config.collect.directories),
            &trust,
        );
        for inline in config.collect.collectors.iter().cloned() {
            let id = inline.id.clone();
            match collector::admit(&collectors, inline) {
                Ok(c) => {
                    log::debug!("collector {id} from the configuration into {}", c.into);
                    collectors.push(c);
                }
                Err(reason) => refusals.push(discovery::Refusal {
                    path: PathBuf::from("collect.collectors"),
                    reason: format!("{id}: {reason}"),
                }),
            }
        }
        let (plugins, plugin_refusals) = discovery::discover(
            &discovery::directories(&exe(), discovery::BESIDE, &config.plugins.directories),
            &trust,
        );
        refusals.extend(plugin_refusals);
        (collectors, plugins, refusals)
    });
    print_refusals(trail::DISCOVERY, &refusals);
    let live = root.is_none();
    let root = trail::scoped(trail::INPUT, || Root::open(root.unwrap_or(Path::new("/"))))
        .map_err(fail(trail::INPUT, EXIT_INPUT))?;
    log::debug!(
        "collecting {} collectors with {} plugins from {} (live {live})",
        collectors.len(),
        plugins.len(),
        root.path().display()
    );
    let hash_key = match &config.collect.hash_key {
        Some(text) => collect::HashKey::configured(text),
        None => collect::HashKey::random().map_err(|error| {
            eprintln!("{error}");
            EXIT_INTERNAL
        })?,
    };
    let options = Options {
        root,
        live,
        privileged: rustix::process::geteuid().is_root(),
        now: SystemTime::now(),
        timeout: config
            .collect
            .timeout
            .map_or(collect::TIMEOUT, Duration::from_secs),
        hash_key,
        image_config,
        jobs: config
            .collect
            .jobs
            .and_then(|j| usize::try_from(j).ok())
            .unwrap_or_else(collect::default_jobs),
        network: config
            .collect
            .network
            .unwrap_or(false)
            .then(|| net::Proxies::from_env(|name| std::env::var(name).ok())),
        containers: config.collect.containers.unwrap_or(false),
        target: None,
    };
    log::debug!(
        "collect.jobs {:?}, running {} at once, network {:?}, containers {}",
        config.collect.jobs,
        options.jobs,
        options.network,
        options.containers
    );
    let started = Instant::now();
    let status = !quiet && !log::log_enabled!(log::Level::Debug) && std::io::stderr().is_terminal();
    let mut document = collected(
        &collectors,
        &plugins,
        &options,
        status,
        &options.root.path().display().to_string(),
    );
    if options.containers {
        containers(
            &collectors,
            &plugins,
            &options,
            &config.collect.container,
            &mut document,
            status,
            quiet,
        );
    }
    if let Some(line) = progress::finished(
        started.elapsed(),
        &progress::commands(&document, &collectors),
        &progress::reached(&document, &collectors),
    )
    .filter(|_| !quiet)
    {
        note(line);
    }
    if collectors.is_empty() && !quiet {
        note(format!(
            "No collectors found. Searched: {}",
            collector::directories(&exe(), &config.collect.directories)
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (target, id, outcome) in errors(&document) {
        let place = target.map(|t| format!(" in {t}")).unwrap_or_default();
        note(traced(
            &trail::collector(id),
            format!(
                "collector {id}{place}: {}",
                outcome["reason"].as_str().unwrap_or_default()
            ),
        ));
    }
    Ok((document, refusals.is_empty()))
}

/// Every collector that ended in error, the host’s first, then each container’s by its key.
fn errors(document: &Value) -> Vec<(Option<&str>, &str, &Value)> {
    std::iter::once((None, document))
        .chain(
            document["targets"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, d)| (Some(k.as_str()), d)),
        )
        .flat_map(|(target, doc)| {
            doc["collectors"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(_, o)| o["status"] == "error")
                .map(move |(id, o)| (target, id.as_str(), o))
        })
        .collect()
}

/// One collection, with a `Collecting` line on stderr naming `what` when `status` is on.
fn collected(
    collectors: &[collector::Collector],
    plugins: &[discovery::Plugin],
    options: &Options,
    status: bool,
    what: &str,
) -> Value {
    if status {
        eprint!("Collecting from {what}…");
    }
    let document =
        collect::collect_reporting(collectors, plugins, options, &mut |done, total, id| {
            if status {
                eprint!("\r\x1b[KCollecting from {what} {}/{total}: {id}…", done + 1);
            }
        });
    if status {
        eprint!("\r\x1b[K");
    }
    document
}

/// Collects every running container into `document`’s `targets`, keyed as [`targets::Found`] keys it, or says why none was.
fn containers(
    collectors: &[collector::Collector],
    plugins: &[discovery::Plugin],
    host: &Options,
    wanted: &[String],
    document: &mut Value,
    status: bool,
    quiet: bool,
) {
    let refused = match (host.live, host.privileged) {
        (false, _) => Some(format!(
            "reads running containers on the live host only, and --root {} was given",
            host.root.path().display()
        )),
        (_, false) => Some("needs root, and this run is unprivileged".to_owned()),
        _ => None,
    };
    if let Some(reason) = refused {
        log::debug!("containers not collected: {reason}");
        if !quiet {
            note(format!("Containers not checked: {reason}."));
        }
        document["meta"]["containers"] = serde_json::json!({"status": "skipped", "reason": reason});
        return;
    }
    let namespace = |pid: u32| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(format!("/proc/{pid}/ns/mnt"))
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    let mut found = targets::discover(&host.root, &namespace);
    log::debug!("{} containers found, wanted {wanted:?}", found.len());
    if !wanted.is_empty() {
        found.retain(|c| {
            let kept = wanted.iter().any(|w| c.named(w));
            log::debug!("container {} kept {kept}", c.key);
            kept
        });
        for pattern in wanted.iter().filter(|w| !found.iter().any(|c| c.named(w))) {
            log::debug!("--container {pattern} named no running container");
            if !quiet {
                note(format!(
                    "No running container matches --container {pattern}."
                ));
            }
        }
    }
    let workers = host.jobs.clamp(1, found.len().max(1));
    let jobs = (host.jobs / workers).max(1);
    let mut prepared = Vec::new();
    for container in found {
        let opened = Root::process(container.pid, container.inner).and_then(|root| {
            let status = std::fs::read_to_string(format!("/proc/{}/status", container.pid))?;
            Ok((root, runner::Inside::of(container.pid, &status)?))
        });
        let (root, inside) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                log::debug!("container {} not collected: {error}", container.key);
                continue;
            }
        };
        let mut subject = container.subject();
        subject["apparmor"] = Value::from(inside.apparmor.as_deref().unwrap_or("unconfined"));
        if inside.seccomp {
            log::debug!(
                "container {}: seccomp filter not applied to its commands",
                container.key
            );
            subject["seccomp"] = Value::from("filter not applied");
        }
        if let Some(paths) = container.upper.as_deref().and_then(targets::changed) {
            subject["changed"] = Value::from(paths);
        }
        let options = Options {
            root,
            live: true,
            privileged: true,
            now: host.now,
            timeout: host.timeout,
            hash_key: host.hash_key.clone(),
            image_config: None,
            jobs,
            network: None,
            containers: true,
            target: Some(collect::Target { inside, subject }),
        };
        prepared.push((container.key, options));
    }
    let total = prepared.len();
    log::debug!("{total} containers, {workers} at once, {jobs} collectors each");
    let queue = std::sync::Mutex::new(prepared);
    let done = std::sync::Mutex::new(Vec::with_capacity(total));
    let progress = |finished: usize| {
        if status {
            eprint!("\r\x1b[KCollecting from containers {finished}/{total}…");
        }
    };
    progress(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let Some((key, options)) = queue.lock().ok().and_then(|mut q| q.pop()) else {
                        break;
                    };
                    log::debug!("container {key}: collecting");
                    let collected = collect::collect_reporting(
                        collectors,
                        plugins,
                        &options,
                        &mut |_, _, _| {},
                    );
                    let Ok(mut documents) = done.lock() else {
                        break;
                    };
                    documents.push((key, collected));
                    progress(documents.len());
                }
            });
        }
    });
    if status {
        eprint!("\r\x1b[K");
    }
    let documents = done.into_inner().unwrap_or_default();
    document["targets"] = Value::Object(documents.into_iter().collect());
}

fn facts(
    config: &Config,
    root: Option<&Path>,
    image_config: Option<PathBuf>,
    output: Option<&Path>,
    format: Option<FactsFormat>,
    quiet: bool,
) -> u8 {
    let (document, trusted) = match gather(config, root, image_config, quiet) {
        Ok(gathered) => gathered,
        Err(code) => return code,
    };
    let saved = output.filter(|p| *p != Path::new("-"));
    log::debug!(
        "facts to {:?} as {:?}",
        output,
        format.map(|f| f == FactsFormat::Json)
    );
    let written = match (saved, format) {
        (Some(path), None) => document::save(&document, path),
        (path, format) => document::render(&document, format == Some(FactsFormat::Json))
            .and_then(|text| document::write(path.unwrap_or(Path::new("-")), &text, 0o600)),
    };
    if let Err(error) = written {
        eprintln!("{error}");
        return EXIT_OUTPUT;
    }
    let failed = errors(&document).len();
    if let Some(path) = saved.filter(|_| !quiet) {
        let ran = document["collectors"]
            .as_object()
            .map_or(0, serde_json::Map::len);
        eprintln!(
            "Saved facts from {} ({}) to {}. Check them with: systemlint check {}",
            plural(ran, "collector"),
            plural(failed, "error"),
            path.display(),
            path.display()
        );
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
        Some(path) => trail::scoped(trail::INPUT, || document::load(path))
            .map(|d| (d, true))
            .map_err(fail(trail::INPUT, EXIT_INPUT)),
        None => gather(
            config,
            input.root.as_deref(),
            input.image_config.clone(),
            quiet,
        ),
    }
}

fn library(config: &Config, vars: &Vars) -> Result<Library, u8> {
    let dirs = rules::directories(&exe(), &config.check.directories);
    let mut flags = vec![(
        "--var".to_owned(),
        vars.var
            .iter()
            .map(|(n, v)| (n.clone(), Value::from(v.as_str())))
            .collect(),
    )];
    if let Some(path) = &vars.vars {
        flags.push((
            format!("--vars {}", path.display()),
            trail::scoped(trail::CONFIG, || systemlint::vars::file(path))
                .map_err(fail(trail::CONFIG, EXIT_CONFIG))?,
        ));
    }
    let supplied = systemlint::vars::Supplied {
        flags,
        config: config.check.vars.clone(),
        ..Default::default()
    };
    let (library, refusals) = trail::scoped(trail::CONFIG, || {
        Library::load(
            &dirs,
            &Trust::invoking_user(),
            &config.check.rulesets,
            &supplied,
        )
    });
    print_refusals(trail::CONFIG, &refusals);
    let library = library.map_err(fail(trail::CONFIG, EXIT_CONFIG))?;
    log::debug!(
        "{} rulesets define {} rules, searched {}",
        library.rulesets.len(),
        library.definitions.len(),
        dirs.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if refusals.is_empty() {
        Ok(library)
    } else {
        Err(EXIT_CONFIG)
    }
}

/// The selected rules compiled, and how many rules a run with no `--tags` left out.
fn compiled(
    library: &Library,
    selection: &Selection,
    config: &Config,
) -> Result<(Vec<Rule>, usize), u8> {
    let base = if selection.tags.is_empty() {
        &config.check.tags
    } else {
        &selection.tags
    };
    let prefer = if selection.prefer.is_empty() {
        &config.check.prefer
    } else {
        &selection.prefer
    };
    let selected = trail::scoped(trail::CONFIG, || {
        library.select_for(base).and_then(|mut selected| {
            let left_out = left_out(&selected.left_out).filter(|_| selection.tags.is_empty());
            rules::prefer(&mut selected.rules, prefer);
            selected
                .rules
                .into_iter()
                .map(|(id, spec)| judge::compile(&id, spec))
                .collect::<Result<Vec<_>, _>>()
                .map(|rules| (rules, left_out.unwrap_or_default()))
        })
    });
    selected.map_err(fail(trail::CONFIG, EXIT_CONFIG))
}

/// How many rules the selection left out, each ruleset’s count logged; none when nothing was.
fn left_out(counts: &std::collections::BTreeMap<String, usize>) -> Option<usize> {
    let total: usize = counts.values().sum();
    log::debug!("{total} rules not selected: {counts:?}");
    (total > 0).then_some(total)
}

/// The error `line`, then each debug record kept under `tag`, indented on its own line.
fn traced(tag: &str, line: String) -> String {
    trail::take(tag)
        .iter()
        .fold(line, |out, record| format!("{out}\n  {record}"))
}

/// Prints an error with the debug records kept under `tag` beneath it, answering `code`.
fn fail(tag: &'static str, code: u8) -> impl FnOnce(String) -> u8 {
    move |error| {
        eprintln!("{}", traced(tag, error));
        code
    }
}

/// Every refusal on its own line, then the debug records kept under `tag` once beneath them all; none when nothing was refused.
fn refused(tag: &str, refusals: &[discovery::Refusal]) -> Option<String> {
    (!refusals.is_empty()).then(|| {
        traced(
            tag,
            refusals
                .iter()
                .map(|r| format!("refused {}: {}", r.path.display(), r.reason))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    })
}

/// Prints [`refused`] when anything was.
fn print_refusals(tag: &str, refusals: &[discovery::Refusal]) {
    if let Some(text) = refused(tag, refusals) {
        eprintln!("{text}");
    }
}

/// `1 collector`, `0 errors`: the count, then the noun, plural unless the count is one.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn today(now: SystemTime) -> String {
    collect::rfc3339(now)[..10].to_owned()
}

/// What `check` runs: the `--tags` selectors, the `--prefer` globs and the ruleset var values.
struct Selection {
    tags: Vec<String>,
    prefer: Vec<String>,
    vars: Vars,
}

fn lint(
    config: &Config,
    input: &Input,
    selection: &Selection,
    fail_on: Option<FailOn>,
    look: &Look,
    output: Option<&Path>,
    quiet: bool,
) -> u8 {
    let run = || -> Result<u8, u8> {
        let library = library(config, &selection.vars)?;
        let (rules, left_out) = if library.definitions.is_empty() {
            (Vec::new(), 0)
        } else {
            compiled(&library, selection, config)?
        };
        let fail_on = fail_on
            .or_else(|| config.check.fail_on.as_deref().and_then(|t| t.parse().ok()))
            .unwrap_or(FailOn::Level(rules::Severity::Error));
        let (mut document, trusted) = facts_for(config, input, quiet)?;
        let mut targets: Vec<(String, Value)> = match document["targets"].take() {
            Value::Object(map) => map.into_iter().collect(),
            _ => Vec::new(),
        };
        if let Some(map) = document.as_object_mut() {
            map.remove("targets");
        }
        let now = SystemTime::now();
        if input.facts.is_some() {
            let epoch = now
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let epoch = i64::try_from(epoch).unwrap_or(i64::MAX);
            for doc in std::iter::once(&mut document).chain(targets.iter_mut().map(|(_, d)| d)) {
                document::expire(doc, epoch);
            }
        }
        log::debug!(
            "linting facts of {} collected at {} with {} rules",
            document["meta"]["subject"],
            document["meta"]["collected-at"],
            rules.len()
        );
        if library.definitions.is_empty() && !quiet {
            note(format!(
                "No rules found. Searched: {}",
                rules::directories(&exe(), &config.check.directories)
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let host_waivers = judge::waivers_for(&config.check.waivers, None);
        let checks = judge::lint(&document, &rules, &host_waivers, &today(now));
        let judged: Vec<(String, Value, Vec<judge::Check>)> = targets
            .into_iter()
            .map(|(key, doc)| {
                let waivers = judge::waivers_for(&config.check.waivers, Some(&key));
                let checks = judge::lint(&doc, &rules, &waivers, &today(now));
                log::debug!("container {key}: {} checks", checks.len());
                (key, doc, checks)
            })
            .collect();
        let others: Vec<report::Target> = judged
            .iter()
            .map(|(k, d, c)| (k.as_str(), d, c.as_slice()))
            .collect();
        let terminal =
            output.is_none_or(|p| p == Path::new("-")) && std::io::stdout().is_terminal();
        let plain = if look.plain || look.no_plain || look.format.is_some() {
            look.plain
        } else {
            config.check.plain.unwrap_or(false)
        };
        let format = if plain {
            Format::Human
        } else {
            look.format.or(config.check.format).unwrap_or(Format::Human)
        };
        let color = look.color.or(config.check.color).unwrap_or(Colour::Auto);
        log::debug!("report as {format:?}, plain {plain}, colour {color:?}");
        let on = report::colour(color, |n| std::env::var(n).ok(), terminal);
        let human = |doc: &Value, checks: &[judge::Check], left_out: usize| {
            report::lint_human(doc, checks, left_out, quiet, look.verbose, on)
        };
        let text = match format {
            Format::Human if plain => others.iter().fold(
                report::lint_plain(&document, &checks, quiet),
                |out, (key, doc, checks)| {
                    format!(
                        "{out}target\t{key}\n{}",
                        report::lint_plain(doc, checks, quiet)
                    )
                },
            ),
            Format::Human if others.is_empty() => human(&document, &checks, left_out),
            Format::Human => report::lint_human_targets(
                &document,
                &checks,
                left_out,
                &others,
                (quiet, look.verbose, on),
            ),
            Format::Json => report::lint_json_targets(&document, &checks, &others),
            Format::Sarif => report::lint_sarif_targets(&document, &checks, &others),
            Format::Textfile => report::lint_textfile_targets(&document, &checks, &others),
        };
        let every: Vec<&judge::Check> = checks
            .iter()
            .chain(judged.iter().flat_map(|(_, _, c)| c))
            .collect();
        if format == Format::Human
            && output.is_none_or(|p| p == Path::new("-"))
            && NOTED.load(std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!();
        }
        document::write(output.unwrap_or(Path::new("-")), &text, 0o644).map_err(|error| {
            eprintln!("{error}");
            EXIT_OUTPUT
        })?;
        if let Some(path) = output.filter(|p| !quiet && *p != Path::new("-")) {
            eprintln!(
                "Wrote {} to {}.",
                plural(every.iter().filter(|c| c.is_failing()).count(), "finding"),
                path.display()
            );
        }
        let reached = std::iter::once(checks.as_slice())
            .chain(judged.iter().map(|(_, _, c)| c.as_slice()))
            .any(|c| fail_on.reached(c));
        let failed = u8::from(reached) * EXIT_FAIL;
        log::debug!("check exits on {failed} at {fail_on:?}, trusted {trusted}");
        Ok(if failed != 0 {
            failed
        } else if trusted {
            0
        } else {
            EXIT_PLUGIN
        })
    };
    run().unwrap_or_else(|code| code)
}

/// How `fix` gets its go-ahead.
struct Ask {
    dry_run: bool,
    force: bool,
    no_input: bool,
}

/// Whether the user typed y or yes after `question` on stderr.
fn confirmed(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let mut answer = String::new();
    let read = std::io::stdin().read_line(&mut answer);
    log::debug!("confirmation answered {answer:?} ({read:?})");
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

fn fix(config: &Config, root: Option<&Path>, selection: &Selection, ask: Ask, quiet: bool) -> u8 {
    if config.fix.enabled == Some(false) {
        eprintln!(
            "Fixing is off: fix.enabled is false in the configuration. Drop it, or set it to true, to let systemlint change files."
        );
        return EXIT_CONFIG;
    }
    let run = || -> Result<u8, u8> {
        let library = library(config, &selection.vars)?;
        let (rules, _) = if library.definitions.is_empty() {
            (Vec::new(), 0)
        } else {
            compiled(&library, selection, config)?
        };
        let (document, trusted) = gather(config, root, None, quiet)?;
        let systemlint::fix::Plan { changes, kept } = systemlint::fix::plan(
            &judge::lint(
                &document,
                &rules,
                &judge::waivers_for(&config.check.waivers, None),
                &today(SystemTime::now()),
            ),
            &rules,
            &document,
        );
        let base = root.unwrap_or(Path::new("/"));
        let shown = |change: &systemlint::fix::Change| {
            base.join(change.subject().trim_start_matches('/'))
                .display()
                .to_string()
        };
        for (change, reason) in &kept {
            eprintln!(
                "Kept {}: {reason}. Add another first, then fix again.",
                shown(change)
            );
        }
        let done = match (trusted, kept.is_empty()) {
            (_, false) => EXIT_FAIL,
            (true, true) => 0,
            (false, true) => EXIT_PLUGIN,
        };
        if changes.is_empty() {
            if !quiet && kept.is_empty() {
                eprintln!("Nothing to fix: no failing rule declares a remedy.");
            }
            return Ok(done);
        }
        log::debug!(
            "fix plans {} changes under {}",
            changes.len(),
            base.display()
        );
        let plan: String = changes
            .iter()
            .map(|c| c.remedy.command(&shown(c)) + "\n")
            .collect();
        document::write(Path::new("-"), &plan, 0).map_err(|error| {
            eprintln!("{error}");
            EXIT_OUTPUT
        })?;
        if ask.dry_run {
            return Ok(done);
        }
        if !ask.force {
            if ask.no_input || !std::io::stdin().is_terminal() {
                eprintln!(
                    "Pass --force to make {} without asking.",
                    plural(changes.len(), "change")
                );
                return Err(2);
            }
            if !confirmed(&format!("Make {}?", plural(changes.len(), "change"))) {
                eprintln!("Nothing changed.");
                return Err(EXIT_FAIL);
            }
        }
        let opened = trail::scoped(trail::INPUT, || Root::open(base))
            .map_err(fail(trail::INPUT, EXIT_INPUT))?;
        let mut failed = 0;
        for change in &changes {
            match systemlint::fix::apply(&opened, change) {
                Ok(Some((before, after))) => {
                    let line = format!("{}: {before} → {after}\n", shown(change));
                    if let Err(error) = document::write(Path::new("-"), &line, 0) {
                        log::debug!("{error}");
                    }
                }
                Ok(None) => log::debug!("{} already satisfies {}", change.path, change.rule),
                Err(error) => {
                    failed += 1;
                    eprintln!(
                        "{}",
                        systemlint::explain::io(
                            "change",
                            Path::new(&shown(change)),
                            &error,
                            &[(
                                std::io::ErrorKind::PermissionDenied,
                                "Run systemlint fix as root."
                            )]
                        )
                    );
                }
            }
        }
        log::debug!(
            "fix made {} changes, {failed} failed",
            changes.len() - failed
        );
        Ok(if failed > 0 { EXIT_FAIL } else { done })
    };
    run().unwrap_or_else(|code| code)
}

fn load_config(explicit: Option<&Path>, project: bool) -> Result<Config, String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    Config::layered(&config::layers(
        explicit,
        project,
        |n| std::env::var(n).ok(),
        &cwd,
    ))
}

/// The shipped rule catalog as YAML on stdout, or every rule page under `output`.
fn rule_pages(format: PagesFormat, lang: &str, output: Option<&Path>) -> u8 {
    let library = match trail::scoped(trail::CONFIG, Library::shipped)
        .map_err(fail(trail::CONFIG, EXIT_CONFIG))
    {
        Ok(library) => library,
        Err(code) => return code,
    };
    log::debug!(
        "rule pages lang {lang}, {} built-in rules",
        library.definitions.len()
    );
    match (format, output) {
        (PagesFormat::Markdown, Some(dir)) => match systemlint::pages::write_all(dir, &library) {
            Ok(count) => {
                let line = format!("{count} pages written to {}\n", dir.display());
                document::write(Path::new("-"), &line, 0).map_or_else(
                    |error| {
                        eprintln!("{error}");
                        EXIT_OUTPUT
                    },
                    |()| 0,
                )
            }
            Err(error) => {
                eprintln!("{error}");
                EXIT_OUTPUT
            }
        },
        (PagesFormat::Markdown, None) => 2,
        (PagesFormat::Yaml, _) => match systemlint::pages::catalog(&library) {
            Ok(text) => document::write(Path::new("-"), &text, 0).map_or_else(
                |error| {
                    eprintln!("{error}");
                    EXIT_OUTPUT
                },
                |()| 0,
            ),
            Err(error) => {
                eprintln!("{error}");
                EXIT_INTERNAL
            }
        },
    }
}

fn plugin_list(config: &Config, json: bool, quiet: bool) -> u8 {
    let dirs = discovery::directories(&exe(), discovery::BESIDE, &config.plugins.directories);
    let (plugins, refusals) = trail::scoped(trail::DISCOVERY, || {
        discovery::discover(&dirs, &Trust::invoking_user())
    });
    let mut problems: Vec<String> = refused(trail::DISCOVERY, &refusals).into_iter().collect();
    let mut listed = Vec::new();
    for plugin in plugins {
        match trail::scoped(&trail::plugin(&plugin.name), || {
            runner::describe(&plugin.name, &plugin.path, runner::DESCRIBE_TIMEOUT)
        }) {
            Ok(d) => listed.push(Listed {
                name: d.name,
                version: d.version,
                protocol: d.protocol,
                path: plugin.path,
                ops: d.ops,
            }),
            Err(error) => problems.push(traced(
                &trail::plugin(&plugin.name),
                format!(
                    "plugin {} at {}: {error}",
                    plugin.name,
                    plugin.path.display()
                ),
            )),
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
        eprintln!(
            "No plugins found. Searched: {}. A bare binary has none beside it: unpack the release archive, which puts plugins in lib/systemlint/plugins next to bin/systemlint, or name a directory in plugins.directories.",
            searched.join(", ")
        );
    }
    for problem in &problems {
        eprintln!("{problem}");
    }
    if problems.is_empty() { 0 } else { EXIT_PLUGIN }
}
