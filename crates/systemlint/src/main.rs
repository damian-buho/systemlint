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
use systemlint::report::{self, Colour, FailOn, Format};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint::{collector, comply, crash, document, progress, rules, runner, trail};
use systemlint_protocol::{OpSpec, VERSION};

/// Exit code when `check` finds failures at `--fail-on` or a `--standard` is not complied with, or a `facts` collector failed.
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

/// Help laid out description, examples, usage, commands and flags, then the notes and links.
const TEMPLATE: &str =
    "{about-with-newline}\n{before-help}{usage-heading} {usage}\n\n{all-args}{after-help}";

/// What `systemlint` with no arguments prints: the description, two examples, the common flags and where the rest is.
const SUMMARY: &str = "Collects operating system facts and lints them with declarative rules.\n\nExamples:\n  systemlint check\n  systemlint facts -o host.facts.yaml\n\nCommands: facts, check, plugin\nCommon flags: --root DIR, --tags LIST, -o PATH, --format FORMAT\nEvery command and flag: systemlint --help, systemlint <command> --help\nDocs: https://kiota.ch/damian-buho/systemlint\n";

/// Collects operating system facts and lints them with declarative rules.
#[derive(Parser)]
#[command(name = "systemlint", version = VERSION, help_template = TEMPLATE)]
#[command(
    before_help = "Examples:\n  systemlint check\n  systemlint facts --root /mnt/image -o image.facts.yaml\n  systemlint check image.facts.yaml\n  systemlint check --standard dev-sec-ssh-baseline\n  systemlint plugin list"
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
    /// Run the containers: true collectors, which read the environment of every running container [default: collect.containers, else off]
    #[arg(long, global = true)]
    containers: bool,
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
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint check\n  systemlint check host.facts.yaml --tags sshd,apt\n  systemlint check --root rootfs --format sarif -o systemlint.sarif")]
    #[command(
        after_help = "Exit codes: 0 clean, 1 failures at --fail-on, 2 bad arguments, 4 a plugin or collector refused, 5 config, rules or catalog, 6 unreadable facts or --root, 7 --output can’t be written, 70 no random hash key.\nWith --standard: 0 compliant, 1 non-compliant, 3 indeterminate, whatever --fail-on says.\nDocs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/rules.md#check-output-and-exit-codes"
    )]
    Check {
        #[command(flatten)]
        input: Input,
        /// Rules to run, comma-separated: rulesets, rule IDs and tags, globs allowed, !x removes [default: check.tags, else default]
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        tags: Vec<String>,
        /// Also run the rules tagged STANDARD:<control> and answer per control; repeatable
        #[arg(long, value_name = "STANDARD")]
        standard: Vec<String>,
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
    #[command(help_template = TEMPLATE, before_help = "Examples:\n  systemlint fix --dry-run\n  sudo systemlint fix --tags files\n  systemlint fix --root rootfs --force")]
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
    /// Inspect the installed plugins
    #[command(subcommand, help_template = TEMPLATE, before_help = "Examples:\n  systemlint plugin list")]
    #[command(
        after_help = "Docs: https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md#discovery-and-trust"
    )]
    Plugin(PluginCommand),
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

/// On SIGINT: says so, kills the running plugins and exits 130, through async-signal-safe calls only.
extern "C" fn interrupted(_: libc::c_int) {
    const MESSAGE: &str = "Interrupted, stopping plugins…\n";
    // SAFETY: write, kill and _exit are async-signal-safe, and MESSAGE is static.
    unsafe { libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len()) };
    runner::stop_children();
    // SAFETY: _exit skips the destructors and buffers a handler must not run.
    unsafe { libc::_exit(EXIT_INTERRUPTED) };
}

fn main() -> ExitCode {
    // SAFETY: restores the default SIGPIPE action Rust’s runtime set to ignore, before any thread starts, so a closed pipe ends the run silently.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    // SAFETY: installs a handler that only calls async-signal-safe functions, before any thread starts.
    unsafe { libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t) };
    crash::install();
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        eprint!("{SUMMARY}");
        return ExitCode::from(2);
    };
    trail::install(cli.verbose, cli.log_format);
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
    config.collect.containers = cli.containers.then_some(true).or(config.collect.containers);
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
            standard,
            fail_on,
            vars,
            look,
            output,
        } => ExitCode::from(lint(
            &config,
            &input,
            &Selection {
                tags,
                standards: standard,
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
            vars,
            dry_run,
            force,
            no_input,
        } => ExitCode::from(fix(
            &config,
            root.as_deref(),
            &Selection {
                tags,
                standards: vec![],
                vars,
            },
            Ask {
                dry_run,
                force,
                no_input,
            },
            cli.quiet,
        )),
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
    if status {
        eprint!("Collecting from {}…", options.root.path().display());
    }
    let document =
        collect::collect_reporting(&collectors, &plugins, &options, &mut |done, total, id| {
            if status {
                eprint!("\r\x1b[KCollecting {}/{total}: {id}…", done + 1);
            }
        });
    if status {
        eprint!("\r\x1b[K");
    }
    if let Some(line) = progress::finished(
        started.elapsed(),
        &progress::commands(&document, &collectors),
        &progress::reached(&document, &collectors),
    )
    .filter(|_| !quiet)
    {
        eprintln!("{line}");
    }
    if collectors.is_empty() && !quiet {
        eprintln!(
            "No collectors found. Searched: {}",
            collector::directories(&exe(), &config.collect.directories)
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(outcomes) = document["collectors"].as_object() {
        for (id, outcome) in outcomes.iter().filter(|(_, o)| o["status"] == "error") {
            eprintln!(
                "{}",
                traced(
                    &trail::collector(id),
                    format!(
                        "collector {id}: {}",
                        outcome["reason"].as_str().unwrap_or_default()
                    )
                )
            );
        }
    }
    Ok((document, refusals.is_empty()))
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
    let failed = document["collectors"]
        .as_object()
        .map_or(0, |o| o.values().filter(|c| c["status"] == "error").count());
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

/// The selected rules compiled; with no `--tags` or `--standard` and unless `quiet`, one stderr line names the rules left out.
fn compiled(
    library: &Library,
    selection: &Selection,
    config: &Config,
    quiet: bool,
) -> Result<Vec<Rule>, u8> {
    let base = if selection.tags.is_empty() {
        &config.check.tags
    } else {
        &selection.tags
    };
    let selected = trail::scoped(trail::CONFIG, || {
        library
            .select_for(base, &selection.standards)
            .and_then(|selected| {
                let implicit = selection.tags.is_empty() && selection.standards.is_empty();
                if let Some(line) = left_out(&selected.left_out).filter(|_| implicit && !quiet) {
                    eprintln!("{line}");
                }
                selected
                    .rules
                    .into_iter()
                    .map(|(id, spec)| judge::compile(&id, spec))
                    .collect::<Result<Vec<_>, _>>()
            })
    });
    selected.map_err(fail(trail::CONFIG, EXIT_CONFIG))
}

/// `12 rules not selected: performance (9), containers (3).`, with how to run them; none when nothing was left out.
fn left_out(counts: &std::collections::BTreeMap<String, usize>) -> Option<String> {
    let total: usize = counts.values().sum();
    log::debug!("{total} rules not selected in {} rulesets", counts.len());
    (total > 0).then(|| {
        let each: Vec<String> = counts.iter().map(|(r, n)| format!("{r} ({n})")).collect();
        format!(
            "{} not selected: {}. Name them in --tags to run them.",
            plural(total, "rule"),
            each.join(", ")
        )
    })
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

fn today() -> String {
    collect::rfc3339(SystemTime::now())[..10].to_owned()
}

/// What `check` runs: the `--tags` selectors, the standards to answer and the ruleset var values.
struct Selection {
    tags: Vec<String>,
    standards: Vec<String>,
    vars: Vars,
}

/// The catalog of each standard, from the rules directories or their `standards` siblings.
fn catalogs(config: &Config, standards: &[String]) -> Result<Vec<Option<comply::Catalog>>, u8> {
    let dirs = comply::directories(&rules::directories(&exe(), &config.check.directories));
    let mut out = Vec::new();
    for standard in standards {
        let (catalog, refusals) = trail::scoped(trail::CONFIG, || {
            comply::catalog(&dirs, &Trust::invoking_user(), standard)
        });
        print_refusals(trail::CONFIG, &refusals);
        let catalog = catalog.map_err(fail(trail::CONFIG, EXIT_CONFIG))?;
        if !refusals.is_empty() {
            return Err(EXIT_CONFIG);
        }
        log::debug!("standard {standard} has a catalog: {}", catalog.is_some());
        out.push(catalog);
    }
    Ok(out)
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
        let rules = if library.definitions.is_empty() {
            Vec::new()
        } else {
            compiled(&library, selection, config, quiet)?
        };
        let catalogs = catalogs(config, &selection.standards)?;
        let fail_on = fail_on
            .or_else(|| config.check.fail_on.as_deref().and_then(|t| t.parse().ok()))
            .unwrap_or(FailOn::Level(rules::Severity::Error));
        let (document, trusted) = facts_for(config, input, quiet)?;
        log::debug!(
            "linting facts of {} collected at {} with {} rules",
            document["meta"]["subject"],
            document["meta"]["collected-at"],
            rules.len()
        );
        if library.definitions.is_empty() && !quiet {
            eprintln!(
                "No rules found. Searched: {}",
                rules::directories(&exe(), &config.check.directories)
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let checks = judge::lint(&document, &rules, &config.check.waivers, &today());
        let compliance: Vec<comply::Report> = selection
            .standards
            .iter()
            .zip(&catalogs)
            .map(|(standard, catalog)| comply::comply(standard, &rules, &checks, catalog.as_ref()))
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
        let text = match format {
            Format::Human if plain => report::lint_plain(&document, &checks, &compliance, quiet),
            Format::Human => report::lint_human(
                &document,
                &checks,
                &compliance,
                quiet,
                look.verbose,
                report::colour(color, |n| std::env::var(n).ok(), terminal),
            ),
            Format::Json => report::lint_json(&document, &checks, &compliance),
            Format::Sarif => report::lint_sarif(&document, &checks, &compliance),
            Format::Textfile => report::lint_textfile(&document, &checks, &compliance),
        };
        document::write(output.unwrap_or(Path::new("-")), &text, 0o644).map_err(|error| {
            eprintln!("{error}");
            EXIT_OUTPUT
        })?;
        if let Some(path) = output.filter(|p| !quiet && *p != Path::new("-")) {
            eprintln!(
                "Wrote {} to {}.",
                plural(checks.iter().filter(|c| c.is_failing()).count(), "finding"),
                path.display()
            );
        }
        let failed = if compliance.is_empty() {
            u8::from(fail_on.reached(&checks)) * EXIT_FAIL
        } else {
            comply::overall(&compliance).code()
        };
        log::debug!(
            "check exits on {failed} from {} standards, trusted {trusted}",
            compliance.len()
        );
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
        let rules = if library.definitions.is_empty() {
            Vec::new()
        } else {
            compiled(&library, selection, config, quiet)?
        };
        let (document, trusted) = gather(config, root, None, quiet)?;
        let systemlint::fix::Plan { changes, kept } = systemlint::fix::plan(
            &judge::lint(&document, &rules, &config.check.waivers, &today()),
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
                Ok(Some((before, after))) => println!("{}: {before} → {after}", shown(change)),
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
