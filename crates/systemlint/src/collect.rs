// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Runs every collector against one subject and builds the facts document.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use systemlint_protocol::{
    Describe, Diagnostic, ExecInput, FileInput, Input, PROTOCOL, Reply, Request, VERSION,
};

use crate::collector::{Collector, overlaps, prefix};
use crate::discovery::Plugin;
use crate::runner::{self, MAX_CHILDREN, OUTPUT_CAP};
use crate::source::Root;
use crate::trail;

/// The facts document schema version written to `meta.schema`.
pub const SCHEMA: u32 = 1;

/// How long one collector command or one plugin call may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// How many collectors run at once by default: the CPUs this process may use, at most [`MAX_CHILDREN`].
pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_CHILDREN)
}

/// What a value a plugin marks secret is replaced with.
pub const REDACTED: &str = "[redacted]";

/// What a hashed value starts with.
pub const HASHED: &str = "hmac-sha256:";

/// How one collection runs.
#[derive(Debug)]
pub struct Options {
    pub root: Root,
    pub live: bool,
    pub privileged: bool,
    pub now: SystemTime,
    pub timeout: Duration,
    pub hash_key: HashKey,
    pub image_config: Option<PathBuf>,
    pub jobs: usize,
}

/// The key every value a plugin marks for hashing is keyed with: random per run unless the config sets one.
#[derive(Clone)]
pub struct HashKey {
    key: Vec<u8>,
    configured: bool,
}

impl std::fmt::Debug for HashKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HashKey({}, {})",
            if self.configured {
                "configured"
            } else {
                "random"
            },
            self.id()
        )
    }
}

impl HashKey {
    /// A fresh random 32-byte key from the kernel.
    pub fn random() -> Result<Self, String> {
        let mut key = vec![0u8; 32];
        let mut filled = 0;
        while filled < key.len() {
            filled +=
                rustix::rand::getrandom(&mut key[filled..], rustix::rand::GetRandomFlags::empty())
                    .map_err(|e| format!("can’t draw a random hash key: {e}"))?;
        }
        Ok(Self {
            key,
            configured: false,
        })
    }

    /// The key a configuration sets, so documents from several hosts compare.
    pub fn configured(text: &str) -> Self {
        Self {
            key: text.as_bytes().to_vec(),
            configured: true,
        }
    }

    /// `value` as `hmac-sha256:` and the hex HMAC-SHA256 under this key.
    pub fn hash(&self, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
        mac.update(value.as_bytes());
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{HASHED}{hex}")
    }

    /// A short public name for the key, equal in two documents exactly when their hashes compare.
    pub fn id(&self) -> String {
        self.hash("systemlint hash key id")[HASHED.len()..HASHED.len() + 16].to_owned()
    }
}

/// The facts document: `meta`, `collectors.<id>` outcomes, and every fact at the top level.
pub fn collect(collectors: &[Collector], plugins: &[Plugin], options: &Options) -> Value {
    collect_reporting(collectors, plugins, options, &mut |_, _, _| {})
}

/// Like [`collect`], calling `progress` with the number done, the number to run and the id before each collector runs.
pub fn collect_reporting(
    collectors: &[Collector],
    plugins: &[Plugin],
    options: &Options,
    progress: &mut dyn FnMut(usize, usize, &str),
) -> Value {
    let now = rfc3339(options.now);
    let (mut facts, mut outcomes, mut versions) = (Map::new(), Map::new(), Map::new());
    let mut described: HashMap<String, Result<Describe, String>> = HashMap::new();
    let mut planned = Vec::new();
    for (index, collector) in collectors.iter().enumerate() {
        let skip = match (
            collector.live && !options.live,
            collector.read.image_config && options.image_config.is_none(),
            collector.privileged && !options.privileged,
        ) {
            (true, _, _) => Some(format!(
                "reads the live host only, and --root {} was given",
                options.root.path().display()
            )),
            (_, true, _) => {
                Some("reads an image config, and no --image-config was given".to_owned())
            }
            (_, _, true) => Some("needs root, and this run is unprivileged".to_owned()),
            _ => None,
        };
        if let Some(reason) = skip {
            log::debug!("collector {} skipped: {reason}", collector.id);
            outcomes.insert(
                collector.id.clone(),
                json!({"status": "skipped", "reason": reason}),
            );
            continue;
        }
        if collector.read.exec.is_some()
            && !options.live
            && collector.read.files.is_empty()
            && collector.read.stat.is_empty()
            && collector.read.statfs.is_empty()
            && collector.read.named().next().is_none()
        {
            log::debug!("collector {} skipped: exec under --root", collector.id);
            outcomes.insert(collector.id.clone(), json!({"status": "skipped", "reason": format!("runs {} on a live host only, and --root {} was given", collector.read.exec.as_deref().unwrap_or_default()[0], options.root.path().display())}));
            continue;
        }
        match trail::scoped(&trail::collector(&collector.id), || {
            plan(collector, plugins, &mut described)
        }) {
            Ok((plugin, needs)) => {
                versions.insert(
                    plugin.name.clone(),
                    Value::from(
                        described[&plugin.name]
                            .as_ref()
                            .map(|d| d.version.clone())
                            .unwrap_or_default(),
                    ),
                );
                planned.push((index, plugin, needs));
            }
            Err(reason) => {
                log::debug!("collector {} can’t run: {reason}", collector.id);
                outcomes.insert(collector.id.clone(), error(reason));
            }
        }
    }
    let (total, jobs) = (planned.len(), options.jobs.clamp(1, MAX_CHILDREN));
    log::debug!("running {total} collectors, {jobs} at a time");
    let (sender, finished) = mpsc::channel();
    let mut running: Vec<usize> = Vec::new();
    std::thread::scope(|scope| {
        loop {
            while running.len() < jobs {
                let waits = |needs: &[String], me: usize| {
                    needs
                        .iter()
                        .cloned()
                        .chain(collectors[me].read.named().map(|p| prefix(p)))
                        .any(|n| {
                            planned
                                .iter()
                                .map(|(j, _, _)| *j)
                                .chain(running.iter().copied())
                                .any(|j| j != me && overlaps(&collectors[j].into, &n))
                        })
                };
                let Some(position) = planned.iter().position(|(i, _, needs)| !waits(needs, *i))
                else {
                    break;
                };
                let (index, plugin, needs) = planned.remove(position);
                let collector = &collectors[index];
                progress(total - planned.len() - 1, total, &collector.id);
                match trail::scoped(&trail::collector(&collector.id), || {
                    gather(collector, &needs, collectors, &facts, &outcomes).and_then(|given| {
                        Ok((given, named(collector, collectors, &facts, &outcomes)?))
                    })
                }) {
                    Ok((given, named)) => {
                        log::debug!(
                            "collector {} starts beside {} running",
                            collector.id,
                            running.len()
                        );
                        running.push(index);
                        let (sender, now) = (sender.clone(), &now);
                        scope.spawn(move || {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    trail::scoped(&trail::collector(&collector.id), || {
                                        run(collector, plugin, given, &named, options, now)
                                    })
                                }));
                            let _ = sender.send((index, plugin, result));
                        });
                    }
                    Err(reason) => record(&mut outcomes, collector, plugin, Err(reason)),
                }
            }
            if running.is_empty() {
                for (i, _, needs) in planned.drain(..) {
                    log::debug!(
                        "collector {} waits in a cycle on {}",
                        collectors[i].id,
                        needs.join(", ")
                    );
                    outcomes.insert(
                        collectors[i].id.clone(),
                        error(format!(
                            "needs {}, which wait on this collector in turn",
                            needs.join(", ")
                        )),
                    );
                }
                break;
            }
            let (index, plugin, result) = finished
                .recv()
                .unwrap_or_else(|_| unreachable!("this thread holds a sender"));
            running.retain(|&j| j != index);
            let collector = &collectors[index];
            let placed = result
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                .and_then(|(value, diagnostics, redacted, hashed)| {
                    place(&mut facts, &collector.into, value)
                        .map(|()| (diagnostics, redacted, hashed))
                });
            record(&mut outcomes, collector, plugin, placed);
        }
    });
    for collector in collectors {
        if let Some(outcome) = outcomes.get_mut(&collector.id) {
            outcome["into"] = Value::from(collector.into.clone());
        }
    }
    let mut subject = if options.live {
        json!({"kind": "host", "name": rustix::system::uname().nodename().to_string_lossy()})
    } else {
        json!({"kind": "root", "path": options.root.path()})
    };
    if let Some(path) = &options.image_config {
        subject["image-config"] = json!(path);
    }
    let hash_key = json!({"source": if options.hash_key.configured { "configured" } else { "random" }, "id": options.hash_key.id()});
    let meta = json!({"schema": SCHEMA, "systemlint": VERSION, "plugins": versions, "collected-at": now, "subject": subject, "privileged": options.privileged, "hash-key": hash_key});
    facts.insert("meta".to_owned(), meta);
    facts.insert("collectors".to_owned(), Value::Object(outcomes));
    Value::Object(facts)
}

/// Records how `collector` finished in `outcomes`.
fn record(
    outcomes: &mut Map<String, Value>,
    collector: &Collector,
    plugin: &Plugin,
    finished: Result<(Vec<Diagnostic>, Vec<String>, usize), String>,
) {
    let outcome = match finished {
        Ok((diagnostics, redacted, hashed)) => {
            log::debug!(
                "collector {} ok into {}, {} diagnostics, {} redacted, {hashed} hashed",
                collector.id,
                collector.into,
                diagnostics.len(),
                redacted.len()
            );
            let mut ok = json!({"status": "ok", "plugin": plugin.name, "op": collector.parse.op});
            if !diagnostics.is_empty() {
                ok["diagnostics"] = json!(diagnostics);
            }
            if !redacted.is_empty() {
                ok["redacted"] = json!(redacted);
            }
            if hashed > 0 {
                ok["hashed"] = json!(hashed);
            }
            ok
        }
        Err(reason) => {
            log::debug!("collector {} failed: {reason}", collector.id);
            error(reason)
        }
    };
    outcomes.insert(collector.id.clone(), outcome);
}

fn error(reason: String) -> Value {
    json!({"status": "error", "reason": reason})
}

fn plan<'p>(
    collector: &Collector,
    plugins: &'p [Plugin],
    described: &mut HashMap<String, Result<Describe, String>>,
) -> Result<(&'p Plugin, Vec<String>), String> {
    let name = &collector.parse.plugin;
    let plugin = plugins.iter().find(|p| &p.name == name).ok_or_else(|| {
        format!(
            "no trusted plugin systemlint-{name}; systemlint plugin list shows the installed ones"
        )
    })?;
    let describe = described
        .entry(name.clone())
        .or_insert_with(|| runner::describe(name, &plugin.path, runner::DESCRIBE_TIMEOUT))
        .as_ref()
        .map_err(|e| format!("plugin {name}: {e}"))?;
    let spec = describe
        .ops
        .iter()
        .find(|s| s.op == collector.parse.op)
        .ok_or_else(|| {
            format!(
                "plugin {name} has no op {}; systemlint plugin list shows its ops",
                collector.parse.op
            )
        })?;
    Ok((plugin, spec.needs.clone()))
}

fn gather(
    collector: &Collector,
    needs: &[String],
    collectors: &[Collector],
    facts: &Map<String, Value>,
    outcomes: &Map<String, Value>,
) -> Result<BTreeMap<String, Value>, String> {
    let mut given = BTreeMap::new();
    for need in needs {
        let Some(value) = lookup(facts, need) else {
            return Err(missing(collector, need, collectors, outcomes));
        };
        log::trace!("collector {} given {need}", collector.id);
        given.insert(need.clone(), value.clone());
    }
    Ok(given)
}

/// Why the fact `need` is absent: the collector that should have produced it and how it finished, or that none does.
fn missing(
    collector: &Collector,
    need: &str,
    collectors: &[Collector],
    outcomes: &Map<String, Value>,
) -> String {
    match collectors
        .iter()
        .find(|c| c.id != collector.id && overlaps(&c.into, need))
    {
        Some(p) => format!(
            "needs fact {need}, and collector {} finished {}",
            p.id,
            outcomes
                .get(&p.id)
                .and_then(|o| o["status"].as_str())
                .unwrap_or("without it")
        ),
        None => format!("needs fact {need}, which no collector produces"),
    }
}

/// The paths a collector reads, stats or statfs because facts name them.
#[derive(Debug, Default)]
pub struct Named {
    pub files: Vec<String>,
    pub stat: Vec<String>,
    pub statfs: Vec<String>,
}

/// The absolute paths at each `read.*-from` pattern, failing when a pattern’s literal prefix is absent.
pub fn named(
    collector: &Collector,
    collectors: &[Collector],
    facts: &Map<String, Value>,
    outcomes: &Map<String, Value>,
) -> Result<Named, String> {
    let resolve = |patterns: &[String]| -> Result<Vec<String>, String> {
        let mut paths = Vec::new();
        for pattern in patterns {
            let literal = prefix(pattern);
            let Some(start) = lookup(facts, &literal) else {
                return Err(missing(collector, &literal, collectors, outcomes));
            };
            let rest: Vec<&str> = pattern
                .split('.')
                .skip(literal.split('.').count())
                .collect();
            let before = paths.len();
            strings(start, &rest, &mut paths);
            log::debug!(
                "collector {}: {pattern} names {} paths",
                collector.id,
                paths.len() - before
            );
        }
        paths.retain(|p| {
            p.starts_with('/') || {
                log::debug!(
                    "collector {}: named path {p:?} is not absolute, skipped",
                    collector.id
                );
                false
            }
        });
        Ok(paths)
    };
    Ok(Named {
        files: resolve(&collector.read.files_from)?,
        stat: resolve(&collector.read.stat_from)?,
        statfs: resolve(&collector.read.statfs_from)?,
    })
}

/// Every string at `segments` under `value`, `*` matching each key, a list giving each of its strings, a map its keys.
fn strings(value: &Value, segments: &[&str], out: &mut Vec<String>) {
    match (segments.split_first(), value) {
        (None, Value::String(s)) => out.push(s.clone()),
        (None, Value::Object(map)) => out.extend(map.keys().cloned()),
        (None, Value::Array(items)) => {
            out.extend(items.iter().filter_map(Value::as_str).map(str::to_owned))
        }
        (Some((&"*", rest)), Value::Object(map)) => {
            map.values().for_each(|v| strings(v, rest, out))
        }
        (Some((key, rest)), Value::Object(map)) => map
            .get(*key)
            .into_iter()
            .for_each(|v| strings(v, rest, out)),
        _ => log::trace!(
            "named fact ends at a {} with {} segments left",
            if value.is_object() { "map" } else { "value" },
            segments.len()
        ),
    }
}

fn run(
    collector: &Collector,
    plugin: &Plugin,
    facts: BTreeMap<String, Value>,
    named: &Named,
    options: &Options,
    now: &str,
) -> Result<(Value, Vec<Diagnostic>, Vec<String>, usize), String> {
    let request = Request {
        protocol: PROTOCOL,
        op: collector.parse.op.clone(),
        root: options.root.path().display().to_string(),
        now: Some(now.to_owned()),
        inputs: read(collector, options, named)?,
        facts,
    };
    log::debug!(
        "collector {} sends {} inputs to {} {}",
        collector.id,
        request.inputs.len(),
        plugin.name,
        request.op
    );
    let body =
        serde_json::to_vec(&request).map_err(|e| format!("can’t encode the request: {e}"))?;
    let output = runner::call(&plugin.path, &[], Some(body), options.timeout, OUTPUT_CAP)
        .map_err(|e| format!("plugin {}: {e}", plugin.name))?;
    let reply: Reply = serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "plugin {} replied with invalid protocol JSON: {e}",
            plugin.name
        )
    })?;
    let mut value = Value::Object(reply.facts.into_iter().collect());
    let mut marked = reply.hash;
    if collector.secret {
        strings_at(&value, String::new(), &mut marked);
        marked.sort();
        marked.dedup();
        log::debug!(
            "collector {} is secret, {} strings to hash",
            collector.id,
            marked.len()
        );
    }
    let hashed = hash(&mut value, &marked, &options.hash_key, &collector.id);
    let mut redacted = Vec::new();
    for pointer in reply.redact {
        match value.pointer_mut(&pointer) {
            Some(secret) => {
                *secret = Value::from(REDACTED);
                redacted.push(pointer);
            }
            None => log::debug!("collector {}: redact {pointer} names no fact", collector.id),
        }
    }
    Ok((value, reply.diagnostics, redacted, hashed))
}

/// The JSON Pointer of every string under `value`, appended to `out`.
fn strings_at(value: &Value, pointer: String, out: &mut Vec<String>) {
    let escape = |key: &str| key.replace('~', "~0").replace('/', "~1");
    match value {
        Value::String(_) => out.push(pointer),
        Value::Object(map) => map
            .iter()
            .for_each(|(k, v)| strings_at(v, format!("{pointer}/{}", escape(k)), out)),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .for_each(|(i, v)| strings_at(v, format!("{pointer}/{i}"), out)),
        _ => {}
    }
}

/// Replaces each non-empty string the `pointers` name with its keyed hash, returning how many were hashed.
pub fn hash(value: &mut Value, pointers: &[String], key: &HashKey, collector: &str) -> usize {
    let mut hashed = 0;
    for pointer in pointers {
        match value.pointer_mut(pointer) {
            Some(Value::String(text)) if !text.is_empty() => {
                *text = key.hash(text);
                hashed += 1;
            }
            Some(Value::String(_)) => {
                log::trace!("collector {collector}: hash {pointer} is empty, kept")
            }
            Some(other) => log::debug!(
                "collector {collector}: hash {pointer} names a {}, not a string",
                if other.is_object() {
                    "object"
                } else {
                    "non-string"
                }
            ),
            None => log::debug!("collector {collector}: hash {pointer} names no fact"),
        }
    }
    hashed
}

/// Reads every source of `collector`: file contents and stats merged by path, then the command.
pub fn inputs(collector: &Collector, options: &Options) -> Result<Vec<Input>, String> {
    read(collector, options, &Named::default())
}

/// Like [`inputs`], adding the `named` paths, taken literally, never as globs.
pub fn read(collector: &Collector, options: &Options, named: &Named) -> Result<Vec<Input>, String> {
    let root = &options.root;
    let mut files: BTreeMap<String, FileInput> = BTreeMap::new();
    let blank = |path: &str| FileInput {
        path: path.to_owned(),
        content: None,
        content_base64: None,
        stat: None,
        statfs: None,
        absent: false,
    };
    let globbed = |patterns: &[String]| -> Result<Vec<String>, String> {
        patterns.iter().try_fold(Vec::new(), |mut all, p| {
            all.extend(root.glob(p)?);
            Ok(all)
        })
    };
    let reads: BTreeSet<String> = globbed(&collector.read.files)?
        .into_iter()
        .chain(named.files.iter().cloned())
        .collect();
    for path in reads {
        match root.read(&path, OUTPUT_CAP) {
            Ok(bytes) => {
                let entry = files.entry(path.clone()).or_insert_with(|| blank(&path));
                match String::from_utf8(bytes) {
                    Ok(text) => entry.content = Some(text),
                    Err(e) => entry.content_base64 = Some(base64(e.as_bytes())),
                }
            }
            Err(e) if gone(&e) => log::debug!("collector {}: {path} is absent", collector.id),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => log::debug!(
                "collector {}: {path} is not a regular file, skipped",
                collector.id
            ),
            Err(e) => return Err(format!("can’t read {path}: {e}")),
        }
    }
    let stats: BTreeSet<String> = globbed(&collector.read.stat)?
        .into_iter()
        .chain(named.stat.iter().cloned())
        .collect();
    let keep = match &collector.read.stat_keep {
        Some(schema) => Some(crate::judge::schema(schema)?),
        None => None,
    };
    let (total, mut dropped) = (stats.len(), 0);
    for path in stats {
        match root.stat(&path) {
            Ok(stat)
                if keep.as_ref().is_some_and(|k| {
                    !k.is_valid(&serde_json::to_value(&stat).unwrap_or_default())
                }) =>
            {
                dropped += 1;
            }
            Ok(mut stat) => {
                if !collector.read.hash.is_empty()
                    && stat.kind == systemlint_protocol::FileKind::File
                {
                    match root.digests(&path, &collector.read.hash) {
                        Ok((sha256, sha512)) => (stat.sha256, stat.sha512) = (sha256, sha512),
                        Err(e) if gone(&e) || e.kind() == io::ErrorKind::InvalidInput => {
                            log::debug!(
                                "collector {}: {path} changed before hashing, no digest",
                                collector.id
                            )
                        }
                        Err(e) => return Err(format!("can’t hash {path}: {e}")),
                    }
                }
                files
                    .entry(path.clone())
                    .or_insert_with(|| blank(&path))
                    .stat = Some(stat);
            }
            Err(e) if gone(&e) && collector.inline => {
                log::debug!(
                    "collector {}: {path} is absent, passed as absent",
                    collector.id
                );
                files
                    .entry(path.clone())
                    .or_insert_with(|| blank(&path))
                    .absent = true;
            }
            Err(e) if gone(&e) => log::debug!("collector {}: {path} is absent", collector.id),
            Err(e) => return Err(format!("can’t stat {path}: {e}")),
        }
    }
    if keep.is_some() {
        log::debug!(
            "collector {}: read.stat-keep kept {} of {total} stats",
            collector.id,
            total - dropped
        );
    }
    let filesystems: BTreeSet<String> = globbed(&collector.read.statfs)?
        .into_iter()
        .chain(named.statfs.iter().cloned())
        .collect();
    for path in filesystems {
        match root.statfs(&path, options.timeout) {
            Ok(statfs) => {
                files
                    .entry(path.clone())
                    .or_insert_with(|| blank(&path))
                    .statfs = Some(statfs);
            }
            Err(e) if gone(&e) => log::debug!("collector {}: {path} is absent", collector.id),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => log::debug!(
                "collector {}: {path} refused statfs, left out",
                collector.id
            ),
            Err(e) => return Err(format!("can’t statfs {path}: {e}")),
        }
    }
    if let (true, Some(path)) = (collector.read.image_config, &options.image_config) {
        let text = image_config(path)?;
        log::debug!(
            "collector {}: image config {} has {} bytes",
            collector.id,
            path.display(),
            text.len()
        );
        let name = path.display().to_string();
        files.insert(
            name.clone(),
            FileInput {
                content: Some(text),
                ..blank(&name)
            },
        );
    }
    let mut inputs: Vec<Input> = files.into_values().map(Input::File).collect();
    match &collector.read.exec {
        Some(argv) if !options.live => log::debug!(
            "collector {}: {} not run under --root",
            collector.id,
            argv[0]
        ),
        Some(argv) if matches!(root.stat(&argv[0]), Err(e) if e.kind() == io::ErrorKind::NotFound) =>
        {
            log::debug!(
                "collector {}: {} is absent, passed as exit 127",
                collector.id,
                argv[0]
            );
            inputs.push(Input::Exec(ExecInput {
                argv: argv.clone(),
                stdout: String::new(),
                stderr: format!("{}: not found\n", argv[0]),
                exit: 127,
            }));
        }
        Some(argv) => {
            let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
            let output = runner::run(
                Path::new(&argv[0]),
                &args,
                None,
                options.timeout,
                OUTPUT_CAP,
            )
            .map_err(|e| format!("{}: {e}", argv[0]))?;
            let exit = output.code();
            inputs.push(Input::Exec(ExecInput {
                argv: argv.clone(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit,
            }));
        }
        None => {}
    }
    Ok(inputs)
}

/// Whether `error` says the path is not there, a process that exited mid-read included.
pub fn gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) || error.raw_os_error() == Some(libc::ESRCH)
}

/// The image config the operator named, a host file outside any root, as text under the output cap.
fn image_config(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("can’t read image config {}: {e}", path.display()))?;
    let mut text = String::new();
    io::Read::read_to_string(&mut io::Read::take(file, OUTPUT_CAP + 1), &mut text)
        .map_err(|e| format!("can’t read image config {}: {e}", path.display()))?;
    if text.len() as u64 > OUTPUT_CAP {
        return Err(format!(
            "image config {} is larger than {OUTPUT_CAP} bytes",
            path.display()
        ));
    }
    Ok(text)
}

/// The value at dotted `path` in `facts`.
pub fn lookup<'a>(facts: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = path.split('.');
    let first = facts.get(segments.next()?)?;
    segments.try_fold(first, |value, key| value.get(key))
}

fn place(facts: &mut Map<String, Value>, path: &str, value: Value) -> Result<(), String> {
    let segments: Vec<&str> = path.split('.').collect();
    let (last, parents) = segments.split_last().ok_or("into is empty")?;
    let mut map = facts;
    for segment in parents {
        let slot = map
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        map = slot
            .as_object_mut()
            .ok_or_else(|| format!("into {path} crosses {segment}, which holds a value"))?;
    }
    map.insert((*last).to_owned(), value);
    Ok(())
}

/// `time` as RFC 3339 UTC to the second.
pub fn rfc3339(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Standard padded base64 of `bytes`.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}
