// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Runs every collector against one subject and builds the facts document.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint_protocol::{Describe, Diagnostic, ExecInput, FileInput, Input, PROTOCOL, Reply, Request, VERSION};

use crate::collector::{Collector, overlaps};
use crate::discovery::Plugin;
use crate::runner::{self, OUTPUT_CAP};
use crate::source::Root;

/// The facts document schema version written to `meta.schema`.
pub const SCHEMA: u32 = 1;

/// How long one collector command or one plugin call may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// What a value a plugin marks secret is replaced with.
pub const REDACTED: &str = "[redacted]";

/// How one collection runs.
#[derive(Debug)]
pub struct Options {
    pub root: Root,
    pub live: bool,
    pub now: SystemTime,
    pub timeout: Duration,
}

/// The facts document: `meta`, `collectors.<id>` outcomes, and every fact at the top level.
pub fn collect(collectors: &[Collector], plugins: &[Plugin], options: &Options) -> Value {
    let now = rfc3339(options.now);
    let (mut facts, mut outcomes, mut versions) = (Map::new(), Map::new(), Map::new());
    let mut described: HashMap<String, Result<Describe, String>> = HashMap::new();
    let mut planned = Vec::new();
    for (index, collector) in collectors.iter().enumerate() {
        if collector.read.exec.is_some() && !options.live && collector.read.files.is_empty() && collector.read.stat.is_empty() {
            log::debug!("collector {} skipped: exec under --root", collector.id);
            outcomes.insert(collector.id.clone(), json!({"status": "skipped", "reason": format!("runs {} on a live host only, and --root {} was given", collector.read.exec.as_deref().unwrap_or_default()[0], options.root.path().display())}));
            continue;
        }
        match plan(collector, plugins, &mut described) {
            Ok((plugin, needs)) => {
                versions.insert(plugin.name.clone(), Value::from(described[&plugin.name].as_ref().map(|d| d.version.clone()).unwrap_or_default()));
                planned.push((index, plugin, needs));
            }
            Err(reason) => {
                log::debug!("collector {} can’t run: {reason}", collector.id);
                outcomes.insert(collector.id.clone(), error(reason));
            }
        }
    }
    while !planned.is_empty() {
        let waits = |needs: &[String], me: usize| needs.iter().any(|n| planned.iter().any(|(j, _, _)| *j != me && overlaps(&collectors[*j].into, n)));
        let Some(position) = planned.iter().position(|(i, _, needs)| !waits(needs, *i)) else {
            for (i, _, needs) in planned.drain(..) {
                log::debug!("collector {} waits in a cycle on {}", collectors[i].id, needs.join(", "));
                outcomes.insert(collectors[i].id.clone(), error(format!("needs {}, which wait on this collector in turn", needs.join(", "))));
            }
            break;
        };
        let (index, plugin, needs) = planned.remove(position);
        let collector = &collectors[index];
        let outcome = gather(collector, &needs, collectors, &facts, &outcomes)
            .and_then(|given| run(collector, plugin, given, options, &now))
            .and_then(|(value, diagnostics, redacted)| place(&mut facts, &collector.into, value).map(|()| (diagnostics, redacted)));
        let outcome = match outcome {
            Ok((diagnostics, redacted)) => {
                log::debug!("collector {} ok into {}, {} diagnostics, {} redacted", collector.id, collector.into, diagnostics.len(), redacted.len());
                let mut ok = json!({"status": "ok", "plugin": plugin.name, "op": collector.parse.op});
                if !diagnostics.is_empty() {
                    ok["diagnostics"] = json!(diagnostics);
                }
                if !redacted.is_empty() {
                    ok["redacted"] = json!(redacted);
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
    for collector in collectors {
        if let Some(outcome) = outcomes.get_mut(&collector.id) {
            outcome["into"] = Value::from(collector.into.clone());
        }
    }
    let subject = if options.live {
        json!({"kind": "host", "name": rustix::system::uname().nodename().to_string_lossy()})
    } else {
        json!({"kind": "root", "path": options.root.path()})
    };
    let meta = json!({"schema": SCHEMA, "systemlint": VERSION, "plugins": versions, "collected-at": now, "subject": subject, "privileged": rustix::process::geteuid().is_root()});
    facts.insert("meta".to_owned(), meta);
    facts.insert("collectors".to_owned(), Value::Object(outcomes));
    Value::Object(facts)
}

fn error(reason: String) -> Value {
    json!({"status": "error", "reason": reason})
}

fn plan<'p>(collector: &Collector, plugins: &'p [Plugin], described: &mut HashMap<String, Result<Describe, String>>) -> Result<(&'p Plugin, Vec<String>), String> {
    let name = &collector.parse.plugin;
    let plugin = plugins.iter().find(|p| &p.name == name).ok_or_else(|| format!("no trusted plugin systemlint-{name}; systemlint plugin list shows the installed ones"))?;
    let describe = described.entry(name.clone()).or_insert_with(|| runner::describe(name, &plugin.path, runner::DESCRIBE_TIMEOUT)).as_ref().map_err(|e| format!("plugin {name}: {e}"))?;
    let spec = describe.ops.iter().find(|s| s.op == collector.parse.op).ok_or_else(|| format!("plugin {name} has no op {}; systemlint plugin list shows its ops", collector.parse.op))?;
    Ok((plugin, spec.needs.clone()))
}

fn gather(collector: &Collector, needs: &[String], collectors: &[Collector], facts: &Map<String, Value>, outcomes: &Map<String, Value>) -> Result<BTreeMap<String, Value>, String> {
    let mut given = BTreeMap::new();
    for need in needs {
        let Some(value) = lookup(facts, need) else {
            let producer = collectors.iter().find(|c| c.id != collector.id && overlaps(&c.into, need));
            return Err(match producer {
                Some(p) => format!("needs fact {need}, and collector {} finished {}", p.id, outcomes.get(&p.id).and_then(|o| o["status"].as_str()).unwrap_or("without it")),
                None => format!("needs fact {need}, which no collector produces"),
            });
        };
        log::trace!("collector {} given {need}", collector.id);
        given.insert(need.clone(), value.clone());
    }
    Ok(given)
}

fn run(collector: &Collector, plugin: &Plugin, facts: BTreeMap<String, Value>, options: &Options, now: &str) -> Result<(Value, Vec<Diagnostic>, Vec<String>), String> {
    let request = Request { protocol: PROTOCOL, op: collector.parse.op.clone(), root: options.root.path().display().to_string(), now: Some(now.to_owned()), inputs: inputs(collector, options)?, facts };
    log::debug!("collector {} sends {} inputs to {} {}", collector.id, request.inputs.len(), plugin.name, request.op);
    let body = serde_json::to_vec(&request).map_err(|e| format!("can’t encode the request: {e}"))?;
    let output = runner::call(&plugin.path, &[], Some(body), options.timeout, OUTPUT_CAP).map_err(|e| format!("plugin {}: {e}", plugin.name))?;
    let reply: Reply = serde_json::from_slice(&output.stdout).map_err(|e| format!("plugin {} replied with invalid protocol JSON: {e}", plugin.name))?;
    let mut value = Value::Object(reply.facts.into_iter().collect());
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
    Ok((value, reply.diagnostics, redacted))
}

/// Reads every source of `collector`: file contents and stats merged by path, then the command.
pub fn inputs(collector: &Collector, options: &Options) -> Result<Vec<Input>, String> {
    let root = &options.root;
    let mut files: BTreeMap<String, FileInput> = BTreeMap::new();
    let blank = |path: &str| FileInput { path: path.to_owned(), content: None, content_base64: None, stat: None };
    for pattern in &collector.read.files {
        for path in root.glob(pattern)? {
            match root.read(&path, OUTPUT_CAP) {
                Ok(bytes) => {
                    let entry = files.entry(path.clone()).or_insert_with(|| blank(&path));
                    match String::from_utf8(bytes) {
                        Ok(text) => entry.content = Some(text),
                        Err(e) => entry.content_base64 = Some(base64(e.as_bytes())),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => log::debug!("collector {}: {path} is absent", collector.id),
                Err(e) => return Err(format!("can’t read {path}: {e}")),
            }
        }
    }
    for pattern in &collector.read.stat {
        for path in root.glob(pattern)? {
            match root.stat(&path) {
                Ok(stat) => files.entry(path.clone()).or_insert_with(|| blank(&path)).stat = Some(stat),
                Err(e) if e.kind() == io::ErrorKind::NotFound => log::debug!("collector {}: {path} is absent", collector.id),
                Err(e) => return Err(format!("can’t stat {path}: {e}")),
            }
        }
    }
    let mut inputs: Vec<Input> = files.into_values().map(Input::File).collect();
    match &collector.read.exec {
        Some(argv) if !options.live => log::debug!("collector {}: {} not run under --root", collector.id, argv[0]),
        Some(argv) if matches!(root.stat(&argv[0]), Err(e) if e.kind() == io::ErrorKind::NotFound) => {
            log::debug!("collector {}: {} is absent, passed as exit 127", collector.id, argv[0]);
            inputs.push(Input::Exec(ExecInput { argv: argv.clone(), stdout: String::new(), stderr: format!("{}: not found\n", argv[0]), exit: 127 }));
        }
        Some(argv) => {
            let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
            let output = runner::run(Path::new(&argv[0]), &args, None, options.timeout, OUTPUT_CAP).map_err(|e| format!("{}: {e}", argv[0]))?;
            let exit = output.code();
            inputs.push(Input::Exec(ExecInput { argv: argv.clone(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned(), exit }));
        }
        None => {}
    }
    Ok(inputs)
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
        let slot = map.entry((*segment).to_owned()).or_insert_with(|| Value::Object(Map::new()));
        map = slot.as_object_mut().ok_or_else(|| format!("into {path} crosses {segment}, which holds a value"))?;
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
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// Standard padded base64 of `bytes`.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}
