// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use std::collections::BTreeMap;

pub mod deb822;
mod kv;
mod options;
pub mod proc;
mod rainerscript;
mod words;
pub use deb822::deb822;
pub use kv::kv;
pub use options::flags;
pub use rainerscript::rainerscript;
pub use words::words;

use serde_json::{Map, Value};
use systemlint_protocol::{
    Describe, Diagnostic, FileInput, FileKind, Input, Reply, Request, Result,
};

/// The unit directories systemd reads, highest precedence first.
pub const UNIT_DIRS: [&str; 8] = [
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];

/// The unit types systemd loads.
pub const UNIT_TYPES: [&str; 11] = [
    "service",
    "socket",
    "device",
    "mount",
    "automount",
    "swap",
    "target",
    "path",
    "timer",
    "slice",
    "scope",
];

/// One INI file: every value of every key, by section; keys before the first section sit under `""`.
pub type Sections = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new(
        "formats",
        &[
            ("csv", &[]),
            ("deb822", &[]),
            ("exec", &[]),
            ("ini", &[]),
            ("json", &[]),
            ("kv", &[]),
            ("lines", &[]),
            ("match", &[]),
            ("options", &[]),
            ("passwd", &[]),
            ("probes", &[]),
            ("rainerscript", &[]),
            ("shadow", &[]),
            ("stat", &[]),
            ("statfs", &[]),
            ("systemd", &[]),
            ("toml", &[]),
            ("words", &[]),
            ("yaml", &[]),
        ],
    )
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    if !WITH_OPS.contains(&request.op.as_str()) && !request.with.is_empty() {
        return Err(format!("op {} takes no with", request.op).into());
    }
    if TEXT_OPS.contains(&request.op.as_str()) {
        let mask = request.with.get("exit-mask").and_then(Value::as_i64);
        ran(
            &request.inputs,
            mask.filter(|_| request.op == "json").unwrap_or(0),
        )?;
    }
    match request.op.as_str() {
        "csv" => Ok(csv(&request.inputs)),
        "deb822" => Ok(deb822(&request.inputs)),
        "exec" => Ok(exec(&request.inputs)),
        "ini" => Ok(ini(&request.inputs)),
        "json" => json(&request.inputs, &request.with),
        "kv" => kv(&request.inputs, &request.with),
        "lines" => Ok(lines(&request.inputs)),
        "match" => r#match(&request.inputs, &request.with),
        "options" => flags(&request.inputs, &request.with),
        "passwd" => passwd_with(&request.inputs, &request.with),
        "probes" => Ok(probes(&request.inputs)),
        "rainerscript" => Ok(rainerscript(&request.inputs)),
        "shadow" => shadow_with(&request.inputs, &request.with),
        "stat" => Ok(stat(&request.inputs)),
        "statfs" => Ok(statfs(&request.inputs)),
        "systemd" => Ok(systemd(&request.inputs)),
        "toml" => Ok(toml(&request.inputs)),
        "words" => words(&request.inputs, &request.with),
        "yaml" => Ok(yaml(&request.inputs)),
        other => Err(format!("unknown op {other}").into()),
    }
}

/// The generic ops that read a command’s stdout as text, so a failed command fails them.
const TEXT_OPS: [&str; 12] = [
    "csv",
    "deb822",
    "ini",
    "json",
    "kv",
    "lines",
    "match",
    "options",
    "rainerscript",
    "toml",
    "words",
    "yaml",
];

/// The family ops that take typed options under `with`.
const WITH_OPS: [&str; 7] = [
    "json", "kv", "match", "options", "passwd", "shadow", "words",
];

/// The typed options of `op` from `with`, or an error naming what is wrong.
pub fn options<T: serde::de::DeserializeOwned>(op: &str, with: &Map<String, Value>) -> Result<T> {
    serde_json::from_value(Value::Object(with.clone()))
        .map_err(|e| format!("{op} with: {e}").into())
}
pub use systemlint_protocol::scalar;

/// An error naming the first command that exited non-zero, 127 (absent) and an exit within `mask` aside, so its collector fails rather than reading as empty.
fn ran(inputs: &[Input], mask: i64) -> Result<()> {
    match inputs.iter().find_map(|i| match i {
        Input::Exec(run)
            if run.exit != 0 && run.exit != 127 && i64::from(run.exit) & !mask != 0 =>
        {
            Some(run)
        }
        _ => None,
    }) {
        Some(run) => Err(format!(
            "{} exited {}: {}",
            run.argv[0],
            run.exit,
            run.stderr.lines().next().unwrap_or("")
        )
        .into()),
        None => Ok(()),
    }
}

/// Every line matching `with.pattern` keyed by its `key` capture, the other named captures its fields; the first line holding a key wins.
pub fn r#match(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    if let Some(other) = with.keys().find(|k| *k != "pattern") {
        return Err(format!("with.{other} is unknown to match").into());
    }
    let pattern = with
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or("match needs with.pattern, a regex")?;
    let regex = regex::Regex::new(pattern).map_err(|e| format!("with.pattern: {e}"))?;
    if !regex.capture_names().any(|n| n == Some("key")) {
        return Err("with.pattern has no (?P<key>…) capture".into());
    }
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let Some(captures) = regex.captures(line) else {
                continue;
            };
            let key = captures.name("key").map_or("", |m| m.as_str());
            let fields: Map<String, Value> = regex
                .capture_names()
                .flatten()
                .filter(|n| *n != "key")
                .filter_map(|n| {
                    captures
                        .name(n)
                        .map(|m| (n.to_owned(), Value::from(m.as_str())))
                })
                .collect();
            let clash = match reply.facts.get(key) {
                _ if key.is_empty() => "an empty key, skipped".to_owned(),
                None => {
                    reply.facts.insert(key.to_owned(), Value::Object(fields));
                    continue;
                }
                Some(Value::Object(first)) if *first == fields => continue,
                Some(_) => format!("key {key} again with other fields, the first kept"),
            };
            reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: Some(index as u64 + 1),
                message: clash,
            });
        }
    }
    Ok(reply)
}

/// Every input’s filesystem use keyed by its path: `blocks` and `inodes` used in whole percent rounded up as df(1) does, each left out when the filesystem counts none, and `read-only`.
pub fn statfs(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let percent =
        |used: u64, total: u64| (total > 0).then(|| used.saturating_mul(100).div_ceil(total));
    for input in inputs {
        match input {
            Input::File(FileInput {
                path,
                statfs: Some(fs),
                ..
            }) => {
                let used = fs.blocks.saturating_sub(fs.blocks_free);
                let mut fact =
                    Map::from_iter([("read-only".to_owned(), Value::Bool(fs.read_only))]);
                if let Some(blocks) = percent(used, used.saturating_add(fs.blocks_available)) {
                    fact.insert("blocks".to_owned(), Value::from(blocks));
                }
                if let Some(inodes) = percent(fs.files.saturating_sub(fs.files_free), fs.files) {
                    fact.insert("inodes".to_owned(), Value::from(inodes));
                }
                reply.facts.insert(path.clone(), Value::Object(fact));
            }
            Input::File(FileInput { path, .. }) => reply.diagnostics.push(Diagnostic {
                path: path.clone(),
                line: None,
                message: "no statfs; list it under read.statfs".to_owned(),
            }),
            other => reply.diagnostics.push(Diagnostic {
                path: other.name(),
                line: None,
                message: "not a file, so no statfs".to_owned(),
            }),
        }
    }
    reply
}

/// Every input’s stat keyed by its path with `exists`, an absent one as `exists: false`; an input without a stat gets a diagnostic.
pub fn stat(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        match input {
            Input::File(FileInput {
                path,
                stat: Some(stat),
                ..
            }) => {
                let mut fact = serde_json::to_value(stat).unwrap_or_default();
                fact["exists"] = Value::Bool(true);
                reply.facts.insert(path.clone(), fact);
            }
            Input::File(FileInput {
                path, absent: true, ..
            }) => {
                reply
                    .facts
                    .insert(path.clone(), serde_json::json!({"exists": false}));
            }
            Input::File(FileInput { path, .. }) => reply.diagnostics.push(Diagnostic {
                path: path.clone(),
                line: None,
                message: "no stat; list it under read.stat".to_owned(),
            }),
            other => reply.diagnostics.push(Diagnostic {
                path: other.name(),
                line: None,
                message: "not a file, so no stat".to_owned(),
            }),
        }
    }
    reply
}

/// The first command’s `exit-status`, `stdout`, `stderr` and `stdout-lines`; a file gets a diagnostic.
pub fn exec(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        match input {
            Input::Exec(run) if reply.facts.is_empty() => {
                reply
                    .facts
                    .insert("exit-status".to_owned(), Value::from(run.exit));
                reply
                    .facts
                    .insert("stdout".to_owned(), Value::from(run.stdout.as_str()));
                reply
                    .facts
                    .insert("stderr".to_owned(), Value::from(run.stderr.as_str()));
                reply.facts.insert(
                    "stdout-lines".to_owned(),
                    Value::from(run.stdout.lines().collect::<Vec<_>>()),
                );
            }
            Input::Exec(run) => reply.diagnostics.push(Diagnostic {
                path: run.argv.join(" "),
                line: None,
                message: "a second command, skipped".to_owned(),
            }),
            other => reply.diagnostics.push(Diagnostic {
                path: other.name(),
                line: None,
                message: "not a command, skipped".to_owned(),
            }),
        }
    }
    reply
}

/// Every probe keyed by its kind then its target, one that got no answer as `{error}` with a diagnostic.
pub fn probes(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Input::Probe(probe) = input else {
            reply.diagnostics.push(Diagnostic {
                path: input.name(),
                line: None,
                message: "not a probe, skipped".to_owned(),
            });
            continue;
        };
        let mut fact = probe.facts.clone();
        if let Some(error) = &probe.error {
            reply.diagnostics.push(Diagnostic {
                path: probe.target.clone(),
                line: None,
                message: error.clone(),
            });
            fact.insert("error".to_owned(), Value::from(error.as_str()));
        }
        let kind = reply
            .facts
            .entry(probe.probe.key().to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        kind[&probe.target] = Value::Object(fact);
    }
    reply
}

/// Every text input as its list of lines, keyed by its path.
pub fn lines(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for (path, text) in inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
    {
        reply.facts.insert(
            path.to_owned(),
            Value::from(text.lines().collect::<Vec<_>>()),
        );
    }
    reply
}

/// A password field as a word, never its hash: `shadow` for `x`, `empty`, `locked` for a leading `!` or `*`, else `hash`.
fn password(field: &str) -> &'static str {
    match field {
        "x" => "shadow",
        "" => "empty",
        f if f.starts_with(['!', '*']) => "locked",
        _ => "hash",
    }
}

/// A numeric id field, or the message naming it.
fn id(parts: &[&str], index: usize, name: &str) -> std::result::Result<Value, String> {
    parts[index]
        .parse::<u32>()
        .map(Value::from)
        .map_err(|_| format!("{name} {:?} is not a number", parts[index]))
}

/// One account line’s fields parsed into facts, or the message naming the bad field.
type Entry = fn(&[&str]) -> std::result::Result<Map<String, Value>, String>;

/// A passwd(5) line’s facts.
fn passwd_entry(parts: &[&str]) -> std::result::Result<Map<String, Value>, String> {
    Ok(Map::from_iter([
        ("password".to_owned(), Value::from(password(parts[1]))),
        ("uid".to_owned(), id(parts, 2, "uid")?),
        ("gid".to_owned(), id(parts, 3, "gid")?),
        ("gecos".to_owned(), Value::from(parts[4])),
        ("home".to_owned(), Value::from(parts[5])),
        ("shell".to_owned(), Value::from(parts[6])),
    ]))
}

/// The shadow(5) ageing fields after the password, by their fact names.
const AGEING: [&str; 6] = [
    "last-change",
    "min-days",
    "max-days",
    "warn-days",
    "inactive-days",
    "expire-day",
];

/// A shadow(5) line’s facts, the hash reduced to its word, each ageing field a number of days or `null` when empty.
fn shadow_entry(parts: &[&str]) -> std::result::Result<Map<String, Value>, String> {
    let mut facts = Map::from_iter([("password".to_owned(), Value::from(password(parts[1])))]);
    for (index, name) in AGEING.iter().enumerate() {
        let value = match parts[index + 2] {
            "" => Value::Null,
            _ => id(parts, index + 2, name)?,
        };
        facts.insert((*name).to_owned(), value);
    }
    Ok(facts)
}

/// Every entry of a colon-separated account database keyed by name, its `line`, and the later lines repeating the name, which glibc never reads, in `shadowed`.
fn accounts(inputs: &[Input], fields: usize, entry: Entry) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        for (index, raw) in text.lines().enumerate() {
            let number = index as u64 + 1;
            let line = raw.trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            let failed = if parts.len() == fields {
                if let Some(Value::Object(first)) = reply.facts.get_mut(parts[0]) {
                    if let Some(Value::Array(shadowed)) = first.get_mut("shadowed") {
                        shadowed.push(Value::from(number));
                    }
                    continue;
                }
                match entry(&parts) {
                    Ok(mut facts) => {
                        facts.insert("line".to_owned(), Value::from(number));
                        facts.insert("shadowed".to_owned(), Value::Array(Vec::new()));
                        reply
                            .facts
                            .insert(parts[0].to_owned(), Value::Object(facts));
                        continue;
                    }
                    Err(message) => message,
                }
            } else {
                format!("{} fields where {fields} are expected", parts.len())
            };
            reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: Some(number),
                message: failed,
            });
        }
    }
    reply
}

/// Every account of passwd(5) files by name.
pub fn passwd(inputs: &[Input]) -> Reply {
    accounts(inputs, 7, passwd_entry)
}

/// The shells getusershell(3) falls back to when `/etc/shells` is absent.
const FALLBACK_SHELLS: [&str; 2] = ["/bin/sh", "/bin/csh"];

/// Program names of interactive shells, so a person’s shell missing from `/etc/shells` is never read as no shell.
const INTERACTIVE_SHELLS: [&str; 18] = [
    "ash", "bash", "busybox", "csh", "dash", "elvish", "fish", "ksh", "mksh", "nu", "oksh", "pwsh",
    "rbash", "sh", "tcsh", "xonsh", "yash", "zsh",
];

/// `passwd`’s options: `shells`, the input listing login shells, which adds `login-shell` to every entry.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswdOptions {
    shells: Option<String>,
}

/// [`passwd`] over every input but `with.shells`, each entry’s `login-shell` true when its shell is empty or listed there, as getusershell(3) reads it, and `interactive-shell` when its program is one of [`INTERACTIVE_SHELLS`].
pub fn passwd_with(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    let PasswdOptions { shells } = options("passwd", with)?;
    let Some(shells) = shells else {
        return Ok(passwd(inputs));
    };
    let (listed, accounts): (Vec<&Input>, Vec<&Input>) =
        inputs.iter().partition(|i| i.name() == shells);
    let mut diagnostics = Vec::new();
    let allowed: Vec<String> = match listed.first() {
        Some(input) => text(input, &mut diagnostics)
            .map(|(_, t)| {
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        None => FALLBACK_SHELLS.map(str::to_owned).to_vec(),
    };
    let accounts: Vec<Input> = accounts.into_iter().cloned().collect();
    let mut reply = passwd(&accounts);
    for entry in reply.facts.values_mut().filter_map(Value::as_object_mut) {
        let shell = entry["shell"].as_str().unwrap_or_default();
        let login = shell.is_empty() || allowed.iter().any(|s| s == shell);
        let program = shell.rsplit('/').next().unwrap_or_default();
        let interactive = shell.is_empty() || INTERACTIVE_SHELLS.contains(&program);
        entry.insert("login-shell".to_owned(), Value::Bool(login));
        entry.insert("interactive-shell".to_owned(), Value::Bool(interactive));
    }
    reply.diagnostics.extend(diagnostics);
    Ok(reply)
}

/// Every account of shadow(5) files by name, with no hash.
pub fn shadow(inputs: &[Input]) -> Reply {
    accounts(inputs, 9, shadow_entry)
}

/// `shadow`’s options: `passwd`, the passwd(5) input whose accounts deferring to shadow must each have a line.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowOptions {
    passwd: Option<String>,
}

/// [`shadow`] over every input but `with.passwd`, each line’s `in-passwd` telling whether an account there holds it, plus `{password: missing}` for each account there that defers with `x` and has no shadow line, as pwck(8) reports it.
pub fn shadow_with(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    let ShadowOptions { passwd: named } = options("shadow", with)?;
    let Some(named) = named else {
        return Ok(shadow(inputs));
    };
    let (listed, files): (Vec<Input>, Vec<Input>) =
        inputs.iter().cloned().partition(|i| i.name() == named);
    let mut reply = shadow(&files);
    if files.is_empty() || listed.is_empty() {
        return Ok(reply);
    }
    let accounts = passwd(&listed);
    for (name, entry) in &mut reply.facts {
        if let Some(entry) = entry.as_object_mut() {
            let known = accounts.facts.contains_key(name);
            entry.insert("in-passwd".to_owned(), Value::Bool(known));
        }
    }
    for (name, entry) in accounts.facts {
        if entry["password"] == "shadow" && !reply.facts.contains_key(&name) {
            let missing = Map::from_iter([
                ("password".to_owned(), Value::from("missing")),
                ("in-passwd".to_owned(), Value::Bool(true)),
            ]);
            reply.facts.insert(name, Value::Object(missing));
        }
    }
    Ok(reply)
}

/// The text of a file, or a zero-exit command’s stdout keyed by its program; a diagnostic otherwise.
pub fn text<'a>(input: &'a Input, diagnostics: &mut Vec<Diagnostic>) -> Option<(&'a str, &'a str)> {
    match input {
        Input::File(FileInput {
            path,
            content: Some(text),
            ..
        }) => Some((path, text)),
        Input::Exec(run) if run.exit == 0 => {
            Some((run.argv.first().map_or("", String::as_str), &run.stdout))
        }
        Input::Exec(run) => {
            diagnostics.push(Diagnostic {
                path: input.name(),
                line: None,
                message: format!(
                    "exited {}: {}",
                    run.exit,
                    run.stderr.lines().next().unwrap_or("")
                ),
            });
            None
        }
        Input::File(FileInput { path, .. }) => {
            diagnostics.push(Diagnostic {
                path: path.clone(),
                line: None,
                message: "not UTF-8 text, skipped".to_owned(),
            });
            None
        }
        other => {
            diagnostics.push(Diagnostic {
                path: other.name(),
                line: None,
                message: "not a file or command, skipped".to_owned(),
            });
            None
        }
    }
}

/// Every input parsed as INI and keyed by its path: `[section]`, `key=value`, `#` and `;` comments, a trailing `\` joining the next line.
pub fn ini(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let sections = parse_ini(text, |line, message| {
            reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: Some(line),
                message,
            })
        });
        reply.facts.insert(
            path.to_owned(),
            serde_json::to_value(sections).unwrap_or_default(),
        );
    }
    reply
}

/// The sections of one INI text, systemd’s flavour: a key repeats into a list, `\` at a line end continues it.
pub fn parse_ini(text: &str, mut diagnose: impl FnMut(u64, String)) -> Sections {
    let (mut sections, mut section, mut pending) =
        (Sections::new(), String::new(), None::<(u64, String)>);
    for (index, raw) in text.lines().enumerate() {
        let (number, line) = match pending.take() {
            Some((start, head)) => (start, format!("{head} {}", raw.trim())),
            None if matches!(raw.trim_start().chars().next(), Some('#' | ';')) => continue,
            None => (index as u64 + 1, raw.trim().to_owned()),
        };
        if let Some(head) = line.strip_suffix('\\') {
            pending = Some((number, head.trim_end().to_owned()));
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_owned();
            sections.entry(section.clone()).or_default();
            continue;
        }
        match line.split_once('=') {
            Some((key, value)) if !key.trim().is_empty() => sections
                .entry(section.clone())
                .or_default()
                .entry(key.trim().to_owned())
                .or_default()
                .push(value.trim().to_owned()),
            _ => diagnose(number, format!("no key=value in {line:?}")),
        }
    }
    if let Some((number, line)) = pending {
        diagnose(
            number,
            format!("{line:?} continues past the end of the file"),
        );
    }
    sections
}

/// Every input’s top-level JSON object merged into one, the first input holding a key winning; `with.exit-mask` reads a command whose exit bits all lie in it, `with.redact` names JSON Pointers the core redacts.
pub fn json(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    if let Some(other) = with
        .keys()
        .find(|k| !matches!(k.as_str(), "exit-mask" | "redact"))
    {
        return Err(format!("with.{other} is unknown to json").into());
    }
    let mask = match with.get("exit-mask") {
        None => 0,
        Some(v) => v
            .as_i64()
            .filter(|m| (1..=255).contains(m))
            .ok_or("with.exit-mask is an exit status bit mask from 1 to 255")?,
    };
    let redact = match with.get("redact") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .map(|i| i.as_str().filter(|p| p.starts_with('/')).map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or("with.redact is a list of JSON Pointers, each starting with /")?,
    };
    let mut reply = Reply {
        redact,
        ..Reply::default()
    };
    for input in inputs {
        let read = match input {
            Input::Exec(run) if run.exit > 0 && i64::from(run.exit) & !mask == 0 => {
                Some((run.argv[0].as_str(), run.stdout.as_str()))
            }
            _ => text(input, &mut reply.diagnostics),
        };
        let Some((path, text)) = read else {
            continue;
        };
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => {
                for (key, value) in map {
                    reply.facts.entry(key).or_insert(value);
                }
            }
            Ok(other) => reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: None,
                message: format!("holds a {}, not an object", kind(&other)),
            }),
            Err(e) => reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: Some(e.line() as u64),
                message: format!("not valid JSON: {e}"),
            }),
        }
    }
    Ok(reply)
}

/// Every input parsed as one YAML document, YAML 1.2 booleans only, keyed by its path.
pub fn yaml(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        match serde_saphyr::from_str_with_options::<Value>(
            text,
            serde_saphyr::options! { strict_booleans: true },
        ) {
            Ok(value) => {
                reply.facts.insert(path.to_owned(), value);
            }
            Err(e) => reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: None,
                message: format!("not valid YAML: {e}"),
            }),
        }
    }
    reply
}

/// Every input parsed as TOML, keyed by its path; a date or time becomes its TOML text.
pub fn toml(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        match text.parse::<toml::Table>() {
            Ok(table) => {
                reply
                    .facts
                    .insert(path.to_owned(), from_toml(toml::Value::Table(table)));
            }
            Err(e) => reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: None,
                message: format!("not valid TOML: {}", e.message()),
            }),
        }
    }
    reply
}

fn from_toml(value: toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::from(s),
        toml::Value::Integer(n) => Value::from(n),
        toml::Value::Float(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        toml::Value::Boolean(b) => Value::from(b),
        toml::Value::Datetime(d) => Value::from(d.to_string()),
        toml::Value::Array(items) => Value::Array(items.into_iter().map(from_toml).collect()),
        toml::Value::Table(table) => {
            Value::Object(table.into_iter().map(|(k, v)| (k, from_toml(v))).collect())
        }
    }
}

/// Every input parsed as RFC 4180 CSV, keyed by its path: one object per row, keyed by the header row.
pub fn csv(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let mut rows = match records(text) {
            Ok(rows) => rows.into_iter(),
            Err(line) => {
                reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: Some(line),
                    message: "a quoted field never ends".to_owned(),
                });
                continue;
            }
        };
        let header = rows.next().unwrap_or_default();
        let mut objects = Vec::new();
        for (index, row) in rows.enumerate() {
            if row.len() != header.len() {
                reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: None,
                    message: format!(
                        "row {} has {} fields, the header {}",
                        index + 2,
                        row.len(),
                        header.len()
                    ),
                });
            }
            objects.push(Value::Object(
                header
                    .iter()
                    .cloned()
                    .zip(row.into_iter().map(Value::from))
                    .collect(),
            ));
        }
        reply.facts.insert(path.to_owned(), Value::Array(objects));
    }
    reply
}

/// The records of `text`, quotes doubled inside quoted fields, blank lines skipped; the line of an unclosed quote as the error.
fn records(text: &str) -> std::result::Result<Vec<Vec<String>>, u64> {
    let (mut rows, mut row, mut field) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut line, mut opened) = (false, 1, 1);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => (quoted, opened) = (true, line),
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\r', false) if chars.peek() == Some(&'\n') => {}
            ('\n', false) => {
                line += 1;
                row.push(std::mem::take(&mut field));
                if row.len() > 1 || !row[0].is_empty() {
                    rows.push(std::mem::take(&mut row));
                }
                row.clear();
            }
            (c, _) => {
                line += u64::from(c == '\n');
                field.push(c);
            }
        }
    }
    if quoted {
        return Err(opened);
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "list",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        _ => "null",
    }
}

/// One unit of `systemctl list-units --output=json`.
#[derive(serde::Deserialize)]
struct Listed {
    unit: String,
    active: String,
    sub: String,
}

/// Each unit’s `enabled` and `masked` from the unit directories, plus `active` and `sub` when `systemctl list-units --output=json` exited 0.
pub fn systemd(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut units: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut highest: BTreeMap<String, usize> = BTreeMap::new();
    let mut live = None;
    for input in inputs {
        let (path, stat) = match input {
            Input::File(FileInput {
                path,
                stat: Some(stat),
                ..
            }) => (path, stat),
            Input::File(_) | Input::Probe(_) => continue,
            Input::Exec(e) if e.exit == 0 => {
                live = Some(e);
                continue;
            }
            Input::Exec(e) if e.exit != 127 => {
                reply.diagnostics.push(Diagnostic {
                    path: e.argv.join(" "),
                    line: None,
                    message: format!("exited {}, no active state: {}", e.exit, e.stderr.trim()),
                });
                continue;
            }
            Input::Exec(_) => continue,
        };
        let Some((dir, name)) = path.rsplit_once('/').filter(|(_, n)| unit_name(n)) else {
            continue;
        };
        let fresh = || {
            Map::from_iter([
                ("enabled".to_owned(), Value::Bool(false)),
                ("masked".to_owned(), Value::Bool(false)),
            ])
        };
        if let Some(rank) = UNIT_DIRS
            .iter()
            .position(|d| *d == dir)
            .filter(|_| stat.kind != FileKind::Directory)
        {
            let unit = units.entry(name.to_owned()).or_insert_with(fresh);
            if highest.get(name).is_none_or(|r| rank < *r) {
                highest.insert(name.to_owned(), rank);
                unit.insert(
                    "masked".to_owned(),
                    Value::Bool(
                        stat.linked_to.as_deref() == Some("/dev/null")
                            || (stat.kind == FileKind::File && stat.size == 0),
                    ),
                );
            }
        } else if dir.rsplit_once('/').is_some_and(|(parent, link)| {
            UNIT_DIRS.contains(&parent) && (link.ends_with(".wants") || link.ends_with(".requires"))
        }) {
            units
                .entry(name.to_owned())
                .or_insert_with(fresh)
                .insert("enabled".to_owned(), Value::Bool(true));
        }
    }
    let listed = live.map(|e| (e, serde_json::from_str::<Vec<Listed>>(&e.stdout)));
    if let Some((exec, Err(e))) = &listed {
        reply.diagnostics.push(Diagnostic {
            path: exec.argv.join(" "),
            line: None,
            message: format!("not systemctl’s JSON, no active state: {e}"),
        });
    }
    if let Some((_, Ok(listed))) = listed {
        let mut seen = std::collections::BTreeSet::new();
        for Listed {
            unit: name,
            active,
            sub,
        } in listed
        {
            let unit = units.entry(name.clone()).or_default();
            unit.insert("active".to_owned(), Value::from(active));
            unit.insert("sub".to_owned(), Value::from(sub));
            seen.insert(name);
        }
        for (_, unit) in units.iter_mut().filter(|(name, _)| !seen.contains(*name)) {
            unit.insert("active".to_owned(), Value::from("inactive"));
            unit.insert("sub".to_owned(), Value::from("dead"));
        }
    }
    reply.facts.extend(
        units
            .into_iter()
            .map(|(name, unit)| (name, Value::Object(unit))),
    );
    reply
}

/// Each unit’s files in the order systemd reads them: the unit file from the highest directory, then its drop-ins by name, one per name.
pub fn unit_files<'a>(files: &[(&'a str, &'a str)]) -> BTreeMap<String, Vec<(&'a str, &'a str)>> {
    let mut mains: BTreeMap<String, (usize, &str, &str)> = BTreeMap::new();
    let mut drops: BTreeMap<String, BTreeMap<&str, (usize, &str, &str)>> = BTreeMap::new();
    for (path, text) in files {
        let Some((dir, file)) = path.rsplit_once('/') else {
            continue;
        };
        let (base, unit, dropin) = match dir.rsplit_once('/') {
            Some((base, d)) if d.ends_with(".d") && file.ends_with(".conf") => {
                (base, d.trim_end_matches(".d"), true)
            }
            _ => (dir, file, false),
        };
        let Some(rank) = UNIT_DIRS.iter().position(|d| *d == base) else {
            continue;
        };
        if !unit.contains('.') {
            continue;
        }
        let slot = if dropin {
            drops
                .entry(unit.to_owned())
                .or_default()
                .entry(file)
                .or_insert((usize::MAX, "", ""))
        } else {
            mains.entry(unit.to_owned()).or_insert((usize::MAX, "", ""))
        };
        if rank < slot.0 {
            *slot = (rank, path, text);
        }
    }
    let mut units: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
    for (unit, (_, path, text)) in mains {
        units.entry(unit).or_default().push((path, text));
    }
    for (unit, confs) in drops {
        units
            .entry(unit)
            .or_default()
            .extend(confs.into_values().map(|(_, p, t)| (p, t)));
    }
    units
}

/// Whether `name` ends in a unit type systemd loads.
fn unit_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(stem, kind)| !stem.is_empty() && UNIT_TYPES.contains(&kind))
}

/// `uri` with its userinfo replaced, so no credential (password, OAuth token-as-username, or single bearer token) reaches the facts.
pub fn mask(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return uri.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rsplit_once('@') {
        Some((info, host)) if !info.is_empty() => {
            format!("{scheme}://[redacted]@{host}{}", &rest[authority_end..])
        }
        _ => uri.to_owned(),
    }
}

/// The value of `raw` as a shell reads one word: `"…"` with `\"`, `\\`, `\$` and `` \` `` escapes, `'…'` literal, else as is.
pub fn unquote(raw: &str) -> std::result::Result<String, String> {
    let Some(quote) = raw.chars().next().filter(|c| *c == '"' || *c == '\'') else {
        return Ok(raw.to_owned());
    };
    let inner = raw
        .strip_prefix(quote)
        .and_then(|r| r.strip_suffix(quote))
        .filter(|_| raw.len() >= 2)
        .ok_or_else(|| format!("unterminated {quote} quote"))?;
    if quote == '\'' {
        return Ok(inner.to_owned());
    }
    let (mut value, mut chars) = (String::with_capacity(inner.len()), inner.chars());
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some(next @ ('"' | '\\' | '$' | '`'))) => {
                value.push(next);
                chars.next();
            }
            ('"', _) => return Err("unescaped \" inside a quoted value".to_owned()),
            _ => value.push(c),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use systemlint_protocol::{ExecInput, FileKind, Stat};

    fn file(path: &str, content: &str) -> Input {
        Input::File(FileInput {
            path: path.to_owned(),
            content: Some(content.to_owned()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        })
    }

    #[test]
    fn probes_key_each_target_by_kind_and_keep_an_error_beside_its_facts() {
        use systemlint_protocol::{ProbeInput, ProbeKind};
        let probe = |probe, target: &str, facts: Value, error: Option<&str>| {
            Input::Probe(ProbeInput {
                probe,
                target: target.to_owned(),
                facts: facts.as_object().cloned().unwrap_or_default(),
                error: error.map(str::to_owned),
            })
        };
        let reply = probes(&[
            probe(
                ProbeKind::Addr,
                "kiota.ch:443",
                serde_json::json!({"reachable": true}),
                None,
            ),
            probe(
                ProbeKind::Http,
                "https://x.test/",
                serde_json::json!({"tls": {"verified": false}}),
                Some("TLS not trusted"),
            ),
            file("/etc/hosts", ""),
        ]);
        assert_eq!(
            Value::Object(reply.facts.into_iter().collect()),
            serde_json::json!({
                "addr": {"kiota.ch:443": {"reachable": true}},
                "http": {"https://x.test/": {"tls": {"verified": false}, "error": "TLS not trusted"}}
            })
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| (d.path.as_str(), d.message.as_str()))
                .collect::<Vec<_>>(),
            [
                ("https://x.test/", "TLS not trusted"),
                ("/etc/hosts", "not a probe, skipped")
            ]
        );
    }

    #[test]
    fn describe_lists_the_generic_parsers() {
        let describe = describe();
        assert_eq!(describe.name, "formats");
        assert_eq!(
            describe
                .ops
                .iter()
                .map(|o| o.op.as_str())
                .collect::<Vec<_>>(),
            [
                "csv",
                "deb822",
                "exec",
                "ini",
                "json",
                "kv",
                "lines",
                "match",
                "options",
                "passwd",
                "probes",
                "rainerscript",
                "shadow",
                "stat",
                "statfs",
                "systemd",
                "toml",
                "words",
                "yaml"
            ]
        );
        assert!(describe.ops.iter().all(|o| o.needs.is_empty()));
    }

    #[test]
    fn kv_reads_the_fixture_os_release() {
        let reply = kv(
            &[file(
                "/usr/lib/os-release",
                include_str!("../../../fixtures/ubuntu-26.04/usr/lib/os-release"),
            )],
            &Map::new(),
        )
        .unwrap();
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(reply.facts["VERSION_CODENAME"], "resolute");
        assert_eq!(reply.facts["PRETTY_NAME"], "Ubuntu 26.04.1 LTS");
        assert_eq!(reply.facts["ID"], "ubuntu");
    }

    #[test]
    fn kv_first_input_wins_and_exec_stdout_counts() {
        let exec = Input::Exec(ExecInput {
            argv: vec!["/bin/env".into()],
            stdout: "A=exec\nB=exec\n".into(),
            stderr: String::new(),
            exit: 0,
        });
        let reply = kv(&[file("/etc/a", "A=file\n"), exec], &Map::new()).unwrap();
        assert_eq!(
            (reply.facts["A"].as_str(), reply.facts["B"].as_str()),
            (Some("file"), Some("exec"))
        );
    }

    #[test]
    fn kv_names_each_bad_line() {
        let reply = kv(
            &[file(
                "/etc/x",
                "# comment\n\nGOOD = spaced \nno equals\n=orphan\nOPEN=\"half\n",
            )],
            &Map::new(),
        )
        .unwrap();
        assert_eq!(reply.facts["GOOD"], "spaced");
        let lines: Vec<_> = reply
            .diagnostics
            .iter()
            .map(|d| (d.path.as_str(), d.line))
            .collect();
        assert_eq!(
            lines,
            [
                ("/etc/x", Some(4)),
                ("/etc/x", Some(5)),
                ("/etc/x", Some(6))
            ]
        );
        assert!(
            reply.diagnostics[2].message.contains("OPEN: unterminated"),
            "{:?}",
            reply.diagnostics
        );
    }

    #[test]
    fn kv_skips_binary_input_with_a_diagnostic() {
        let input = Input::File(FileInput {
            path: "/bin".into(),
            content: None,
            content_base64: Some("AA==".into()),
            stat: None,
            statfs: None,
            absent: false,
        });
        let reply = kv(&[input], &Map::new()).unwrap();
        assert!(reply.facts.is_empty());
        assert_eq!(reply.diagnostics[0].line, None);
    }

    #[test]
    fn unquote_follows_the_shell() {
        assert_eq!(
            unquote(r#""a \"b\" \\ \$c \`d\` \n""#).unwrap(),
            r#"a "b" \ $c `d` \n"#
        );
        assert_eq!(unquote(r#"'it \n "x"'"#).unwrap(), r#"it \n "x""#);
        assert_eq!(unquote("bare").unwrap(), "bare");
        assert_eq!(unquote("").unwrap(), "");
        assert_eq!(unquote(r#""""#).unwrap(), "");
        assert!(unquote("\"").is_err());
        assert!(unquote("'").is_err());
        assert!(unquote(r#""a"b""#).is_err());
    }

    #[test]
    fn yaml_keeps_no_and_off_as_strings_and_names_a_bad_file() {
        let reply = super::yaml(&[
            file("/etc/netplan/a.yaml", "network:\n  dhcp4: no\n  up: true\n"),
            file("/etc/bad.yaml", "a: [1\n"),
        ]);
        assert_eq!(
            reply.facts["/etc/netplan/a.yaml"],
            serde_json::json!({"network": {"dhcp4": "no", "up": true}})
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/bad.yaml"]
        );
    }

    #[test]
    fn toml_turns_tables_and_dates_into_json_and_names_a_bad_file() {
        let reply = super::toml(&[
            file(
                "/etc/containerd/config.toml",
                "version = 3\n[plugins.cri]\nsandbox = \"pause\"\nratio = 0.5\nat = 2026-11-12T10:00:00Z\n",
            ),
            file("/etc/bad.toml", "a = \n"),
        ]);
        assert_eq!(
            reply.facts["/etc/containerd/config.toml"],
            serde_json::json!({"version": 3, "plugins": {"cri": {"sandbox": "pause", "ratio": 0.5, "at": "2026-11-12T10:00:00Z"}}})
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/bad.toml"]
        );
    }

    #[test]
    fn csv_keys_rows_by_the_header_with_rfc_4180_quotes() {
        let reply = super::csv(&[file(
            "/etc/a.csv",
            "name,note\r\nroot,\"a, \"\"b\"\"\"\r\n\nbin,\"two\nlines\"\nshort\n",
        )]);
        assert_eq!(
            reply.facts["/etc/a.csv"],
            serde_json::json!([{"name": "root", "note": "a, \"b\""}, {"name": "bin", "note": "two\nlines"}, {"name": "short"}])
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>(),
            ["row 4 has 1 fields, the header 2"]
        );
        let open = super::csv(&[file("/etc/b.csv", "a\n\"x\n")]);
        assert_eq!((open.facts.len(), open.diagnostics[0].line), (0, Some(2)));
    }

    #[test]
    fn exec_returns_the_first_command_and_names_the_rest() {
        let run = |argv: &str, exit| {
            Input::Exec(ExecInput {
                argv: vec![argv.into()],
                stdout: "a\nb\n".into(),
                stderr: "warn".into(),
                exit,
            })
        };
        let reply = super::exec(&[
            run("/bin/first", 3),
            file("/etc/a", "x"),
            run("/bin/second", 0),
        ]);
        assert_eq!(
            Value::Object(reply.facts.into_iter().collect()),
            serde_json::json!({"exit-status": 3, "stdout": "a\nb\n", "stderr": "warn", "stdout-lines": ["a", "b"]})
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/a", "/bin/second"]
        );
    }

    #[test]
    fn lines_keys_each_file_by_path_and_a_command_by_program_unless_it_failed() {
        let run = |program: &str, exit| {
            Input::Exec(ExecInput {
                argv: vec![program.into(), "-a".into()],
                stdout: "x\ny\n".into(),
                stderr: "denied\nmore".into(),
                exit,
            })
        };
        let reply = super::lines(&[
            file("/etc/a", "one\r\n\ntwo"),
            file("/etc/empty", ""),
            run("/bin/ok", 0),
            run("/bin/failed", 1),
        ]);
        assert_eq!(reply.facts["/etc/a"], serde_json::json!(["one", "", "two"]));
        assert_eq!(reply.facts["/etc/empty"], serde_json::json!([]));
        assert_eq!(reply.facts["/bin/ok"], serde_json::json!(["x", "y"]));
        assert!(!reply.facts.contains_key("/bin/failed"));
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| format!("{}: {}", d.path, d.message))
                .collect::<Vec<_>>(),
            ["/bin/failed -a: exited 1: denied"]
        );
    }

    #[test]
    fn stat_keys_each_stat_by_path_and_names_inputs_without_one() {
        let stat = Stat {
            kind: FileKind::File,
            mode: "0666".into(),
            uid: 0,
            gid: 0,
            size: 3,
            allocated: None,
            world_writable: true,
            group_writable: true,
            setuid: false,
            setgid: false,
            linked_to: None,
            sha256: None,
            sha512: None,
        };
        let with = Input::File(FileInput {
            path: "/etc/sudoers.d/x".into(),
            content: None,
            content_base64: None,
            stat: Some(stat),
            statfs: None,
            absent: false,
        });
        let exec = Input::Exec(ExecInput {
            argv: vec!["/bin/true".into()],
            stdout: String::new(),
            stderr: String::new(),
            exit: 0,
        });
        let absent = Input::File(FileInput {
            path: "/etc/gone".into(),
            content: None,
            content_base64: None,
            stat: None,
            statfs: None,
            absent: true,
        });
        let reply = super::stat(&[with, file("/etc/a", "x"), exec, absent]);
        assert_eq!(reply.facts["/etc/sudoers.d/x"]["mode"], "0666");
        assert_eq!(reply.facts["/etc/sudoers.d/x"]["world-writable"], true);
        assert_eq!(reply.facts["/etc/sudoers.d/x"]["exists"], true);
        assert_eq!(
            reply.facts["/etc/gone"],
            serde_json::json!({"exists": false})
        );
        assert_eq!(reply.facts.len(), 2);
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/a", "/bin/true"]
        );
    }

    // A unit-directory entry with its stat: a regular file of `size` bytes, or a symlink to `to`.
    fn unit(path: &str, size: u64, to: Option<&str>) -> Input {
        let kind = if to.is_some() {
            FileKind::Symlink
        } else {
            FileKind::File
        };
        let stat = Stat {
            kind,
            mode: "0644".into(),
            uid: 0,
            gid: 0,
            size,
            allocated: None,
            world_writable: false,
            group_writable: false,
            setuid: false,
            setgid: false,
            linked_to: to.map(str::to_owned),
            sha256: None,
            sha512: None,
        };
        Input::File(FileInput {
            path: path.into(),
            content: None,
            content_base64: None,
            stat: Some(stat),
            statfs: None,
            absent: false,
        })
    }

    #[test]
    fn systemd_reads_enablement_and_masks_by_precedence() {
        let reply = super::systemd(&[
            unit("/usr/lib/systemd/system/ufw.service", 341, None),
            unit(
                "/etc/systemd/system/multi-user.target.wants/ufw.service",
                35,
                Some("/usr/lib/systemd/system/ufw.service"),
            ),
            unit("/usr/lib/systemd/system/cups.socket", 200, None),
            unit("/run/systemd/system/cups.socket", 9, Some("/dev/null")),
            unit("/etc/systemd/system/cups.socket", 120, None),
            unit("/usr/lib/systemd/system/empty.service", 200, None),
            unit("/etc/systemd/system/empty.service", 0, None),
            unit("/usr/lib/systemd/system/db.service", 200, None),
            unit("/etc/systemd/system/db.service", 9, Some("/dev/null")),
            unit("/etc/systemd/system/db.service.d", 4096, None),
            unit("/etc/systemd/system/opt/x.service", 1, None),
            unit("/etc/systemd/system/.service", 1, None),
            unit("/etc/systemd/system/app.conf", 1, None),
        ]);
        let facts = Value::Object(reply.facts.into_iter().collect());
        assert_eq!(
            facts,
            serde_json::json!({
                "ufw.service": {"enabled": true, "masked": false},
                "cups.socket": {"enabled": false, "masked": false},
                "empty.service": {"enabled": false, "masked": true},
                "db.service": {"enabled": false, "masked": true},
            }),
            "/etc beats a /run mask, an empty file masks, a stray path or name is no unit"
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    }

    #[test]
    fn systemd_adds_the_live_state_and_marks_unloaded_units_inactive() {
        let listed = r#"[{"unit":"ufw.service","load":"loaded","active":"active","sub":"exited","description":"Uncomplicated firewall"},{"unit":"home.mount","load":"not-found","active":"inactive","sub":"dead","description":"home.mount"}]"#;
        let reply = super::systemd(&[
            unit("/usr/lib/systemd/system/ufw.service", 341, None),
            unit("/usr/lib/systemd/system/clean.timer", 30, None),
            exec("/bin/systemctl list-units", listed, 0),
        ]);
        assert_eq!(
            reply.facts["ufw.service"],
            serde_json::json!({"enabled": false, "masked": false, "active": "active", "sub": "exited"})
        );
        assert_eq!(
            reply.facts["clean.timer"],
            serde_json::json!({"enabled": false, "masked": false, "active": "inactive", "sub": "dead"})
        );
        assert_eq!(
            reply.facts["home.mount"],
            serde_json::json!({"active": "inactive", "sub": "dead"}),
            "a live-only unit claims nothing about its files"
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    }

    #[test]
    fn systemd_ignores_output_that_is_not_json_rather_than_mark_units_inactive() {
        let reply = super::systemd(&[
            unit("/usr/lib/systemd/system/ufw.service", 341, None),
            exec(
                "/bin/systemctl list-units",
                "ufw.service loaded active exited x\n",
                0,
            ),
        ]);
        assert_eq!(
            reply.facts["ufw.service"],
            serde_json::json!({"enabled": false, "masked": false})
        );
        assert!(
            reply.diagnostics[0]
                .message
                .starts_with("not systemctl’s JSON")
        );
    }

    #[test]
    fn systemd_without_a_manager_keeps_the_files_and_says_why() {
        let reply = super::systemd(&[
            unit("/usr/lib/systemd/system/ufw.service", 341, None),
            exec("/bin/systemctl list-units", "", 1),
            exec("/bin/systemctl list-units", "", 127),
        ]);
        assert_eq!(
            reply.facts["ufw.service"],
            serde_json::json!({"enabled": false, "masked": false})
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>(),
            ["exited 1, no active state: denied"],
            "exit 127 is an absent systemctl, no diagnostic"
        );
    }

    #[test]
    fn an_unknown_op_is_refused_by_name() {
        let request = Request {
            protocol: 1,
            op: "regex".into(),
            root: "/".into(),
            now: None,
            inputs: vec![],
            facts: Default::default(),
            with: Default::default(),
        };
        assert!(op(request).unwrap_err().to_string().contains("regex"));
    }

    fn request(op_name: &str, inputs: Vec<Input>, with: Value) -> Request {
        Request {
            protocol: 1,
            op: op_name.into(),
            root: "/".into(),
            now: None,
            inputs,
            facts: Default::default(),
            with: serde_json::from_value(with).unwrap(),
        }
    }

    const INST: &str = r"^Inst (?P<key>\S+) (?:\[(?P<installed>[^\]]+)\] )?\((?P<candidate>\S+) (?P<origins>.*) \[(?P<arch>[^\]]+)\]\)";

    #[test]
    fn match_keys_each_matching_line_by_its_key_capture() {
        let stdout = "NOTE: simulation\nInst libc6 [2.41-1] (2.41-2 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])\nInst newpkg (1.0 Ubuntu:26.04/resolute [all])\nConf libc6 (2.41-2 Ubuntu:26.04/resolute-updates [amd64])\nInst libc6 [2.41-1] (9 other [amd64])\nInst newpkg (1.0 Ubuntu:26.04/resolute [all])\n";
        let reply = op(request(
            "match",
            vec![exec("/usr/bin/apt-get --simulate", stdout, 0)],
            json!({"pattern": INST}),
        ))
        .unwrap();
        assert_eq!(
            Value::Object(reply.facts.into_iter().collect()),
            json!({
                "libc6": {"installed": "2.41-1", "candidate": "2.41-2", "origins": "Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security", "arch": "amd64"},
                "newpkg": {"candidate": "1.0", "origins": "Ubuntu:26.04/resolute", "arch": "all"}
            })
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| (d.path.as_str(), d.line, d.message.as_str()))
                .collect::<Vec<_>>(),
            [(
                "/usr/bin/apt-get",
                Some(5),
                "key libc6 again with other fields, the first kept"
            )]
        );
    }

    #[test]
    fn match_skips_an_empty_key_and_reads_files_too() {
        let reply = op(request(
            "match",
            vec![file("/etc/a", "=x\nk=v\n")],
            json!({"pattern": "^(?P<key>[^=]*)=(?P<value>.*)$"}),
        ))
        .unwrap();
        assert_eq!(reply.facts["k"], json!({"value": "v"}));
        assert_eq!(
            (
                reply.diagnostics[0].line,
                reply.diagnostics[0].message.as_str()
            ),
            (Some(1), "an empty key, skipped")
        );
    }

    #[test]
    fn match_refuses_a_pattern_it_cannot_use() {
        let refused = |with: Value| op(request("match", vec![], with)).unwrap_err().to_string();
        assert_eq!(refused(json!({})), "match needs with.pattern, a regex");
        assert_eq!(
            refused(json!({"pattern": "(?P<k>x)"})),
            "with.pattern has no (?P<key>…) capture"
        );
        assert!(refused(json!({"pattern": "(?P<key>"})).starts_with("with.pattern: "));
        assert_eq!(
            refused(json!({"pattern": "(?P<key>x)", "flags": "i"})),
            "with.flags is unknown to match"
        );
    }

    #[test]
    fn json_takes_its_exit_mask_and_redact_through_the_op() {
        let with = json!({"exit-mask": 1, "redact": ["/serial"]});
        let reply = op(request("json", vec![], with)).unwrap();
        assert_eq!(reply.redact, ["/serial"]);
        let run = |exit, mask| {
            let with = json!({"exit-mask": mask});
            let input = Input::Exec(ExecInput {
                argv: vec!["/usr/bin/sensors".into()],
                stdout: r#"{"a": 1}"#.into(),
                stderr: "failed".into(),
                exit,
            });
            op(request("json", vec![input], with))
        };
        assert!(run(1, 1).unwrap().facts.contains_key("a"));
        assert!(run(8, 248).unwrap().facts.contains_key("a"));
        assert!(run(2, 1).is_err(), "bit 2 is outside the mask");
        assert!(run(4, 248).is_err(), "bit 4 is outside the mask");
    }

    #[test]
    fn an_op_other_than_match_refuses_with() {
        let error = op(request("lines", vec![], json!({"pattern": "x"}))).unwrap_err();
        assert_eq!(error.to_string(), "op lines takes no with");
    }

    #[test]
    fn a_text_op_fails_on_a_command_that_exited_non_zero_and_exec_keeps_it() {
        let lines = |exit| {
            op(request(
                "lines",
                vec![exec("/bin/cmd -a", "x\n", exit)],
                json!({}),
            ))
        };
        assert_eq!(lines(0).unwrap().facts["/bin/cmd"], json!(["x"]));
        assert_eq!(
            lines(1).unwrap_err().to_string(),
            "/bin/cmd exited 1: denied"
        );
        let absent = lines(127).unwrap();
        assert!(absent.facts.is_empty());
        assert_eq!(absent.diagnostics[0].message, "exited 127: denied");
        let kept = op(request("exec", vec![exec("/bin/cmd", "", 1)], json!({}))).unwrap();
        assert_eq!(kept.facts["exit-status"], 1);
    }

    fn exec(argv: &str, stdout: &str, exit: i32) -> Input {
        Input::Exec(ExecInput {
            argv: argv.split(' ').map(str::to_owned).collect(),
            stdout: stdout.to_owned(),
            stderr: "denied\n".to_owned(),
            exit,
        })
    }

    #[test]
    fn ini_lists_every_value_and_joins_continued_lines() {
        let unit = "# head\nTop=1\n[Unit]\nDescription=App\n[Service]\nEnvironment=A=1\nEnvironment=\nEnvironment=B=2 \\\n  C=3\n; note\nbroken\nExecStart=/bin/app\n";
        let reply = ini(&[file("/etc/systemd/system/app.service", unit)]);
        let sections = &reply.facts["/etc/systemd/system/app.service"];
        assert_eq!(sections[""]["Top"], json!(["1"]));
        assert_eq!(
            sections["Service"]["Environment"],
            json!(["A=1", "", "B=2 C=3"])
        );
        assert_eq!(sections["Service"]["ExecStart"], json!(["/bin/app"]));
        assert_eq!(
            reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(),
            [Some(11)]
        );
        let open = ini(&[file("/x", "[S]\nA=1 \\\n")]);
        assert!(
            open.diagnostics[0].message.contains("past the end"),
            "{:?}",
            open.diagnostics
        );
    }

    #[test]
    fn json_merges_objects_and_names_the_rest() {
        let reply = json(
            &[
                file(
                    "/etc/docker/daemon.json",
                    r#"{"icc": false, "hosts": ["unix:///run/docker.sock"]}"#,
                ),
                file("/b", r#"{"icc": true, "live-restore": true}"#),
                file("/c", "[1]"),
                file("/d", "{\n  \"x\": ,\n}"),
            ],
            &Map::new(),
        )
        .unwrap();
        assert_eq!(
            (
                reply.facts["icc"].clone(),
                reply.facts["live-restore"].clone()
            ),
            (json!(false), json!(true))
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| (d.path.as_str(), d.line))
                .collect::<Vec<_>>(),
            [("/c", None), ("/d", Some(2))]
        );
        assert!(reply.diagnostics[0].message.contains("list"));
    }

    #[test]
    fn json_exit_mask_reads_an_exit_whose_bits_it_holds_only() {
        let run = |exit, key: &str| {
            Input::Exec(ExecInput {
                argv: vec!["/usr/sbin/smartctl".into()],
                stdout: format!(r#"{{"{key}": {exit}}}"#),
                stderr: "failed".into(),
                exit,
            })
        };
        let with = json!({"exit-mask": 248}).as_object().unwrap().clone();
        let reply = json(
            &[run(8, "a"), run(255, "b"), run(4, "c"), run(0, "d")],
            &with,
        )
        .unwrap();
        assert_eq!(reply.facts.keys().collect::<Vec<_>>(), ["a", "d"]);
        assert_eq!(reply.diagnostics.len(), 2, "{:?}", reply.diagnostics);
        assert!(json(&[run(8, "a")], &Map::new()).unwrap().facts.is_empty());
        for bad in [
            json!({"exit-mask": 0}),
            json!({"exit-mask": 256}),
            json!({"mask": 8}),
        ] {
            assert!(json(&[], bad.as_object().unwrap()).is_err(), "{bad}");
        }
        let with = json!({"redact": ["/serial_number", "/wwn"]});
        let reply = json(&[run(0, "a")], with.as_object().unwrap()).unwrap();
        assert_eq!(reply.redact, ["/serial_number", "/wwn"]);
        for bad in [
            json!({"redact": "/a"}),
            json!({"redact": ["a"]}),
            json!({"redact": [1]}),
        ] {
            assert!(json(&[], bad.as_object().unwrap()).is_err(), "{bad}");
        }
        for good in [json!({"exit-mask": 1}), json!({"exit-mask": 255})] {
            assert!(json(&[], good.as_object().unwrap()).is_ok(), "{good}");
        }
    }

    #[test]
    fn mask_hides_all_userinfo_shapes() {
        assert_eq!(
            mask("http://u:p@proxy:3128/"),
            "http://[redacted]@proxy:3128/"
        );
        assert_eq!(
            mask("https://secret-bearer-token@apt.example.com/debian/"),
            "https://[redacted]@apt.example.com/debian/"
        );
        assert_eq!(
            mask("https://oauth-pat:x-oauth-basic@proxy.example.com:8443/path"),
            "https://[redacted]@proxy.example.com:8443/path"
        );
        assert_eq!(
            mask("https://api-key:@proxy.example.com?q=1"),
            "https://[redacted]@proxy.example.com?q=1"
        );
        assert_eq!(mask("http://proxy:3128"), "http://proxy:3128");
        assert_eq!(mask("https://@host/"), "https://@host/");
    }

    #[test]
    fn passwd_keys_accounts_by_name_the_first_line_winning() {
        let reply = passwd(&[file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n# a comment\n\n  toor::0:0::/root:/bin/sh\nbob:$6$salt$hash:1000:1000:Bob,,,:/home/bob:/bin/bash\nroot:x:1001:1001::/x:/bin/sh\nbad:x:zero:0::/:/bin/sh\nshort:x:1:1\n",
        )]);
        assert_eq!(
            json!(reply.facts),
            json!({
                "root": {"password": "shadow", "uid": 0, "gid": 0, "gecos": "root", "home": "/root", "shell": "/bin/bash", "line": 1, "shadowed": [6]},
                "toor": {"password": "empty", "uid": 0, "gid": 0, "gecos": "", "home": "/root", "shell": "/bin/sh", "line": 4, "shadowed": []},
                "bob": {"password": "hash", "uid": 1000, "gid": 1000, "gecos": "Bob,,,", "home": "/home/bob", "shell": "/bin/bash", "line": 5, "shadowed": []},
            })
        );
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| (d.line, d.message.as_str()))
                .collect::<Vec<_>>(),
            [
                (Some(7), "uid \"zero\" is not a number"),
                (Some(8), "4 fields where 7 are expected"),
            ]
        );
    }

    #[test]
    fn passwd_marks_login_shells_as_getusershell_reads_them() {
        let with = Map::from_iter([("shells".to_owned(), json!("/etc/shells"))]);
        let users = file(
            "/etc/passwd",
            "root:x:0:0::/root:/bin/bash\nsync:x:4:65534::/bin:/bin/sync\nold:x:5:5::/:\nme:x:1000:1000::/home/me:/usr/bin/zsh\nnobody:x:65534:65534::/:/usr/sbin/nologin\n",
        );
        let shells = file("/etc/shells", "# /etc/shells\n/bin/sh\n  /bin/bash \n");
        let login = |reply: &Reply| {
            reply
                .facts
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        (v["login-shell"].clone(), v["interactive-shell"].clone()),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let reply = passwd_with(&[users.clone(), shells], &with).unwrap();
        assert_eq!(
            login(&reply),
            BTreeMap::from([
                ("me".to_owned(), (json!(false), json!(true))),
                ("nobody".to_owned(), (json!(false), json!(false))),
                ("old".to_owned(), (json!(true), json!(true))),
                ("root".to_owned(), (json!(true), json!(true))),
                ("sync".to_owned(), (json!(false), json!(false)))
            ]),
            "an empty shell is /bin/sh; an unlisted zsh is still interactive"
        );
        let fallback = passwd_with(std::slice::from_ref(&users), &with).unwrap();
        assert_eq!(
            login(&fallback)["root"].0,
            json!(false),
            "no /etc/shells: only /bin/sh and /bin/csh"
        );
        assert!(
            passwd_with(std::slice::from_ref(&users), &Map::new())
                .unwrap()
                .facts["root"]
                .get("login-shell")
                .is_none()
        );
        assert!(passwd_with(&[users], &Map::from_iter([("x".to_owned(), json!(1))])).is_err());
    }

    #[test]
    fn shadow_never_returns_a_hash() {
        let shadowed = shadow(&[file(
            "/etc/shadow",
            "root:$y$j9T$secret:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\nlocked:!$6$x:20000::::::\nopen::20000:0:99999:7:::\n",
        )]);
        let text = json!(shadowed.facts).to_string();
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(
            shadowed
                .facts
                .iter()
                .map(|(name, f)| (name.as_str(), f["password"].as_str().unwrap()))
                .collect::<Vec<_>>(),
            [
                ("daemon", "locked"),
                ("locked", "locked"),
                ("open", "empty"),
                ("root", "hash")
            ]
        );
    }

    #[test]
    fn shadow_types_ageing_as_days_or_null() {
        let shadowed = shadow(&[file(
            "/etc/shadow",
            "root:*:20000:0:99999:7:::\nbob:$6$x:0:1:365:7:45:20500:\nbad:*:soon::::::\n",
        )]);
        assert_eq!(
            json!(shadowed.facts["root"]),
            json!({"password": "locked", "last-change": 20000, "min-days": 0, "max-days": 99999, "warn-days": 7,
                   "inactive-days": null, "expire-day": null, "line": 1, "shadowed": []})
        );
        assert_eq!(shadowed.facts["bob"]["last-change"], 0);
        assert_eq!(shadowed.facts["bob"]["expire-day"], 20500);
        assert!(!shadowed.facts.contains_key("bad"));
        assert_eq!(
            shadowed.diagnostics[0].message,
            "last-change \"soon\" is not a number"
        );
    }

    #[test]
    fn shadow_marks_passwd_accounts_deferring_to_it_without_a_line() {
        let users = file(
            "/etc/passwd",
            "root:x:0:0::/root:/bin/sh\nghost:x:9:9::/:/bin/sh\nold:*:8:8::/:/bin/sh\n",
        );
        let lines = file(
            "/etc/shadow",
            "root:*:20000:0:99999:7:::\nstale:$6$x:20000:0:99999:7:::\n",
        );
        let with = Map::from_iter([("passwd".to_owned(), json!("/etc/passwd"))]);
        let reply = shadow_with(&[users.clone(), lines.clone()], &with).unwrap();
        assert_eq!(
            json!(reply.facts["ghost"]),
            json!({"password": "missing", "in-passwd": true})
        );
        assert_eq!(reply.facts["root"]["password"], "locked");
        assert_eq!(reply.facts["root"]["in-passwd"], true);
        assert_eq!(
            reply.facts["stale"]["in-passwd"], false,
            "a line no account holds"
        );
        let alone = shadow_with(&[lines], &with).unwrap();
        assert!(
            alone.facts["root"].get("in-passwd").is_none(),
            "no passwd read, so no line is known to lack an account"
        );
        assert!(
            !reply.facts.contains_key("old"),
            "a hash in passwd defers to nothing"
        );
        let unread = shadow_with(std::slice::from_ref(&users), &with).unwrap();
        assert!(
            unread.facts.is_empty(),
            "no shadow file read, so nothing is missing from it"
        );
        assert!(shadow_with(&[users], &Map::from_iter([("x".to_owned(), json!(1))])).is_err());
    }

    #[test]
    fn scalar_types_only_a_decimal_integer_without_a_leading_zero() {
        for (word, typed) in [
            ("0", json!(0)),
            ("27", json!(27)),
            ("-1", json!(-1)),
            ("9223372036854775807", json!(9223372036854775807_i64)),
            ("9223372036854775808", json!("9223372036854775808")),
            ("0644", json!("0644")),
            ("-0", json!("-0")),
            ("-", json!("-")),
            ("+1", json!("+1")),
            ("1.5", json!("1.5")),
            ("yes", json!("yes")),
            ("", json!("")),
        ] {
            assert_eq!(scalar(word), typed, "{word:?}");
        }
    }

    #[test]
    fn statfs_rounds_use_up_as_df_does_and_leaves_out_what_a_filesystem_never_counts() {
        let fs = |path: &str, blocks, free, available, files, files_free, read_only| {
            Input::File(FileInput {
                path: path.into(),
                content: None,
                content_base64: None,
                stat: None,
                statfs: Some(systemlint_protocol::Statfs {
                    blocks,
                    blocks_free: free,
                    blocks_available: available,
                    files,
                    files_free,
                    read_only,
                }),
                absent: false,
            })
        };
        let reply = statfs(&[
            fs("/", 1000, 150, 100, 200, 22, false),
            fs("/srv", 1000, 111, 111, 100, 100, false),
            fs("/proc", 0, 0, 0, 0, 0, false),
            fs("/snap/core/1", 100, 0, 0, 10, 0, true),
            file("/etc/x", ""),
        ]);
        assert_eq!(
            json!(reply.facts),
            json!({
                "/": {"blocks": 90, "inodes": 89, "read-only": false},
                "/srv": {"blocks": 89, "inodes": 0, "read-only": false},
                "/proc": {"read-only": false},
                "/snap/core/1": {"blocks": 100, "inodes": 100, "read-only": true},
            }),
            "850 of the 950 blocks a user may fill is 89.5 %, so 90"
        );
        assert_eq!(reply.diagnostics.len(), 1, "{:?}", reply.diagnostics);
    }
}
