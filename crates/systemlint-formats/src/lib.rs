// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use std::collections::BTreeMap;

mod auth;
mod kv;
mod words;
pub use auth::pam;
pub use kv::kv;
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
            ("exec", &[]),
            ("ini", &[]),
            ("json", &[]),
            ("kv", &[]),
            ("lines", &[]),
            ("match", &[]),
            ("pam", &[]),
            ("passwd", &[]),
            ("probes", &[]),
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
        ran(&request.inputs)?;
    }
    match request.op.as_str() {
        "csv" => Ok(csv(&request.inputs)),
        "exec" => Ok(exec(&request.inputs)),
        "ini" => Ok(ini(&request.inputs)),
        "json" => Ok(json(&request.inputs)),
        "kv" => kv(&request.inputs, &request.with),
        "lines" => Ok(lines(&request.inputs)),
        "match" => r#match(&request.inputs, &request.with),
        "pam" => Ok(pam(&request.inputs)),
        "passwd" => Ok(passwd(&request.inputs)),
        "probes" => Ok(probes(&request.inputs)),
        "shadow" => Ok(shadow(&request.inputs)),
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
const TEXT_OPS: [&str; 9] = [
    "csv", "ini", "json", "kv", "lines", "match", "toml", "words", "yaml",
];

/// The family ops that take typed options under `with`.
const WITH_OPS: [&str; 3] = ["kv", "match", "words"];

/// The typed options of `op` from `with`, or an error naming what is wrong.
pub fn options<T: serde::de::DeserializeOwned>(op: &str, with: &Map<String, Value>) -> Result<T> {
    serde_json::from_value(Value::Object(with.clone()))
        .map_err(|e| format!("{op} with: {e}").into())
}

/// A bare word as a fact: a decimal integer with no leading zero becomes a number, anything else stays text.
pub fn scalar(word: &str) -> Value {
    let digits = word.strip_prefix('-').unwrap_or(word);
    let integer = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && word != "-0";
    match word.parse::<i64>() {
        Ok(n) if integer => Value::from(n),
        _ => Value::from(word),
    }
}

/// An error naming the first command that exited non-zero, 127 (absent) aside, so its collector fails rather than reading as empty.
fn ran(inputs: &[Input]) -> Result<()> {
    match inputs.iter().find_map(|i| match i {
        Input::Exec(run) if run.exit != 0 && run.exit != 127 => Some(run),
        _ => None,
    }) {
        Some(run) => Err(format!(
            "{} exited {}: {}",
            run.argv.join(" "),
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

/// A shadow(5) line’s facts, the hash reduced to its word.
fn shadow_entry(parts: &[&str]) -> std::result::Result<Map<String, Value>, String> {
    Ok(Map::from_iter([(
        "password".to_owned(),
        Value::from(password(parts[1])),
    )]))
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

/// Every account of shadow(5) files by name, with no hash.
pub fn shadow(inputs: &[Input]) -> Reply {
    accounts(inputs, 9, shadow_entry)
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

/// Every input’s top-level JSON object merged into one, the first input holding a key winning.
pub fn json(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
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
    reply
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

/// Places `value` at `key` split on `separator` in `map`, refusing a key that crosses a value.
pub fn nest(
    map: &mut Map<String, Value>,
    key: &str,
    separator: char,
    value: Value,
) -> std::result::Result<(), String> {
    let segments: Vec<&str> = key.split(separator).collect();
    let (last, parents) = segments.split_last().ok_or("empty key")?;
    let mut at = map;
    for segment in parents {
        at = at
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| format!("{key} crosses {segment}, which holds a value"))?;
    }
    if at.get(*last).is_some_and(Value::is_object) {
        return Err(format!("{key} holds both a value and keys below it"));
    }
    at.insert((*last).to_owned(), value);
    Ok(())
}

/// Each unit’s `enabled` and `masked` from the unit directories, plus `active` and `sub` when `systemctl list-units` exited 0.
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
    if let Some(exec) = live {
        let mut seen = std::collections::BTreeSet::new();
        for line in exec.stdout.lines().filter(|l| !l.trim().is_empty()) {
            match line.split_whitespace().collect::<Vec<_>>()[..] {
                [name, _, active, sub, ..] => {
                    let unit = units.entry(name.to_owned()).or_default();
                    unit.insert("active".to_owned(), Value::from(active));
                    unit.insert("sub".to_owned(), Value::from(sub));
                    seen.insert(name.to_owned());
                }
                _ => reply.diagnostics.push(Diagnostic {
                    path: exec.argv.join(" "),
                    line: None,
                    message: format!("no “unit load active sub” in {line:?}"),
                }),
            }
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

/// `uri` with its password replaced, so no credential reaches the facts.
pub fn mask(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return uri.to_owned();
    };
    let authority = rest.split('/').next().unwrap_or_default();
    match authority
        .rsplit_once('@')
        .and_then(|(info, host)| info.split_once(':').map(|(user, _)| (user, host)))
    {
        Some((user, host)) => format!(
            "{scheme}://{user}:[redacted]@{host}{}",
            &rest[authority.len()..]
        ),
        None => uri.to_owned(),
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
                "csv", "exec", "ini", "json", "kv", "lines", "match", "pam", "passwd", "probes",
                "shadow", "stat", "statfs", "systemd", "toml", "words", "yaml"
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
        let listed = "ufw.service loaded active exited Uncomplicated firewall\nhome.mount not-found inactive dead home.mount\n\nbroken\n";
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
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>(),
            ["no “unit load active sub” in \"broken\""]
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
            "/bin/cmd -a exited 1: denied"
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
        let reply = json(&[
            file(
                "/etc/docker/daemon.json",
                r#"{"icc": false, "hosts": ["unix:///run/docker.sock"]}"#,
            ),
            file("/b", r#"{"icc": true, "live-restore": true}"#),
            file("/c", "[1]"),
            file("/d", "{\n  \"x\": ,\n}"),
        ]);
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
    fn mask_hides_a_password_only() {
        assert_eq!(
            mask("http://u:p@proxy:3128/"),
            "http://u:[redacted]@proxy:3128/"
        );
        assert_eq!(mask("http://proxy:3128"), "http://proxy:3128");
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
