// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{
    Describe, Diagnostic, FileInput, FileKind, Input, Reply, Request, Result,
};

/// The sysctl.d directories systemd-sysctl reads, highest precedence first; `/etc/sysctl.conf` applies after them all.
pub const SYSCTL_DIRS: [&str; 5] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
];

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
            ("fstab", &[]),
            ("group", &[]),
            ("ini", &[]),
            ("json", &[]),
            ("kv", &[]),
            ("lines", &[]),
            ("mountinfo", &[]),
            ("passwd", &[]),
            ("probes", &[]),
            ("resolv", &[]),
            ("shadow", &[]),
            ("stat", &[]),
            ("statfs", &[]),
            ("sysctl", &[]),
            ("systemd", &[]),
            ("toml", &[]),
            ("yaml", &[]),
        ],
    )
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "csv" => Ok(csv(&request.inputs)),
        "exec" => Ok(exec(&request.inputs)),
        "fstab" => Ok(fstab(&request.inputs)),
        "group" => Ok(group(&request.inputs)),
        "ini" => Ok(ini(&request.inputs)),
        "json" => Ok(json(&request.inputs)),
        "kv" => Ok(kv(&request.inputs)),
        "lines" => Ok(lines(&request.inputs)),
        "mountinfo" => Ok(mountinfo(&request.inputs)),
        "passwd" => Ok(passwd(&request.inputs)),
        "probes" => Ok(probes(&request.inputs)),
        "resolv" => Ok(resolv(&request.inputs)),
        "shadow" => Ok(shadow(&request.inputs)),
        "stat" => Ok(stat(&request.inputs)),
        "statfs" => Ok(statfs(&request.inputs)),
        "sysctl" => Ok(sysctl(&request.inputs)),
        "systemd" => Ok(systemd(&request.inputs)),
        "toml" => Ok(toml(&request.inputs)),
        "yaml" => Ok(yaml(&request.inputs)),
        other => Err(format!("unknown op {other}").into()),
    }
}

/// Every `key=value` line of every input in one object, the first input holding a key winning; values unquoted as a shell would.
pub fn kv(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let (path, text) = match input {
            Input::File(file) => (file.path.clone(), file.content.as_deref()),
            Input::Exec(exec) => (exec.argv.join(" "), Some(exec.stdout.as_str())),
            Input::Probe(probe) => (probe.target.clone(), None),
        };
        let mut diagnose = |line: Option<u64>, message: String| {
            reply.diagnostics.push(Diagnostic {
                path: path.clone(),
                line,
                message,
            })
        };
        let Some(text) = text else {
            diagnose(None, "not UTF-8 text, skipped".to_owned());
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let number = Some(index as u64 + 1);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                diagnose(number, format!("no = in {line:?}"));
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                diagnose(number, "a value with no key".to_owned());
                continue;
            }
            match unquote(value.trim()) {
                Ok(value) => {
                    reply
                        .facts
                        .entry(key.to_owned())
                        .or_insert(Value::from(value));
                }
                Err(message) => diagnose(number, format!("{key}: {message}")),
            }
        }
    }
    reply
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

/// A group(5) line’s facts.
fn group_entry(parts: &[&str]) -> std::result::Result<Map<String, Value>, String> {
    let members: Vec<&str> = parts[3].split(',').filter(|m| !m.is_empty()).collect();
    Ok(Map::from_iter([
        ("password".to_owned(), Value::from(password(parts[1]))),
        ("gid".to_owned(), id(parts, 2, "gid")?),
        ("members".to_owned(), Value::from(members)),
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

/// Every group of group(5) files by name.
pub fn group(inputs: &[Input]) -> Reply {
    accounts(inputs, 4, group_entry)
}

/// Every account of shadow(5) files by name, with no hash.
pub fn shadow(inputs: &[Input]) -> Reply {
    accounts(inputs, 9, shadow_entry)
}

/// A mount table field with its `\040`-style octal escapes decoded.
fn unoctal(field: &str) -> String {
    let (bytes, mut out, mut i) = (field.as_bytes(), Vec::with_capacity(field.len()), 0);
    while i < bytes.len() {
        let code = bytes.get(i + 1..i + 4).filter(|_| bytes[i] == b'\\');
        match code.and_then(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 8).ok()) {
            Some(byte) => (out.push(byte), i += 4),
            None => (out.push(bytes[i]), i += 1),
        };
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fstab(5) options as mount(8) applies them: `user`, `users`, `owner` and `group` add what they imply, and a later `dev`, `suid` or `exec` drops its `no` form.
fn fstab_options(written: &str) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for option in written.split(',').filter(|o| !o.is_empty()) {
        let implied: &[&str] = match option {
            "user" | "users" => &["noexec", "nosuid", "nodev"],
            "owner" | "group" => &["nosuid", "nodev"],
            _ => &[],
        };
        for o in std::iter::once(option).chain(implied.iter().copied()) {
            let opposite = o.strip_prefix("no").map_or(format!("no{o}"), str::to_owned);
            options.retain(|kept| *kept != opposite && kept != o);
            options.push(o.to_owned());
        }
    }
    options
}

/// One mount table line’s mount point and facts, `None` to skip it, or the message naming the bad field.
type MountEntry = fn(&[&str]) -> std::result::Result<Option<(String, Map<String, Value>)>, String>;

/// Every mount of mount table inputs keyed by mount point, a later line over the same point winning as the kernel stacks it; `entry` gives a line’s mount point and facts, or `None` to skip it.
fn mount_table(inputs: &[Input], entry: MountEntry) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        for (index, raw) in text.lines().enumerate() {
            let fields: Vec<&str> = raw.split_whitespace().collect();
            if fields.first().is_none_or(|f| f.starts_with('#')) {
                continue;
            }
            match entry(&fields) {
                Ok(Some((point, mut facts))) => {
                    facts.insert("line".to_owned(), Value::from(index as u64 + 1));
                    reply.facts.insert(point, Value::Object(facts));
                }
                Ok(None) => {}
                Err(message) => reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: Some(index as u64 + 1),
                    message,
                }),
            }
        }
    }
    reply
}

/// Every mount of `/proc/*/mountinfo` by mount point: `source`, `filesystem`, the per-mount `options` and the filesystem’s `super-options`.
pub fn mountinfo(inputs: &[Input]) -> Reply {
    mount_table(inputs, |fields| {
        let dash = fields
            .iter()
            .position(|f| *f == "-")
            .filter(|d| *d >= 6 && d + 3 < fields.len());
        let Some(dash) = dash else {
            return Err(
                "not a mountinfo line: no ` - ` after six fields with three after it".to_owned(),
            );
        };
        let list = |s: &str| Value::from(s.split(',').map(unoctal).collect::<Vec<_>>());
        Ok(Some((
            unoctal(fields[4]),
            Map::from_iter([
                ("source".to_owned(), Value::from(unoctal(fields[dash + 2]))),
                ("filesystem".to_owned(), Value::from(fields[dash + 1])),
                ("options".to_owned(), list(fields[5])),
                ("super-options".to_owned(), list(fields[dash + 3])),
            ]),
        )))
    })
}

/// Every mount of fstab(5) files by mount point, swap left out: `source`, `filesystem` and the effective `options`.
pub fn fstab(inputs: &[Input]) -> Reply {
    mount_table(inputs, |fields| {
        if !(3..=6).contains(&fields.len()) {
            return Err(format!("{} fields where 3 to 6 are expected", fields.len()));
        }
        if fields[2] == "swap" {
            return Ok(None);
        }
        Ok(Some((
            unoctal(fields[1]),
            Map::from_iter([
                ("source".to_owned(), Value::from(unoctal(fields[0]))),
                ("filesystem".to_owned(), Value::from(fields[2])),
                (
                    "options".to_owned(),
                    Value::from(fstab_options(fields.get(3).copied().unwrap_or("defaults"))),
                ),
            ]),
        )))
    })
}

/// The nameservers glibc asks, at most this many.
pub const MAXNS: usize = 3;

/// Every resolv.conf(5) by path, as glibc reads it: the first [`MAXNS`] valid `nameservers`, the last `search` or `domain` line’s `search` list, and every `options` word.
pub fn resolv(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let (mut nameservers, mut search, mut options) = (Vec::new(), Vec::new(), Vec::new());
        for (index, line) in text.lines().enumerate() {
            let mut words = line.split_whitespace();
            let (Some(keyword), rest) = (words.next(), words) else {
                continue;
            };
            let mut diagnose = |message: String| {
                reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: Some(index as u64 + 1),
                    message,
                })
            };
            match keyword {
                k if k.starts_with(['#', ';']) => {}
                "nameserver" => match rest.clone().next() {
                    Some(ip)
                        if ip
                            .split('%')
                            .next()
                            .unwrap_or(ip)
                            .parse::<std::net::IpAddr>()
                            .is_err() =>
                    {
                        diagnose(format!(
                            "nameserver {ip} is not an IP address, ignored as glibc does"
                        ))
                    }
                    Some(ip) if nameservers.len() < MAXNS => nameservers.push(ip.to_owned()),
                    Some(ip) => diagnose(format!(
                        "nameserver {ip} is past the first {MAXNS}, ignored as glibc does"
                    )),
                    None => diagnose("nameserver names no address".to_owned()),
                },
                "search" => search = rest.map(str::to_owned).collect(),
                "domain" => search = rest.take(1).map(str::to_owned).collect(),
                "sortlist" => {}
                "options" => options.extend(rest.map(str::to_owned)),
                other => diagnose(format!("keyword {other} is unknown, ignored")),
            }
        }
        reply.facts.insert(
            path.to_owned(),
            serde_json::json!({"nameservers": nameservers, "search": search, "options": options}),
        );
    }
    reply
}

/// The text of a file input, or a diagnostic when it is missing or not UTF-8.
pub fn text<'a>(input: &'a Input, diagnostics: &mut Vec<Diagnostic>) -> Option<(&'a str, &'a str)> {
    match input {
        Input::File(FileInput {
            path,
            content: Some(text),
            ..
        }) => Some((path, text)),
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
                message: "not a file, skipped".to_owned(),
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

/// Kernel parameters nested by their dotted keys: from `sysctl -a` when it exited 0, else from the sysctl.d files in systemd-sysctl’s order.
pub fn sysctl(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut flat = BTreeMap::new();
    let effective = inputs.iter().find_map(|i| match i {
        Input::Exec(e) if e.exit == 0 => Some(e),
        Input::Exec(e) if e.exit != 127 => {
            reply.diagnostics.push(Diagnostic {
                path: e.argv.join(" "),
                line: None,
                message: format!(
                    "exited {}, read from the files: {}",
                    e.exit,
                    e.stderr.trim()
                ),
            });
            None
        }
        _ => None,
    });
    let source = if let Some(exec) = effective {
        for line in exec.stdout.lines().filter(|l| !l.trim().is_empty()) {
            match line.split_once(" = ") {
                Some((key, value)) => {
                    drop(flat.insert(key.trim().to_owned(), value.trim().to_owned()))
                }
                None => reply.diagnostics.push(Diagnostic {
                    path: exec.argv.join(" "),
                    line: None,
                    message: format!("no “key = value” in {line:?}"),
                }),
            }
        }
        "effective"
    } else {
        let files: Vec<(&str, &str)> = inputs
            .iter()
            .filter(|i| matches!(i, Input::File(_)))
            .filter_map(|i| text(i, &mut reply.diagnostics))
            .collect();
        for (path, text) in sysctl_order(&files) {
            for (index, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(['#', ';']) {
                    continue;
                }
                match line.trim_start_matches('-').split_once('=') {
                    Some((key, value)) if !key.trim().is_empty() => {
                        drop(flat.insert(sysctl_key(key.trim()), value.trim().to_owned()))
                    }
                    _ => reply.diagnostics.push(Diagnostic {
                        path: path.to_owned(),
                        line: Some(index as u64 + 1),
                        message: format!("no key = value in {line:?}"),
                    }),
                }
            }
        }
        if files.is_empty() { "none" } else { "files" }
    };
    let mut settings = Map::new();
    for (key, value) in flat {
        let value = value
            .parse::<i64>()
            .map_or_else(|_| Value::from(value.clone()), Value::from);
        if let Err(message) = nest(&mut settings, &key, value) {
            reply.diagnostics.push(Diagnostic {
                path: key,
                line: None,
                message,
            });
        }
    }
    reply.facts.insert("source".to_owned(), Value::from(source));
    reply
        .facts
        .insert("settings".to_owned(), Value::Object(settings));
    reply
}

/// The sysctl files in the order systemd-sysctl applies them: one file per name from the highest directory, by name, `/etc/sysctl.conf` last.
pub fn sysctl_order<'a>(files: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut chosen: BTreeMap<&str, (usize, &str, &str)> = BTreeMap::new();
    let mut conf = None;
    for (path, text) in files {
        if *path == "/etc/sysctl.conf" {
            conf = Some((*path, *text));
            continue;
        }
        let Some((dir, name)) = path.rsplit_once('/') else {
            continue;
        };
        let Some(rank) = SYSCTL_DIRS.iter().position(|d| *d == dir) else {
            continue;
        };
        if chosen.get(name).is_none_or(|(r, _, _)| rank < *r) {
            chosen.insert(name, (rank, path, text));
        }
    }
    chosen
        .into_values()
        .map(|(_, p, t)| (p, t))
        .chain(conf)
        .collect()
}

/// A sysctl key with `.` separators, swapping `/` and `.` when `/` comes first as systemd does.
pub fn sysctl_key(key: &str) -> String {
    match key.find(['.', '/']) {
        Some(i) if key.as_bytes()[i] == b'/' => key
            .chars()
            .map(|c| match c {
                '/' => '.',
                '.' => '/',
                c => c,
            })
            .collect(),
        _ => key.to_owned(),
    }
}

/// Places `value` at the dotted `key` in `map`, refusing a key that crosses a value.
pub fn nest(
    map: &mut Map<String, Value>,
    key: &str,
    value: Value,
) -> std::result::Result<(), String> {
    let segments: Vec<&str> = key.split('.').collect();
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
                "csv",
                "exec",
                "fstab",
                "group",
                "ini",
                "json",
                "kv",
                "lines",
                "mountinfo",
                "passwd",
                "probes",
                "resolv",
                "shadow",
                "stat",
                "statfs",
                "sysctl",
                "systemd",
                "toml",
                "yaml"
            ]
        );
        assert!(describe.ops.iter().all(|o| o.needs.is_empty()));
    }

    #[test]
    fn kv_reads_the_fixture_os_release() {
        let reply = kv(&[file(
            "/usr/lib/os-release",
            include_str!("../../../fixtures/ubuntu-26.04/usr/lib/os-release"),
        )]);
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
        let reply = kv(&[file("/etc/a", "A=file\n"), exec]);
        assert_eq!(
            (reply.facts["A"].as_str(), reply.facts["B"].as_str()),
            (Some("file"), Some("exec"))
        );
    }

    #[test]
    fn kv_names_each_bad_line() {
        let reply = kv(&[file(
            "/etc/x",
            "# comment\n\nGOOD = spaced \nno equals\n=orphan\nOPEN=\"half\n",
        )]);
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
        let reply = kv(&[input]);
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
    fn lines_keys_each_file_by_path_and_skips_a_command() {
        let exec = Input::Exec(ExecInput {
            argv: vec!["/bin/true".into()],
            stdout: "x".into(),
            stderr: String::new(),
            exit: 0,
        });
        let reply = super::lines(&[file("/etc/a", "one\r\n\ntwo"), file("/etc/empty", ""), exec]);
        assert_eq!(reply.facts["/etc/a"], serde_json::json!(["one", "", "two"]));
        assert_eq!(reply.facts["/etc/empty"], serde_json::json!([]));
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["/bin/true"]
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
        };
        assert!(op(request).unwrap_err().to_string().contains("regex"));
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
    fn sysctl_takes_sysctl_a_when_it_ran() {
        let files = file("/etc/sysctl.d/10-x.conf", "kernel.kptr_restrict = 0\n");
        let reply = sysctl(&[
            files.clone(),
            exec(
                "/usr/sbin/sysctl -a",
                "kernel.kptr_restrict = 2\nnet.ipv4.conf.eth0/100.rp_filter = 1\nnet.ipv4.ip_local_port_range = 32768\t60999\n",
                0,
            ),
        ]);
        assert_eq!(reply.facts["source"], "effective");
        let settings = &reply.facts["settings"];
        assert_eq!(settings["kernel"]["kptr_restrict"], 2);
        assert_eq!(settings["net"]["ipv4"]["conf"]["eth0/100"]["rp_filter"], 1);
        assert_eq!(
            settings["net"]["ipv4"]["ip_local_port_range"],
            "32768\t60999"
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        let absent = sysctl(&[files.clone(), exec("/usr/sbin/sysctl -a", "", 127)]);
        assert_eq!(
            (
                absent.facts["source"].as_str(),
                absent.facts["settings"]["kernel"]["kptr_restrict"].as_i64()
            ),
            (Some("files"), Some(0))
        );
        assert!(absent.diagnostics.is_empty());
        let failed = sysctl(&[exec("/usr/sbin/sysctl -a", "", 1)]);
        assert_eq!(failed.facts["source"], "none");
        assert!(
            failed.diagnostics[0]
                .message
                .contains("exited 1, read from the files: denied"),
            "{:?}",
            failed.diagnostics
        );
    }

    #[test]
    fn sysctl_files_follow_systemd_order() {
        let reply = sysctl(&[
            file("/etc/sysctl.conf", "kernel.c = conf\n"),
            file("/etc/sysctl.d/50-same.conf", "kernel.a = etc\n"),
            file(
                "/usr/lib/sysctl.d/50-same.conf",
                "kernel.a = usr\nkernel.b = usr\n",
            ),
            file(
                "/usr/lib/sysctl.d/10-early.conf",
                "kernel.b = early\nkernel/c = early\n-net/ipv4/conf/eth0.100/rp_filter=2\n; c\nbad line\n",
            ),
            file("/usr/lib/sysctl.d/99-late.conf", "kernel.a.deeper = 1\n"),
            file("/opt/sysctl.d/00-ignored.conf", "kernel.a = ignored\n"),
        ]);
        let settings = &reply.facts["settings"];
        assert_eq!(
            (
                settings["kernel"]["a"].as_str(),
                settings["kernel"]["b"].as_str(),
                settings["kernel"]["c"].as_str()
            ),
            (Some("etc"), Some("early"), Some("conf"))
        );
        assert_eq!(settings["net"]["ipv4"]["conf"]["eth0/100"]["rp_filter"], 2);
        assert_eq!(
            reply
                .diagnostics
                .iter()
                .map(|d| (d.path.as_str(), d.line))
                .collect::<Vec<_>>(),
            [
                ("/usr/lib/sysctl.d/10-early.conf", Some(5)),
                ("kernel.a.deeper", None)
            ]
        );
    }

    #[test]
    fn sysctl_keys_swap_only_when_a_slash_comes_first() {
        assert_eq!(
            sysctl_key("net/ipv4/conf/eth0.100/rp_filter"),
            "net.ipv4.conf.eth0/100.rp_filter"
        );
        assert_eq!(
            sysctl_key("net.ipv4.conf.eth0/100.rp_filter"),
            "net.ipv4.conf.eth0/100.rp_filter"
        );
        assert_eq!(sysctl_key("kernel"), "kernel");
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
    fn group_lists_members_and_shadow_never_returns_a_hash() {
        let groups = group(&[file("/etc/group", "sudo:x:27:alice,bob\nusers:x:100:\n")]);
        assert_eq!(
            json!(groups.facts),
            json!({
                "sudo": {"password": "shadow", "gid": 27, "members": ["alice", "bob"], "line": 1, "shadowed": []},
                "users": {"password": "shadow", "gid": 100, "members": [], "line": 2, "shadowed": []},
            })
        );
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

    #[test]
    fn mountinfo_keys_mounts_by_point_the_top_of_a_stack_winning() {
        let reply = mountinfo(&[file(
            "/proc/self/mountinfo",
            "22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             30 22 0:30 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,size=50%\n\
             31 30 0:31 / /tmp rw - tmpfs tmpfs rw\n\
             32 22 0:32 / /mnt/my\\040disk rw,noexec - vfat /dev/sd\\134b rw\n\
             33 22 0:33 / /bad rw shared:1 - tmpfs\n",
        )]);
        assert_eq!(
            json!(reply.facts),
            json!({
                "/": {"source": "/dev/sda1", "filesystem": "ext4", "options": ["rw", "relatime"], "super-options": ["rw"], "line": 1},
                "/tmp": {"source": "tmpfs", "filesystem": "tmpfs", "options": ["rw"], "super-options": ["rw"], "line": 3},
                "/mnt/my disk": {"source": "/dev/sd\\b", "filesystem": "vfat", "options": ["rw", "noexec"], "super-options": ["rw"], "line": 4},
            })
        );
        assert_eq!(
            reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(),
            [Some(5)]
        );
    }

    #[test]
    fn fstab_applies_implied_and_later_options_and_skips_swap() {
        let reply = fstab(&[file(
            "/etc/fstab",
            "# comment\n\
             UUID=1 / ext4 defaults 0 1\n\
             tmpfs /tmp tmpfs nosuid,nodev,noexec,dev 0 0\n\
             /dev/sdb /media/usb vfat users,exec\n\
             /dev/sdc /srv/a\\040b xfs\n\
             /swapfile none swap sw 0 0\n\
             /dev/sdd /x ext4 defaults 0 0 extra\n",
        )]);
        assert_eq!(
            json!(reply.facts),
            json!({
                "/": {"source": "UUID=1", "filesystem": "ext4", "options": ["defaults"], "line": 2},
                "/tmp": {"source": "tmpfs", "filesystem": "tmpfs", "options": ["nosuid", "noexec", "dev"], "line": 3},
                "/media/usb": {"source": "/dev/sdb", "filesystem": "vfat", "options": ["users", "nosuid", "nodev", "exec"], "line": 4},
                "/srv/a b": {"source": "/dev/sdc", "filesystem": "xfs", "options": ["defaults"], "line": 5},
            })
        );
        assert_eq!(
            reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(),
            [Some(7)]
        );
    }

    #[test]
    fn resolv_keeps_the_first_three_valid_nameservers_and_the_last_search_as_glibc() {
        let reply = resolv(&[file(
            "/etc/resolv.conf",
            "# comment\n\
             ; comment\n\
             search a.test b.test\n\
             nameserver nonsense\n\
             nameserver 127.0.0.53\n\
             nameserver fe80::1%eth0\n\
             options edns0\n\
             nameserver 192.0.2.1\n\
             nameserver 192.0.2.2\n\
             domain c.test d.test\n\
             sortlist 10.0.0.0/8\n\
             options ndots:2 trust-ad\n\
             lookup file bind\n",
        )]);
        assert_eq!(
            json!(reply.facts),
            json!({"/etc/resolv.conf": {
                "nameservers": ["127.0.0.53", "fe80::1%eth0", "192.0.2.1"],
                "search": ["c.test"],
                "options": ["edns0", "ndots:2", "trust-ad"],
            }})
        );
        assert_eq!(
            reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(),
            [Some(4), Some(9), Some(13)]
        );
    }

    #[test]
    fn unoctal_decodes_three_octal_digits_only() {
        assert_eq!(unoctal("a\\040b\\011c\\134"), "a b\tc\\");
        assert_eq!(unoctal("\\04"), "\\04");
        assert_eq!(unoctal("\\777x"), "\\777x");
        assert_eq!(unoctal("\\08a"), "\\08a");
    }
}
