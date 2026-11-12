// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Describe, Diagnostic, FileInput, Input, Reply, Request, Result};

/// The sysctl.d directories systemd-sysctl reads, highest precedence first; `/etc/sysctl.conf` applies after them all.
pub const SYSCTL_DIRS: [&str; 5] = ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"];

/// One INI file: every value of every key, by section; keys before the first section sit under `""`.
pub type Sections = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("formats", &[("ini", &[]), ("json", &[]), ("kv", &[]), ("lines", &[]), ("regex", &[]), ("stat", &[]), ("sysctl", &[]), ("toml", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "ini" => Ok(ini(&request.inputs)),
        "json" => Ok(json(&request.inputs)),
        "kv" => Ok(kv(&request.inputs)),
        "stat" => Ok(stat(&request.inputs)),
        "sysctl" => Ok(sysctl(&request.inputs)),
        other => Err(format!("op {other} is not implemented yet").into()),
    }
}

/// Every `key=value` line of every input in one object, the first input holding a key winning; values unquoted as a shell would.
pub fn kv(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let (path, text) = match input {
            Input::File(file) => (file.path.clone(), file.content.as_deref()),
            Input::Exec(exec) => (exec.argv.join(" "), Some(exec.stdout.as_str())),
        };
        let mut diagnose = |line: Option<u64>, message: String| reply.diagnostics.push(Diagnostic { path: path.clone(), line, message });
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
                    reply.facts.entry(key.to_owned()).or_insert(Value::from(value));
                }
                Err(message) => diagnose(number, format!("{key}: {message}")),
            }
        }
    }
    reply
}

/// Every input’s stat keyed by its path; an input the core sent without one gets a diagnostic.
pub fn stat(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        match input {
            Input::File(FileInput { path, stat: Some(stat), .. }) => {
                reply.facts.insert(path.clone(), serde_json::to_value(stat).unwrap_or_default());
            }
            Input::File(FileInput { path, .. }) => reply.diagnostics.push(Diagnostic { path: path.clone(), line: None, message: "no stat; list it under read.stat".to_owned() }),
            Input::Exec(exec) => reply.diagnostics.push(Diagnostic { path: exec.argv.join(" "), line: None, message: "a command has no stat".to_owned() }),
        }
    }
    reply
}

/// The text of a file input, or a diagnostic when it is missing or not UTF-8.
pub fn text<'a>(input: &'a Input, diagnostics: &mut Vec<Diagnostic>) -> Option<(&'a str, &'a str)> {
    match input {
        Input::File(FileInput { path, content: Some(text), .. }) => Some((path, text)),
        Input::File(FileInput { path, .. }) => {
            diagnostics.push(Diagnostic { path: path.clone(), line: None, message: "not UTF-8 text, skipped".to_owned() });
            None
        }
        Input::Exec(exec) => {
            diagnostics.push(Diagnostic { path: exec.argv.join(" "), line: None, message: "a command is not a file, skipped".to_owned() });
            None
        }
    }
}

/// Every input parsed as INI and keyed by its path: `[section]`, `key=value`, `#` and `;` comments, a trailing `\` joining the next line.
pub fn ini(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else { continue };
        let sections = parse_ini(text, |line, message| reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: Some(line), message }));
        reply.facts.insert(path.to_owned(), serde_json::to_value(sections).unwrap_or_default());
    }
    reply
}

/// The sections of one INI text, systemd’s flavour: a key repeats into a list, `\` at a line end continues it.
pub fn parse_ini(text: &str, mut diagnose: impl FnMut(u64, String)) -> Sections {
    let (mut sections, mut section, mut pending) = (Sections::new(), String::new(), None::<(u64, String)>);
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
            Some((key, value)) if !key.trim().is_empty() => sections.entry(section.clone()).or_default().entry(key.trim().to_owned()).or_default().push(value.trim().to_owned()),
            _ => diagnose(number, format!("no key=value in {line:?}")),
        }
    }
    if let Some((number, line)) = pending {
        diagnose(number, format!("{line:?} continues past the end of the file"));
    }
    sections
}

/// Every input’s top-level JSON object merged into one, the first input holding a key winning.
pub fn json(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else { continue };
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => {
                for (key, value) in map {
                    reply.facts.entry(key).or_insert(value);
                }
            }
            Ok(other) => reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: None, message: format!("holds a {}, not an object", kind(&other)) }),
            Err(e) => reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: Some(e.line() as u64), message: format!("not valid JSON: {e}") }),
        }
    }
    reply
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
            reply.diagnostics.push(Diagnostic { path: e.argv.join(" "), line: None, message: format!("exited {}, read from the files: {}", e.exit, e.stderr.trim()) });
            None
        }
        _ => None,
    });
    let source = if let Some(exec) = effective {
        for line in exec.stdout.lines().filter(|l| !l.trim().is_empty()) {
            match line.split_once(" = ") {
                Some((key, value)) => drop(flat.insert(key.trim().to_owned(), value.trim().to_owned())),
                None => reply.diagnostics.push(Diagnostic { path: exec.argv.join(" "), line: None, message: format!("no “key = value” in {line:?}") }),
            }
        }
        "effective"
    } else {
        let files: Vec<(&str, &str)> = inputs.iter().filter(|i| matches!(i, Input::File(_))).filter_map(|i| text(i, &mut reply.diagnostics)).collect();
        for (path, text) in sysctl_order(&files) {
            for (index, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(['#', ';']) {
                    continue;
                }
                match line.trim_start_matches('-').split_once('=') {
                    Some((key, value)) if !key.trim().is_empty() => drop(flat.insert(sysctl_key(key.trim()), value.trim().to_owned())),
                    _ => reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: Some(index as u64 + 1), message: format!("no key = value in {line:?}") }),
                }
            }
        }
        if files.is_empty() { "none" } else { "files" }
    };
    let mut settings = Map::new();
    for (key, value) in flat {
        let value = value.parse::<i64>().map_or_else(|_| Value::from(value.clone()), Value::from);
        if let Err(message) = nest(&mut settings, &key, value) {
            reply.diagnostics.push(Diagnostic { path: key, line: None, message });
        }
    }
    reply.facts.insert("source".to_owned(), Value::from(source));
    reply.facts.insert("settings".to_owned(), Value::Object(settings));
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
        let Some((dir, name)) = path.rsplit_once('/') else { continue };
        let Some(rank) = SYSCTL_DIRS.iter().position(|d| *d == dir) else { continue };
        if chosen.get(name).is_none_or(|(r, _, _)| rank < *r) {
            chosen.insert(name, (rank, path, text));
        }
    }
    chosen.into_values().map(|(_, p, t)| (p, t)).chain(conf).collect()
}

/// A sysctl key with `.` separators, swapping `/` and `.` when `/` comes first as systemd does.
pub fn sysctl_key(key: &str) -> String {
    match key.find(['.', '/']) {
        Some(i) if key.as_bytes()[i] == b'/' => key.chars().map(|c| match c {
            '/' => '.',
            '.' => '/',
            c => c,
        }).collect(),
        _ => key.to_owned(),
    }
}

/// Places `value` at the dotted `key` in `map`, refusing a key that crosses a value.
pub fn nest(map: &mut Map<String, Value>, key: &str, value: Value) -> std::result::Result<(), String> {
    let segments: Vec<&str> = key.split('.').collect();
    let (last, parents) = segments.split_last().ok_or("empty key")?;
    let mut at = map;
    for segment in parents {
        at = at.entry((*segment).to_owned()).or_insert_with(|| Value::Object(Map::new())).as_object_mut().ok_or_else(|| format!("{key} crosses {segment}, which holds a value"))?;
    }
    if at.get(*last).is_some_and(Value::is_object) {
        return Err(format!("{key} holds both a value and keys below it"));
    }
    at.insert((*last).to_owned(), value);
    Ok(())
}

/// `uri` with its password replaced, so no credential reaches the facts.
pub fn mask(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once("://") else { return uri.to_owned() };
    let authority = rest.split('/').next().unwrap_or_default();
    match authority.rsplit_once('@').and_then(|(info, host)| info.split_once(':').map(|(user, _)| (user, host))) {
        Some((user, host)) => format!("{scheme}://{user}:[redacted]@{host}{}", &rest[authority.len()..]),
        None => uri.to_owned(),
    }
}

/// The value of `raw` as a shell reads one word: `"…"` with `\"`, `\\`, `\$` and `` \` `` escapes, `'…'` literal, else as is.
pub fn unquote(raw: &str) -> std::result::Result<String, String> {
    let Some(quote) = raw.chars().next().filter(|c| *c == '"' || *c == '\'') else {
        return Ok(raw.to_owned());
    };
    let inner = raw.strip_prefix(quote).and_then(|r| r.strip_suffix(quote)).filter(|_| raw.len() >= 2).ok_or_else(|| format!("unterminated {quote} quote"))?;
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
        Input::File(FileInput { path: path.to_owned(), content: Some(content.to_owned()), content_base64: None, stat: None })
    }

    #[test]
    fn describe_lists_the_generic_parsers() {
        let describe = describe();
        assert_eq!(describe.name, "formats");
        assert_eq!(describe.ops.iter().map(|o| o.op.as_str()).collect::<Vec<_>>(), ["ini", "json", "kv", "lines", "regex", "stat", "sysctl", "toml"]);
        assert!(describe.ops.iter().all(|o| o.needs.is_empty()));
    }

    #[test]
    fn kv_reads_the_fixture_os_release() {
        let reply = kv(&[file("/usr/lib/os-release", include_str!("../../../fixtures/ubuntu-26.04/usr/lib/os-release"))]);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(reply.facts["VERSION_CODENAME"], "resolute");
        assert_eq!(reply.facts["PRETTY_NAME"], "Ubuntu 26.04.1 LTS");
        assert_eq!(reply.facts["ID"], "ubuntu");
    }

    #[test]
    fn kv_first_input_wins_and_exec_stdout_counts() {
        let exec = Input::Exec(ExecInput { argv: vec!["/bin/env".into()], stdout: "A=exec\nB=exec\n".into(), stderr: String::new(), exit: 0 });
        let reply = kv(&[file("/etc/a", "A=file\n"), exec]);
        assert_eq!((reply.facts["A"].as_str(), reply.facts["B"].as_str()), (Some("file"), Some("exec")));
    }

    #[test]
    fn kv_names_each_bad_line() {
        let reply = kv(&[file("/etc/x", "# comment\n\nGOOD = spaced \nno equals\n=orphan\nOPEN=\"half\n")]);
        assert_eq!(reply.facts["GOOD"], "spaced");
        let lines: Vec<_> = reply.diagnostics.iter().map(|d| (d.path.as_str(), d.line)).collect();
        assert_eq!(lines, [("/etc/x", Some(4)), ("/etc/x", Some(5)), ("/etc/x", Some(6))]);
        assert!(reply.diagnostics[2].message.contains("OPEN: unterminated"), "{:?}", reply.diagnostics);
    }

    #[test]
    fn kv_skips_binary_input_with_a_diagnostic() {
        let input = Input::File(FileInput { path: "/bin".into(), content: None, content_base64: Some("AA==".into()), stat: None });
        let reply = kv(&[input]);
        assert!(reply.facts.is_empty());
        assert_eq!(reply.diagnostics[0].line, None);
    }

    #[test]
    fn unquote_follows_the_shell() {
        assert_eq!(unquote(r#""a \"b\" \\ \$c \`d\` \n""#).unwrap(), r#"a "b" \ $c `d` \n"#);
        assert_eq!(unquote(r#"'it \n "x"'"#).unwrap(), r#"it \n "x""#);
        assert_eq!(unquote("bare").unwrap(), "bare");
        assert_eq!(unquote("").unwrap(), "");
        assert_eq!(unquote(r#""""#).unwrap(), "");
        assert!(unquote("\"").is_err());
        assert!(unquote("'").is_err());
        assert!(unquote(r#""a"b""#).is_err());
    }

    #[test]
    fn stat_keys_each_stat_by_path_and_names_inputs_without_one() {
        let stat = Stat { kind: FileKind::File, mode: "0666".into(), uid: 0, gid: 0, size: 3, world_writable: true, group_writable: true, setuid: false, setgid: false, linked_to: None };
        let with = Input::File(FileInput { path: "/etc/sudoers.d/x".into(), content: None, content_base64: None, stat: Some(stat) });
        let exec = Input::Exec(ExecInput { argv: vec!["/bin/true".into()], stdout: String::new(), stderr: String::new(), exit: 0 });
        let reply = super::stat(&[with, file("/etc/a", "x"), exec]);
        assert_eq!(reply.facts["/etc/sudoers.d/x"]["mode"], "0666");
        assert_eq!(reply.facts["/etc/sudoers.d/x"]["world-writable"], true);
        assert_eq!(reply.facts.len(), 1);
        assert_eq!(reply.diagnostics.iter().map(|d| d.path.as_str()).collect::<Vec<_>>(), ["/etc/a", "/bin/true"]);
    }

    #[test]
    fn other_ops_are_not_implemented() {
        let request = Request { protocol: 1, op: "toml".into(), root: "/".into(), now: None, inputs: vec![], facts: Default::default() };
        assert!(op(request).unwrap_err().to_string().contains("toml"));
    }

    fn exec(argv: &str, stdout: &str, exit: i32) -> Input {
        Input::Exec(ExecInput { argv: argv.split(' ').map(str::to_owned).collect(), stdout: stdout.to_owned(), stderr: "denied\n".to_owned(), exit })
    }

    #[test]
    fn ini_lists_every_value_and_joins_continued_lines() {
        let unit = "# head\nTop=1\n[Unit]\nDescription=App\n[Service]\nEnvironment=A=1\nEnvironment=\nEnvironment=B=2 \\\n  C=3\n; note\nbroken\nExecStart=/bin/app\n";
        let reply = ini(&[file("/etc/systemd/system/app.service", unit)]);
        let sections = &reply.facts["/etc/systemd/system/app.service"];
        assert_eq!(sections[""]["Top"], json!(["1"]));
        assert_eq!(sections["Service"]["Environment"], json!(["A=1", "", "B=2 C=3"]));
        assert_eq!(sections["Service"]["ExecStart"], json!(["/bin/app"]));
        assert_eq!(reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(), [Some(11)]);
        let open = ini(&[file("/x", "[S]\nA=1 \\\n")]);
        assert!(open.diagnostics[0].message.contains("past the end"), "{:?}", open.diagnostics);
    }

    #[test]
    fn json_merges_objects_and_names_the_rest() {
        let reply = json(&[file("/etc/docker/daemon.json", r#"{"icc": false, "hosts": ["unix:///run/docker.sock"]}"#), file("/b", r#"{"icc": true, "live-restore": true}"#), file("/c", "[1]"), file("/d", "{\n  \"x\": ,\n}")]);
        assert_eq!((reply.facts["icc"].clone(), reply.facts["live-restore"].clone()), (json!(false), json!(true)));
        assert_eq!(reply.diagnostics.iter().map(|d| (d.path.as_str(), d.line)).collect::<Vec<_>>(), [("/c", None), ("/d", Some(2))]);
        assert!(reply.diagnostics[0].message.contains("list"));
    }

    #[test]
    fn sysctl_takes_sysctl_a_when_it_ran() {
        let files = file("/etc/sysctl.d/10-x.conf", "kernel.kptr_restrict = 0\n");
        let reply = sysctl(&[files.clone(), exec("/usr/sbin/sysctl -a", "kernel.kptr_restrict = 2\nnet.ipv4.conf.eth0/100.rp_filter = 1\nnet.ipv4.ip_local_port_range = 32768\t60999\n", 0)]);
        assert_eq!(reply.facts["source"], "effective");
        let settings = &reply.facts["settings"];
        assert_eq!(settings["kernel"]["kptr_restrict"], 2);
        assert_eq!(settings["net"]["ipv4"]["conf"]["eth0/100"]["rp_filter"], 1);
        assert_eq!(settings["net"]["ipv4"]["ip_local_port_range"], "32768\t60999");
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        let absent = sysctl(&[files.clone(), exec("/usr/sbin/sysctl -a", "", 127)]);
        assert_eq!((absent.facts["source"].as_str(), absent.facts["settings"]["kernel"]["kptr_restrict"].as_i64()), (Some("files"), Some(0)));
        assert!(absent.diagnostics.is_empty());
        let failed = sysctl(&[exec("/usr/sbin/sysctl -a", "", 1)]);
        assert_eq!(failed.facts["source"], "none");
        assert!(failed.diagnostics[0].message.contains("exited 1, read from the files: denied"), "{:?}", failed.diagnostics);
    }

    #[test]
    fn sysctl_files_follow_systemd_order() {
        let reply = sysctl(&[
            file("/etc/sysctl.conf", "kernel.c = conf\n"),
            file("/etc/sysctl.d/50-same.conf", "kernel.a = etc\n"),
            file("/usr/lib/sysctl.d/50-same.conf", "kernel.a = usr\nkernel.b = usr\n"),
            file("/usr/lib/sysctl.d/10-early.conf", "kernel.b = early\nkernel/c = early\n-net/ipv4/conf/eth0.100/rp_filter=2\n; c\nbad line\n"),
            file("/usr/lib/sysctl.d/99-late.conf", "kernel.a.deeper = 1\n"),
            file("/opt/sysctl.d/00-ignored.conf", "kernel.a = ignored\n"),
        ]);
        let settings = &reply.facts["settings"];
        assert_eq!((settings["kernel"]["a"].as_str(), settings["kernel"]["b"].as_str(), settings["kernel"]["c"].as_str()), (Some("etc"), Some("early"), Some("conf")));
        assert_eq!(settings["net"]["ipv4"]["conf"]["eth0/100"]["rp_filter"], 2);
        assert_eq!(reply.diagnostics.iter().map(|d| (d.path.as_str(), d.line)).collect::<Vec<_>>(), [("/usr/lib/sysctl.d/10-early.conf", Some(5)), ("kernel.a.deeper", None)]);
    }

    #[test]
    fn sysctl_keys_swap_only_when_a_slash_comes_first() {
        assert_eq!(sysctl_key("net/ipv4/conf/eth0.100/rp_filter"), "net.ipv4.conf.eth0/100.rp_filter");
        assert_eq!(sysctl_key("net.ipv4.conf.eth0/100.rp_filter"), "net.ipv4.conf.eth0/100.rp_filter");
        assert_eq!(sysctl_key("kernel"), "kernel");
    }

    #[test]
    fn mask_hides_a_password_only() {
        assert_eq!(mask("http://u:p@proxy:3128/"), "http://u:[redacted]@proxy:3128/");
        assert_eq!(mask("http://proxy:3128"), "http://proxy:3128");
    }
}
