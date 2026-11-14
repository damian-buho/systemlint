// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Kernel audit rules: the `rules.d` files augenrules loads, or the set `auditctl -l` lists.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use systemlint_protocol::{Diagnostic, Input, Reply};

/// The auditctl options that set one value, and the fact each becomes.
const VALUED: [(&str, &str); 5] = [
    ("-e", "enabled"),
    ("-b", "backlog"),
    ("-f", "failure"),
    ("-r", "rate"),
    ("--backlog_wait_time", "backlog-wait-time"),
];

/// The auditctl options that take no value, and the fact each sets true.
const FLAGS: [(&str, &str); 3] = [
    ("-c", "continue-on-error"),
    ("-i", "ignore-errors"),
    ("--loginuid-immutable", "loginuid-immutable"),
];

/// The lists a `-a` rule may name.
const LISTS: [&str; 6] = ["task", "exit", "user", "exclude", "filesystem", "io_uring"];

/// The `arch=` names of a 64-bit syscall table.
const B64: [&str; 7] = [
    "b64", "x86_64", "aarch64", "ppc64", "ppc64le", "s390x", "riscv64",
];

/// The `arch=` names of a 32-bit syscall table.
const B32: [&str; 9] = [
    "b32", "i386", "i486", "i586", "i686", "arm", "armeb", "ppc", "s390",
];

/// The rule set as the kernel would hold it after every line ran.
#[derive(Default)]
struct Rules {
    watches: BTreeMap<String, Vec<Value>>,
    syscalls: BTreeMap<String, Vec<Value>>,
    lists: BTreeMap<String, Vec<Value>>,
    control: Map<String, Value>,
}

impl Rules {
    /// Files `entry` under `key` of `map`, first when the rule was `-A`.
    fn add(map: &mut BTreeMap<String, Vec<Value>>, key: &str, entry: Value, first: bool) {
        let entries = map.entry(key.to_owned()).or_default();
        if first {
            entries.insert(0, entry);
        } else {
            entries.push(entry);
        }
    }
}

/// The watches, syscall rules, other lists and control settings of auditctl rule lines: the `rules.d` files in augenrules’ order, or `auditctl -l` when it exited 0.
pub fn audit_rules(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut sources: Vec<(String, &str)> = Vec::new();
    for input in inputs {
        match input {
            Input::Exec(e) if e.exit == 0 => sources.push((e.argv.join(" "), &e.stdout)),
            Input::Exec(e) if e.exit == 127 => return reply,
            Input::Exec(e) => {
                reply.diagnostics.push(Diagnostic {
                    path: e.argv.join(" "),
                    line: None,
                    message: format!("exited {}: {}", e.exit, e.stderr.trim()),
                });
                return reply;
            }
            other => {
                if let Some((path, content)) = crate::text(other, &mut reply.diagnostics) {
                    sources.push((path.to_owned(), content));
                }
            }
        }
    }
    sources.sort_by_cached_key(|(path, _)| version_key(path.rsplit('/').next().unwrap_or(path)));
    let mut rules = Rules::default();
    for (path, content) in &sources {
        for (index, raw) in content.lines().enumerate() {
            let words: Vec<&str> = raw.split_whitespace().collect();
            if words.first().is_none_or(|w| w.starts_with('#')) || raw.trim() == "No rules" {
                continue;
            }
            if let Err(message) = line(&mut rules, &words, format!("{path}:{}", index + 1)) {
                reply.diagnostics.push(Diagnostic {
                    path: path.clone(),
                    line: Some(index as u64 + 1),
                    message,
                });
            }
        }
    }
    reply.facts.insert("watches".into(), json!(rules.watches));
    reply.facts.insert("syscalls".into(), json!(rules.syscalls));
    reply.facts.insert("lists".into(), json!(rules.lists));
    reply
        .facts
        .insert("control".into(), Value::Object(rules.control));
    reply
}

/// Applies one rule line to `rules`, or says why it was ignored.
fn line(rules: &mut Rules, words: &[&str], source: String) -> Result<(), String> {
    let (option, rest) = (words[0], &words[1..]);
    if let Some((_, name)) = FLAGS.iter().find(|(o, _)| *o == option) {
        rules.control.insert((*name).into(), Value::Bool(true));
        return Ok(());
    }
    if let Some((_, name)) = VALUED.iter().find(|(o, _)| *o == option) {
        let value = rest
            .first()
            .ok_or(format!("{option} without its value, ignored"))?;
        let value = value
            .parse::<u64>()
            .map_or_else(|_| json!(value), Value::from);
        rules.control.insert((*name).into(), value);
        return Ok(());
    }
    match option {
        "-D" if rest.is_empty() => {
            (rules.watches, rules.syscalls, rules.lists) = Default::default();
            Ok(())
        }
        "-w" => watch(rules, rest, source),
        "-a" | "-A" => rule(rules, option == "-A", rest, source),
        other => Err(format!(
            "{other:?} is not an auditctl rule this op applies, ignored"
        )),
    }
}

/// Applies `-w PATH [-p PERMS] [-k KEY]…` as a watch on every access `-p` names.
fn watch(rules: &mut Rules, rest: &[&str], source: String) -> Result<(), String> {
    let path = rest.first().ok_or("-w without its path, ignored")?;
    let (mut perms, mut keys) = ("rwxa".to_owned(), Vec::new());
    for pair in rest[1..].chunks(2) {
        match pair {
            ["-p", value] => perms = permissions(value)?,
            ["-k", value] => keys.push(unquoted(value)),
            _ => return Err(format!("{:?} after -w is not -p or -k, ignored", pair[0])),
        }
    }
    let entry =
        json!({"action": "always", "perms": perms, "filters": [], "keys": keys, "source": source});
    Rules::add(&mut rules.watches, trimmed(path), entry, false);
    Ok(())
}

/// Applies `-a LIST,ACTION` with its `-S`, `-F`, `-C` and `-k`: a path rule over every syscall as a watch, an `exit` rule under each syscall, any other under its list.
fn rule(rules: &mut Rules, first: bool, rest: &[&str], source: String) -> Result<(), String> {
    let spec = rest
        .first()
        .ok_or("-a without its list and action, ignored")?;
    let (list, action) = match spec.split_once(',') {
        Some((a, l)) if ["always", "never"].contains(&a) => (l, a),
        Some((l, a)) if ["always", "never"].contains(&a) => (l, a),
        _ => return Err(format!("{spec:?} is not a list and an action, ignored")),
    };
    if !LISTS.contains(&list) {
        return Err(format!("{list:?} is not an audit list, ignored"));
    }
    let (mut syscalls, mut filters, mut keys) = (Vec::new(), Vec::new(), Vec::new());
    let (mut arch, mut path, mut perms): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    for pair in rest[1..].chunks(2) {
        match pair {
            ["-S", value] => syscalls.extend(value.split(',').map(str::to_owned)),
            ["-C", value] => filters.push((*value).to_owned()),
            ["-k", value] => keys.push(unquoted(value)),
            ["-F", value] => {
                let (field, op, value) = field(value)?;
                match (field, op) {
                    ("key", "=") => keys.push(unquoted(value)),
                    ("arch", "=") => arch = Some(architecture(value)),
                    ("path" | "dir", "=") if path.is_none() => {
                        path = Some(format!("{field}={}", trimmed(value)))
                    }
                    ("perm", "=") => perms = Some(permissions(value)?),
                    _ => filters.push(format!("{field}{op}{}", unset(field, value))),
                }
            }
            _ => return Err(format!("{:?} is not -S, -F, -C or -k, ignored", pair[0])),
        }
    }
    let every = syscalls.is_empty() || syscalls == ["all"];
    if let (true, "exit", Some(target)) = (every, list, &path) {
        let watched = target
            .split_once('=')
            .map_or(target.as_str(), |(_, p)| p)
            .to_owned();
        filters.extend(arch.map(|a| format!("arch={a}")));
        let perms = perms.unwrap_or_else(|| "rwxa".to_owned());
        let entry = json!({"action": action, "perms": perms, "filters": filters, "keys": keys, "source": source});
        Rules::add(&mut rules.watches, &watched, entry, first);
        return Ok(());
    }
    filters.extend(path);
    filters.extend(perms.map(|p| format!("perm={p}")));
    if list != "exit" {
        let entry = json!({"action": action, "syscalls": syscalls, "filters": filters, "keys": keys, "source": source});
        Rules::add(&mut rules.lists, list, entry, first);
        return Ok(());
    }
    let entry =
        json!({"action": action, "arch": arch, "filters": filters, "keys": keys, "source": source});
    for name in if syscalls.is_empty() {
        vec!["all".to_owned()]
    } else {
        syscalls
    } {
        Rules::add(&mut rules.syscalls, &name, entry.clone(), first);
    }
    Ok(())
}

/// A `-F` filter split into field, operator and value.
fn field(text: &str) -> Result<(&str, &str, &str), String> {
    let invalid = || format!("{text:?} is not a field, an operator and a value, ignored");
    let start = text.find(['=', '!', '<', '>', '&']).ok_or_else(invalid)?;
    let end = start
        + text[start..]
            .find(|c: char| !"=!<>&".contains(c))
            .ok_or_else(invalid)?;
    match (&text[..start], &text[start..end]) {
        ("", _) => Err(invalid()),
        (field, op @ ("=" | "!=" | "<" | ">" | "<=" | ">=" | "&" | "&=")) => {
            Ok((field, op, &text[end..]))
        }
        _ => Err(invalid()),
    }
}

/// An id field’s `-1` or `4294967295` as `unset`, the spelling auditctl accepts for both.
fn unset<'a>(field: &str, value: &'a str) -> &'a str {
    let id = field.ends_with("uid") || field.ends_with("gid");
    if id && ["-1", "4294967295"].contains(&value) {
        "unset"
    } else {
        value
    }
}

/// `-p` or `perm=` letters in `rwxa` order, or why they are not permissions.
fn permissions(value: &str) -> Result<String, String> {
    if value.is_empty() || !value.chars().all(|c| "rwxa".contains(c)) {
        return Err(format!("{value:?} is not a set of r, w, x and a, ignored"));
    }
    Ok("rwxa".chars().filter(|c| value.contains(*c)).collect())
}

/// An `arch=` value as `b64` or `b32` when it names one of those tables.
fn architecture(value: &str) -> String {
    match value {
        v if B64.contains(&v) => "b64".to_owned(),
        v if B32.contains(&v) => "b32".to_owned(),
        v => v.to_owned(),
    }
}

/// A key without the double quotes a hand-written rule may carry.
fn unquoted(value: &str) -> String {
    value.trim_matches('"').to_owned()
}

/// A watched path without a trailing `/`, as auditctl stores a directory.
fn trimmed(path: &str) -> &str {
    match path.trim_end_matches('/') {
        "" => "/",
        p => p,
    }
}

/// A file name split into text and number runs, which compare as `ls -v` orders augenrules’ files.
fn version_key(name: &str) -> Vec<(String, u64)> {
    let mut key = Vec::new();
    let mut rest = name;
    while !rest.is_empty() {
        let (text, tail) = rest.split_at(
            rest.find(|c: char| c.is_ascii_digit())
                .unwrap_or(rest.len()),
        );
        let (digits, tail) = tail.split_at(
            tail.find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len()),
        );
        key.push((text.to_owned(), digits.parse().unwrap_or(u64::MAX)));
        rest = tail;
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::{ExecInput, FileInput};

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

    fn exec(stdout: &str, stderr: &str, exit: i32) -> Input {
        Input::Exec(ExecInput {
            argv: vec!["/usr/sbin/auditctl".into(), "-l".into()],
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            exit,
        })
    }

    #[test]
    fn audit_rules_reads_rules_d_in_augenrules_order() {
        let reply = audit_rules(&[
            file(
                "/etc/audit/rules.d/10-base.rules",
                "-w /etc/passwd -p wa -k identity\n-e 2\n",
            ),
            file(
                "/etc/audit/rules.d/9-early.rules",
                "## comment\n-D\n-b 8192\n--backlog_wait_time 60000\n-f 1\n-w /etc/shadow -k identity\n",
            ),
            file(
                "/etc/audit/rules.d/50-scope.rules",
                "-w /etc/sudoers.d/ -p aw -k scope\n-a always,exit -F arch=x86_64 -S adjtimex,settimeofday -k time-change\n-a exit,always -F arch=i386 -S adjtimex -F key=time-change\n-a always,exit -F arch=b64 -C euid!=uid -F auid!=-1 -S execve -k user_emulation\n-A never,exit -F arch=b64 -S adjtimex -F auid=4294967295\n-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n-a always,exit -F arch=b64 -S open -F exit=-EACCES -F path=/etc/x\n-a always,exclude -F msgtype=CWD\n",
            ),
        ]);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        let facts = Value::Object(reply.facts.into_iter().collect());
        assert_eq!(
            facts["control"],
            json!({"backlog": 8192, "backlog-wait-time": 60000, "failure": 1, "enabled": 2})
        );
        let scope = "/etc/audit/rules.d/50-scope.rules";
        assert_eq!(
            facts["watches"],
            json!({
                "/etc/passwd": [{"action": "always", "perms": "wa", "filters": [], "keys": ["identity"], "source": "/etc/audit/rules.d/10-base.rules:1"}],
                "/etc/shadow": [{"action": "always", "perms": "rwxa", "filters": [], "keys": ["identity"], "source": "/etc/audit/rules.d/9-early.rules:6"}],
                "/etc/sudoers.d": [{"action": "always", "perms": "wa", "filters": [], "keys": ["scope"], "source": format!("{scope}:1")}],
                "/usr/bin/sudo": [{"action": "always", "perms": "x", "filters": ["auid>=1000", "auid!=unset"], "keys": ["privileged"], "source": format!("{scope}:6")}]})
        );
        assert_eq!(
            facts["syscalls"]["adjtimex"],
            json!([
                {"action": "never", "arch": "b64", "filters": ["auid=unset"], "keys": [], "source": format!("{scope}:5")},
                {"action": "always", "arch": "b64", "filters": [], "keys": ["time-change"], "source": format!("{scope}:2")},
                {"action": "always", "arch": "b32", "filters": [], "keys": ["time-change"], "source": format!("{scope}:3")}])
        );
        assert_eq!(
            facts["syscalls"]["execve"][0]["filters"],
            json!(["euid!=uid", "auid!=unset"])
        );
        assert_eq!(
            facts["syscalls"]["open"][0]["filters"],
            json!(["exit=-EACCES", "path=/etc/x"])
        );
        assert_eq!(
            facts["lists"]["exclude"][0]["filters"],
            json!(["msgtype=CWD"])
        );
    }

    #[test]
    fn audit_rules_clears_on_minus_d_and_names_each_ignored_line() {
        let reply = audit_rules(&[file(
            "/etc/audit/rules.d/a.rules",
            "-w /etc/group -p wa\n-D\n-w /etc/hosts -p wq\n-a always,entry -S open\n-a sometimes,exit\n-F key=x\n-a always,exit -F =1\n-a always,exit -F auid~1\n-w\n-e\n-w /etc/issue -p r\n",
        )]);
        let lines: Vec<_> = reply.diagnostics.iter().map(|d| d.line).collect();
        assert_eq!(lines, [3, 4, 5, 6, 7, 8, 9, 10].map(Some));
        let facts = Value::Object(reply.facts.into_iter().collect());
        assert_eq!(
            facts["watches"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["/etc/issue"]
        );
        assert_eq!(facts["watches"]["/etc/issue"][0]["perms"], "r");
    }

    #[test]
    fn audit_rules_reads_auditctl_l_when_it_exited_0() {
        let listed = audit_rules(&[exec(
            "-w /etc/sudoers -p wa -k scope\n-a always,exit -F arch=b64 -S chmod,fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod\n",
            "",
            0,
        )]);
        let facts = Value::Object(listed.facts.into_iter().collect());
        assert_eq!(
            facts["watches"]["/etc/sudoers"][0]["source"],
            "/usr/sbin/auditctl -l:1"
        );
        assert_eq!(facts["syscalls"]["fchmod"][0]["keys"], json!(["perm_mod"]));
        let empty = audit_rules(&[exec("No rules\n", "", 0)]);
        assert_eq!(empty.facts["watches"], json!({}));
        let absent = audit_rules(&[exec("", "", 127)]);
        assert!(absent.facts.is_empty() && absent.diagnostics.is_empty());
        let refused = audit_rules(&[exec("", "You must be root to run this program.\n", 4)]);
        assert!(refused.facts.is_empty());
        assert_eq!(
            refused.diagnostics[0].message,
            "exited 4: You must be root to run this program."
        );
    }

    #[test]
    fn version_key_orders_numbers_by_value() {
        assert!(version_key("9-a.rules") < version_key("10-a.rules"));
        assert!(version_key("10-a.rules") < version_key("10-b.rules"));
        assert!(version_key("a.rules") > version_key("99-z.rules"));
    }
}
