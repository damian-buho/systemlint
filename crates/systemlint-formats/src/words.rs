// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `words` family: whitespace records keyed by their first word or by named columns.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, Reply, Result};

use crate::{options, scalar, text};

/// What to keep when a key comes again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Repeat {
    First,
    Last,
    List,
    Append,
}

/// One policy for every key, or one per directive with `*` for the rest.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Policy {
    One(Repeat),
    Each(BTreeMap<String, Repeat>),
}

impl Policy {
    fn of(&self, key: &str) -> Repeat {
        match self {
            Policy::One(repeat) => *repeat,
            Policy::Each(map) => map
                .get(key)
                .or_else(|| map.get("*"))
                .copied()
                .unwrap_or(Repeat::First),
        }
    }
}

/// One column name, or several for nested keys.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Names {
    One(String),
    Many(Vec<String>),
}

/// The typed options of `words`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    separator: Option<String>,
    #[serde(default = "hash")]
    comments: Vec<String>,
    columns: Option<Vec<Option<String>>>,
    rest: Option<String>,
    required: Option<usize>,
    #[serde(default)]
    lists: Vec<String>,
    #[serde(default)]
    toggles: Vec<String>,
    key: Option<Names>,
    repeat: Option<Policy>,
    directives: Option<Vec<String>>,
    #[serde(default)]
    octal: bool,
}

fn hash() -> Vec<String> {
    vec!["#".to_owned()]
}

/// One word of a line, and whether it was quoted.
type Word = (String, bool);

/// Every record of every input: by first word per path, or by named columns, per path or merged by `key`.
pub fn words(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    let mut options: Options = options("words", with)?;
    let columns = options.columns.as_deref();
    let keys = match &options.key {
        None => Vec::new(),
        Some(Names::One(k)) => vec![k.clone()],
        Some(Names::Many(ks)) => ks.clone(),
    };
    let named = |n: &String| columns.is_some_and(|c| c.iter().flatten().any(|c| c == n));
    if let Some(bad) = keys.iter().chain(&options.lists).find(|n| !named(n)) {
        return Err(format!("with names {bad}, which no column does").into());
    }
    if let Some(bad) = options.toggles.iter().find(|n| !options.lists.contains(n)) {
        return Err(format!("with.toggles names {bad}, which is no list column").into());
    }
    if columns.is_none() && (options.rest.is_some() || options.required.is_some()) {
        return Err("with.rest and with.required need with.columns".into());
    }
    let policy = options.repeat.take().unwrap_or(Policy::One(Repeat::First));
    if columns.is_some() {
        match &policy {
            Policy::Each(_) => {
                return Err("with.repeat per key needs directives, not columns".into());
            }
            Policy::One(Repeat::Append) => return Err("with.repeat append needs directives".into()),
            Policy::One(Repeat::List) if keys.is_empty() => {
                return Err("with.repeat needs with.key".into());
            }
            Policy::One(_) => {}
        }
    }
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, content)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let mut per_path: Vec<Value> = Vec::new();
        let mut directives = Map::new();
        for (number, line) in records(content, options.separator.as_deref(), &options.comments) {
            let mut diagnose = |message: String| {
                reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: Some(number),
                    message,
                })
            };
            let words = match line {
                Ok(words) if options.octal => {
                    words.into_iter().map(|(w, q)| (unoctal(&w), q)).collect()
                }
                Ok(words) => words,
                Err(message) => {
                    diagnose(message);
                    continue;
                }
            };
            if options
                .directives
                .as_ref()
                .is_some_and(|d| !d.contains(&words[0].0))
            {
                continue;
            }
            let Some(columns) = columns else {
                let (head, args) = words.split_first().unwrap_or((&words[0], &[]));
                let args: Vec<Value> = args.iter().map(typed).collect();
                merge(
                    &mut directives,
                    &head.0,
                    Value::from(args),
                    policy.of(&head.0),
                );
                continue;
            };
            let mut record = match columned(&words, columns, &options) {
                Ok(record) => record,
                Err(message) => {
                    diagnose(message);
                    continue;
                }
            };
            record.insert("line".to_owned(), Value::from(number));
            if keys.is_empty() {
                per_path.push(Value::Object(record));
                continue;
            }
            let mut at = Vec::new();
            for key in &keys {
                match record.remove(key) {
                    Some(Value::String(s)) => at.push(s),
                    Some(Value::Number(n)) => at.push(n.to_string()),
                    _ => at.clear(),
                }
            }
            if at.len() != keys.len() {
                diagnose(format!("no {} to key the line by", keys.join(" and ")));
                continue;
            }
            record.insert("path".to_owned(), Value::from(path));
            if let Err(message) = place(&mut reply.facts, &at, record, policy.of("")) {
                diagnose(message);
            }
        }
        match columns {
            None => drop(
                reply
                    .facts
                    .insert(path.to_owned(), Value::Object(directives)),
            ),
            Some(_) if keys.is_empty() => {
                drop(reply.facts.insert(path.to_owned(), Value::Array(per_path)))
            }
            Some(_) => {}
        }
    }
    Ok(reply)
}

/// A word with its `\040`-style octal escapes decoded, as fstab(5) and the kernel’s mount tables write them.
fn unoctal(word: &str) -> String {
    let (bytes, mut out, mut i) = (word.as_bytes(), Vec::with_capacity(word.len()), 0);
    while i < bytes.len() {
        let code = bytes.get(i + 1..i + 4).filter(|_| bytes[i] == b'\\');
        match code.and_then(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 8).ok()) {
            Some(byte) => (out.push(byte), i += 4),
            None => (out.push(bytes[i]), i += 1),
        };
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A word as a fact: quoted text stays text, a bare one is typed.
pub(crate) fn typed((word, quoted): &Word) -> Value {
    match quoted {
        true => Value::from(word.as_str()),
        false => scalar(word),
    }
}

/// One directive’s arguments merged into what earlier lines gave it, by `repeat`.
fn merge(map: &mut Map<String, Value>, key: &str, args: Value, repeat: Repeat) {
    match (map.get_mut(key), repeat) {
        (None, Repeat::List) => drop(map.insert(key.to_owned(), Value::Array(vec![args]))),
        (None, _) | (Some(_), Repeat::Last) => drop(map.insert(key.to_owned(), args)),
        (Some(_), Repeat::First) => {}
        (Some(Value::Array(kept)), Repeat::List) => kept.push(args),
        (Some(Value::Array(kept)), Repeat::Append) => {
            kept.extend(args.as_array().into_iter().flatten().cloned())
        }
        (Some(_), _) => {}
    }
}

/// The record of one line’s words under `columns`, `rest` taking the words past them, or why the line does not fit.
fn columned(
    words: &[Word],
    columns: &[Option<String>],
    options: &Options,
) -> std::result::Result<Map<String, Value>, String> {
    let required = options.required.unwrap_or(columns.len());
    if words.len() < required {
        return Err(format!(
            "{} fields where at least {required} are expected",
            words.len()
        ));
    }
    if words.len() > columns.len() && options.rest.is_none() {
        return Err(format!(
            "{} fields where at most {} are expected",
            words.len(),
            columns.len()
        ));
    }
    let mut record = Map::new();
    for (word, name) in words.iter().zip(columns) {
        let Some(name) = name else { continue };
        let value = match options.lists.contains(name) {
            true => {
                let items = word.0.split(',').filter(|w| !w.is_empty());
                let items: Vec<&str> = match options.toggles.contains(name) {
                    true => toggled(items),
                    false => items.collect(),
                };
                Value::from(items.into_iter().map(scalar).collect::<Vec<_>>())
            }
            false => typed(word),
        };
        record.insert(name.clone(), value);
    }
    if let Some(rest) = &options.rest {
        let tail = words.get(columns.len()..).unwrap_or_default();
        record.insert(rest.clone(), tail.iter().map(typed).collect());
    }
    Ok(record)
}

/// The items left once each `noX` cancels an earlier `X` and each `X` an earlier `noX` or `X`, as mount(8) lets the later option win.
fn toggled<'a>(items: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let base = |item: &'a str| item.strip_prefix("no").unwrap_or(item);
    let mut kept: Vec<&str> = Vec::new();
    for item in items {
        kept.retain(|k| base(k) != base(item));
        kept.push(item);
    }
    kept
}

/// Puts `record` at the nested key `at`, keeping the first or last line and the others’ numbers in `shadowed`, or every line under `list`.
fn place(
    facts: &mut BTreeMap<String, Value>,
    at: &[String],
    record: Map<String, Value>,
    repeat: Repeat,
) -> std::result::Result<(), String> {
    let (first, rest) = at.split_first().ok_or("no key")?;
    let mut value = facts.entry(first.clone()).or_insert(Value::Null);
    for key in rest {
        if value.is_null() {
            *value = Value::Object(Map::new());
        }
        value = value
            .as_object_mut()
            .ok_or_else(|| format!("key {key} sits below a list"))?
            .entry(key.clone())
            .or_insert(Value::Null);
    }
    slot(value, record, repeat);
    Ok(())
}

/// Fills one keyed slot by `repeat`.
fn slot(slot: &mut Value, mut record: Map<String, Value>, repeat: Repeat) {
    if repeat != Repeat::List && !record.contains_key("shadowed") {
        record.insert("shadowed".to_owned(), Value::Array(Vec::new()));
    }
    let line = record.get("line").cloned().unwrap_or_default();
    match (slot, repeat) {
        (slot @ Value::Null, Repeat::List) => *slot = Value::Array(vec![Value::Object(record)]),
        (slot @ Value::Null, _) => *slot = Value::Object(record),
        (Value::Array(kept), Repeat::List) => kept.push(Value::Object(record)),
        (Value::Object(kept), Repeat::Last) => {
            let mut shadowed = kept
                .remove("shadowed")
                .unwrap_or_else(|| Value::Array(Vec::new()));
            if let (Value::Array(lines), Some(old)) = (&mut shadowed, kept.get("line")) {
                lines.push(old.clone());
            }
            record.insert("shadowed".to_owned(), shadowed);
            *kept = record;
        }
        (Value::Object(kept), _) => {
            if let Some(Value::Array(lines)) = kept.get_mut("shadowed") {
                lines.push(line);
            }
        }
        (_, _) => {}
    }
}

/// Each record of `content` with its first line number: whitespace words with `\` joining the next line, or fields split on `separator`; comments and blank lines left out.
fn records(
    content: &str,
    separator: Option<&str>,
    comments: &[String],
) -> Vec<(u64, std::result::Result<Vec<Word>, String>)> {
    let mut out = Vec::new();
    let (mut joined, mut start) = (String::new(), 0);
    for (index, raw) in content.lines().enumerate() {
        let number = index as u64 + 1;
        if let Some(separator) = separator.filter(|s| !s.trim().is_empty()) {
            if raw.is_empty()
                || comments
                    .iter()
                    .any(|c| raw.trim_start().starts_with(c.as_str()))
            {
                continue;
            }
            let fields = raw
                .split(separator)
                .map(|f| (f.to_owned(), false))
                .collect();
            out.push((number, Ok(fields)));
            continue;
        }
        if joined.is_empty() {
            start = number;
        }
        if let Some(head) = raw.strip_suffix('\\') {
            joined.push_str(head);
            joined.push(' ');
            continue;
        }
        joined.push_str(raw);
        let line = std::mem::take(&mut joined);
        match split(&line, comments) {
            Ok(words) if words.is_empty() => {}
            words => out.push((start, words)),
        }
    }
    if !joined.is_empty() {
        out.push((start, Err("continues past the end of the input".to_owned())));
    }
    out
}

/// The words of one line: `"…"` with `\"` and `\\` escapes and `[…]` with `\]` are one word each, their delimiters dropped; a word opening with a comment marker ends the line.
pub fn split(line: &str, comments: &[String]) -> std::result::Result<Vec<Word>, String> {
    let mut words = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() || comments.iter().any(|c| rest.starts_with(c.as_str())) {
            return Ok(words);
        }
        let close = match rest.as_bytes()[0] {
            b'"' => Some('"'),
            b'[' => Some(']'),
            _ => None,
        };
        let Some(close) = close else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            words.push((rest[..end].to_owned(), false));
            rest = &rest[end..];
            continue;
        };
        let (mut word, mut chars) = (String::new(), rest[1..].char_indices());
        let end = loop {
            match chars.next() {
                Some((_, '\\')) => match chars.next() {
                    Some((_, c)) if c == close || c == '\\' => word.push(c),
                    Some((_, c)) => (word.push('\\'), word.push(c)).1,
                    None => word.push('\\'),
                },
                Some((at, c)) if c == close => break Some(at + 2),
                Some((_, c)) => word.push(c),
                None => break None,
            }
        };
        let Some(end) = end else {
            return Err(format!("a {close} never closes"));
        };
        words.push((word, true));
        rest = &rest[end..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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

    fn run(inputs: &[Input], with: Value) -> Reply {
        words(inputs, with.as_object().unwrap()).unwrap()
    }

    fn lines(reply: &Reply) -> Vec<Option<u64>> {
        reply.diagnostics.iter().map(|d| d.line).collect()
    }

    #[test]
    fn directives_take_a_repeat_policy_per_word() {
        let reply = run(
            &[file(
                "/etc/resolv.conf",
                "# comment\n; comment\nsearch a.test b.test\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nsearch c.test\noptions ndots:2 trust-ad\nport 53\n",
            )],
            json!({"comments": ["#", ";"], "repeat": {"nameserver": "append", "options": "append", "search": "last"}}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({"/etc/resolv.conf": {
                "search": ["c.test"],
                "nameserver": ["127.0.0.53", "fe80::1%eth0", "192.0.2.1", "192.0.2.2"],
                "options": ["edns0", "ndots:2", "trust-ad"],
                "port": [53],
            }})
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    }

    #[test]
    fn directives_keep_the_first_by_default_or_every_line_as_a_list() {
        let text = "a 1\na 2 3\n";
        let first = run(&[file("/f", text)], json!({}));
        assert_eq!(json!(first.facts), json!({"/f": {"a": [1]}}));
        let all = run(&[file("/f", text)], json!({"repeat": "list"}));
        assert_eq!(json!(all.facts), json!({"/f": {"a": [[1], [2, 3]]}}));
    }

    #[test]
    fn columns_key_records_the_last_winning_with_octal_and_lists() {
        let reply = run(
            &[file(
                "/etc/fstab",
                "# comment\nUUID=1 / ext4 defaults 0 1\ntmpfs /tmp tmpfs nosuid,nodev 0 0\n/dev/sdc /srv/a\\040b xfs\ntmpfs /tmp tmpfs nosuid,,noexec 0 0\n/dev/sdd /x\n/dev/sde /y ext4 defaults 0 0 extra\n",
            )],
            json!({"columns": ["source", "mountpoint", "filesystem", "options", "dump", "pass"], "required": 3, "lists": ["options"], "key": "mountpoint", "repeat": "last", "octal": true}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({
                "/": {"source": "UUID=1", "filesystem": "ext4", "options": ["defaults"], "dump": 0, "pass": 1, "line": 2, "path": "/etc/fstab", "shadowed": []},
                "/tmp": {"source": "tmpfs", "filesystem": "tmpfs", "options": ["nosuid", "noexec"], "dump": 0, "pass": 0, "line": 5, "path": "/etc/fstab", "shadowed": [3]},
                "/srv/a b": {"source": "/dev/sdc", "filesystem": "xfs", "line": 4, "path": "/etc/fstab", "shadowed": []},
            })
        );
        assert_eq!(lines(&reply), [Some(6), Some(7)]);
    }

    #[test]
    fn a_separator_splits_exact_fields_and_a_null_column_is_dropped() {
        let reply = run(
            &[file(
                "/etc/group",
                "root:x:0:\nsudo:$6$secret:27:alice,bob\n#gone:x:1:\nsudo:x:28:\nbad:x:2\n",
            )],
            json!({"separator": ":", "columns": ["name", null, "gid", "members"], "lists": ["members"], "key": "name"}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({
                "root": {"gid": 0, "members": [], "line": 1, "path": "/etc/group", "shadowed": []},
                "sudo": {"gid": 27, "members": ["alice", "bob"], "line": 2, "path": "/etc/group", "shadowed": [4]},
            })
        );
        assert!(!json!(reply.facts).to_string().contains("secret"));
        assert_eq!(lines(&reply), [Some(5)]);
    }

    #[test]
    fn unkeyed_columns_list_records_per_path_with_rest_brackets_and_joined_lines() {
        let reply = run(
            &[file(
                "/etc/pam.d/common-auth",
                "auth\t[success=1  default=ignore]\tpam_unix.so nullok\n-auth optional pam_faillock.so \\\n  authfail # tail\n@include common-account\nauth required pam_exec.so [a b\\] c] \"q 1\" 2\n",
            )],
            json!({"columns": ["type", "control", "module"], "rest": "arguments", "required": 2}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({"/etc/pam.d/common-auth": [
                {"type": "auth", "control": "success=1  default=ignore", "module": "pam_unix.so", "arguments": ["nullok"], "line": 1},
                {"type": "-auth", "control": "optional", "module": "pam_faillock.so", "arguments": ["authfail"], "line": 2},
                {"type": "@include", "control": "common-account", "arguments": [], "line": 4},
                {"type": "auth", "control": "required", "module": "pam_exec.so", "arguments": ["a b] c", "q 1", 2], "line": 5},
            ]})
        );
    }

    #[test]
    fn directives_filter_lines_by_their_first_word_and_commands_count() {
        let showconfig = Input::Exec(ExecInput {
            argv: vec!["/usr/sbin/modprobe".into(), "--showconfig".into()],
            stdout: "blacklist usb_storage\nalias pci:v1 e1000\ninstall cramfs /bin/false\ninstall usb_storage /bin/true --quiet\nblacklist usb_storage\n".into(),
            stderr: String::new(),
            exit: 0,
        });
        let install = run(
            std::slice::from_ref(&showconfig),
            json!({"directives": ["install"], "columns": [null, "module"], "rest": "command", "key": "module"}),
        );
        assert_eq!(
            json!(install.facts),
            json!({
                "cramfs": {"command": ["/bin/false"], "line": 3, "path": "/usr/sbin/modprobe", "shadowed": []},
                "usb_storage": {"command": ["/bin/true", "--quiet"], "line": 4, "path": "/usr/sbin/modprobe", "shadowed": []},
            })
        );
        let blacklist = run(
            &[showconfig],
            json!({"directives": ["blacklist"], "columns": [null, "module"], "key": "module"}),
        );
        assert_eq!(blacklist.facts["usb_storage"]["shadowed"], json!([5]));
    }

    #[test]
    fn nested_keys_and_list_keep_every_record() {
        let reply = run(
            &[file("/f", "options a x=1\noptions a y=2\noptions b z\n")],
            json!({"columns": ["directive", "module"], "rest": "args", "key": ["directive", "module"], "repeat": "list"}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({"options": {
                "a": [{"args": ["x=1"], "line": 1, "path": "/f"}, {"args": ["y=2"], "line": 2, "path": "/f"}],
                "b": [{"args": ["z"], "line": 3, "path": "/f"}],
            }})
        );
    }

    #[test]
    fn an_unclosed_quote_or_continuation_is_named_by_line() {
        let reply = run(&[file("/f", "a \"open\nb [x\nc \\")], json!({}));
        assert_eq!(json!(reply.facts), json!({"/f": {}}));
        assert_eq!(lines(&reply), [Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn options_it_cannot_use_are_refused() {
        for (with, says) in [
            (json!({"pattern": "x"}), "unknown field"),
            (json!({"key": "a"}), "no column"),
            (json!({"columns": ["a"], "lists": ["b"]}), "no column"),
            (
                json!({"columns": ["a"], "toggles": ["a"]}),
                "no list column",
            ),
            (json!({"rest": "r"}), "need with.columns"),
            (
                json!({"columns": ["a"], "repeat": {"a": "last"}}),
                "per key",
            ),
            (
                json!({"columns": ["a"], "key": "a", "repeat": "append"}),
                "append",
            ),
            (json!({"columns": ["a"], "repeat": "list"}), "with.key"),
            (json!({"repeat": "most"}), "words with"),
        ] {
            let error = words(&[], with.as_object().unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains(says), "{with}: {error}");
        }
    }

    #[test]
    fn toggles_keep_the_later_of_an_option_and_its_no_form() {
        let reply = run(
            &[file(
                "/etc/fstab",
                "tmpfs /tmp tmpfs suid,nosuid,nodev,dev,noexec,noexec,user,nouser,notail\n",
            )],
            json!({"columns": ["source", "mountpoint", "filesystem", "options"], "required": 3, "lists": ["options"], "toggles": ["options"], "key": "mountpoint"}),
        );
        assert_eq!(
            reply.facts["/tmp"]["options"],
            json!(["nosuid", "dev", "noexec", "nouser", "notail"])
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
