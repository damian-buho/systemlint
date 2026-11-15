// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `kv` family: one key and its value per line.

use serde::Deserialize;
use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, Reply, Result};

use crate::{nest, options, scalar, text, unquote};

/// What to keep when a key comes again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Repeat {
    #[default]
    First,
    Last,
    List,
}

/// The typed options of `kv`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default = "equals")]
    separator: String,
    #[serde(default = "hash")]
    comments: Vec<String>,
    #[serde(default)]
    repeat: Repeat,
    nest: Option<char>,
    swap: Option<char>,
    #[serde(default)]
    strip: String,
    section: Option<String>,
    records: Option<char>,
    negate: Option<String>,
}

fn equals() -> String {
    "=".to_owned()
}

fn hash() -> Vec<String> {
    vec!["#".to_owned()]
}

/// The word that splits a line at its first run of blanks.
const WHITESPACE: &str = "whitespace";

/// Every key of every input in one object, in input order, by `repeat`: a quoted value unquoted as a shell would and kept as text, a bare one typed.
pub fn kv(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    let options: Options = options("kv", with)?;
    if options.separator.is_empty() {
        return Err("kv with.separator is empty".into());
    }
    if options.swap.is_some() && options.nest.is_none() {
        return Err("kv with.swap needs with.nest".into());
    }
    if options.negate.as_deref() == Some("") || options.section.as_deref() == Some("") {
        return Err("kv with.negate and with.section must not be empty".into());
    }
    let mut reply = Reply::default();
    let mut flat: Vec<(String, Value)> = Vec::new();
    for input in inputs {
        let Some((path, content)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let mut inside = options.section.is_none();
        for (index, raw) in content.lines().enumerate() {
            let mut diagnose = |message: String| {
                reply.diagnostics.push(Diagnostic {
                    path: path.to_owned(),
                    line: Some(index as u64 + 1),
                    message,
                })
            };
            if let Some(header) = &options.section {
                if raw.starts_with(header.as_str()) {
                    inside = true;
                    continue;
                }
                if raw.trim().is_empty() || !raw.starts_with(char::is_whitespace) {
                    inside = false;
                }
            }
            let line = raw.trim();
            if !inside
                || line.is_empty()
                || options
                    .comments
                    .iter()
                    .any(|c| line.starts_with(c.as_str()))
            {
                continue;
            }
            let records = match options.records {
                Some(separator) => split_records(line, separator),
                None => vec![line.to_owned()],
            };
            for record in records.iter().map(|r| r.trim()).filter(|r| !r.is_empty()) {
                let split = match options.separator.as_str() {
                    WHITESPACE => Some(
                        record
                            .split_once(char::is_whitespace)
                            .unwrap_or((record, "")),
                    ),
                    separator => record.split_once(separator),
                };
                let Some((key, value)) = split else {
                    match options.negate.as_deref() {
                        Some(not) => flat.push(match record.strip_prefix(not) {
                            Some(key) => (key.trim().to_owned(), Value::Bool(false)),
                            None => (record.to_owned(), Value::Bool(true)),
                        }),
                        None => diagnose(format!("no {} in {record:?}", options.separator)),
                    }
                    continue;
                };
                let key = key.trim().trim_start_matches(|c| options.strip.contains(c));
                if key.is_empty() {
                    diagnose("a value with no key".to_owned());
                    continue;
                }
                let value = value.trim();
                let typed = match unquote(value) {
                    Ok(text) if value.starts_with(['"', '\'']) => Value::from(text),
                    Ok(_) if options.records.is_some() => scalar(&unescape(value)),
                    Ok(_) => scalar(value),
                    Err(message) => {
                        diagnose(format!("{key}: {message}"));
                        continue;
                    }
                };
                flat.push((swapped(key, options.nest, options.swap), typed));
            }
        }
    }
    let mut kept = Map::new();
    for (key, value) in flat {
        match (kept.get_mut(&key), options.repeat) {
            (Some(_), Repeat::First) => {}
            (Some(Value::Array(all)), Repeat::List) => all.push(value),
            (None, Repeat::List) => drop(kept.insert(key, Value::Array(vec![value]))),
            _ => drop(kept.insert(key, value)),
        }
    }
    let Some(separator) = options.nest else {
        reply.facts.extend(kept);
        return Ok(reply);
    };
    let mut nested = Map::new();
    for (key, value) in kept {
        if let Err(message) = nest(&mut nested, &key, separator, value) {
            reply.diagnostics.push(Diagnostic {
                path: key,
                line: None,
                message,
            });
        }
    }
    reply.facts.extend(nested);
    Ok(reply)
}

/// `line` cut at each `separator` outside `"…"` and not escaped by a backslash, the escapes kept.
fn split_records(line: &str, separator: char) -> Vec<String> {
    let (mut records, mut current, mut quoted, mut chars) =
        (Vec::new(), String::new(), false, line.chars());
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push(c);
                current.extend(chars.next());
            }
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            c if c == separator && !quoted => records.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    records.push(current);
    records
}

/// A bare value with each backslash escape replaced by the character it escapes.
fn unescape(value: &str) -> String {
    let (mut out, mut chars) = (String::with_capacity(value.len()), value.chars());
    while let Some(c) = chars.next() {
        out.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }
    out
}

/// `key` with `swap` and `nest` exchanged when `swap` comes first, as sysctl.d(5) writes `net/ipv4/conf/eth0.100/rp_filter`.
fn swapped(key: &str, nest: Option<char>, swap: Option<char>) -> String {
    let (Some(nest), Some(swap)) = (nest, swap) else {
        return key.to_owned();
    };
    match key.chars().find(|c| *c == nest || *c == swap) {
        Some(first) if first == swap => key
            .chars()
            .map(|c| match c {
                c if c == swap => nest,
                c if c == nest => swap,
                c => c,
            })
            .collect(),
        _ => key.to_owned(),
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
        kv(inputs, with.as_object().unwrap()).unwrap()
    }

    #[test]
    fn the_first_input_holding_a_key_wins_and_quotes_keep_text() {
        let reply = run(
            &[
                file(
                    "/etc/os-release",
                    "# c\nID=ubuntu\nVERSION_ID=\"26.04\"\nN=7\nQ=\"7\"\nZ=0644\nE=\n",
                ),
                file("/usr/lib/os-release", "ID=debian\nX='y'\n"),
            ],
            json!({}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({"ID": "ubuntu", "VERSION_ID": "26.04", "N": 7, "Q": "7", "Z": "0644", "E": "", "X": "y"})
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    }

    #[test]
    fn whitespace_splits_at_the_first_blanks_and_the_last_line_wins() {
        let reply = run(
            &[file(
                "/etc/login.defs",
                "UMASK\t\t022\nUMASK 027\nPASS_MAX_DAYS 99999\nENV_PATH PATH=/bin\nLOG_OK_LOGINS\nTTYGROUP \"tty\"\n",
            )],
            json!({"separator": "whitespace", "repeat": "last"}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({"UMASK": "027", "PASS_MAX_DAYS": 99999, "ENV_PATH": "PATH=/bin", "LOG_OK_LOGINS": "", "TTYGROUP": "tty"})
        );
    }

    #[test]
    fn nest_swap_and_strip_read_sysctl_files_and_its_output() {
        let reply = run(
            &[
                file(
                    "/usr/lib/sysctl.d/50-default.conf",
                    "; c\nnet.ipv4.ip_forward = 0\n-net/ipv4/conf/eth0.100/rp_filter=1\nkernel.printk = 4\t4\t1\t7\n",
                ),
                Input::Exec(ExecInput {
                    argv: vec!["/usr/sbin/sysctl".into(), "-a".into()],
                    stdout: "net.ipv4.ip_forward = 1\nfs.suid_dumpable = 0\n".into(),
                    stderr: String::new(),
                    exit: 0,
                }),
            ],
            json!({"comments": ["#", ";"], "repeat": "last", "nest": ".", "swap": "/", "strip": "-"}),
        );
        assert_eq!(
            json!(reply.facts),
            json!({
                "net": {"ipv4": {"ip_forward": 1, "conf": {"eth0/100": {"rp_filter": 1}}}},
                "kernel": {"printk": "4\t4\t1\t7"},
                "fs": {"suid_dumpable": 0},
            })
        );
    }

    #[test]
    fn list_keeps_every_value_and_a_crossing_key_is_named() {
        let reply = run(
            &[file("/f", "a.b=1\na.b=2\na.b.c=3\n")],
            json!({"repeat": "list", "nest": "."}),
        );
        assert_eq!(json!(reply.facts), json!({"a": {"b": [1, 2]}}));
        assert_eq!(reply.diagnostics.len(), 1, "{:?}", reply.diagnostics);
    }

    #[test]
    fn a_line_without_its_separator_or_key_or_closing_quote_is_named_by_line() {
        let reply = run(&[file("/f", "a\n=1\nb=\"x\nc=1\n")], json!({}));
        assert_eq!(json!(reply.facts), json!({"c": 1}));
        let lines: Vec<_> = reply.diagnostics.iter().map(|d| d.line).collect();
        assert_eq!(lines, [Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn section_records_and_negate_read_a_sudo_defaults_list() {
        let out = "Matching Defaults entries for bob on h:\n    env_reset, secure_path=/usr/sbin\\:/bin, use_pty, env_keep+=\"LANG LC_*\", logfile=\"/var/log/a, b\", !use_pty, ! authenticate, timestamp_timeout=-1, a\\,b\n\nRunas and Command-specific defaults for bob:\n    Defaults>postgres !use_pty\n\nUser bob may run the following commands on h:\n    (root) /usr/bin/id\n";
        let reply = run(
            &[file("sudo", out)],
            json!({"section": "Matching Defaults entries", "records": ",", "negate": "!", "repeat": "last"}),
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(
            json!(reply.facts),
            json!({
                "env_reset": true, "secure_path": "/usr/sbin:/bin", "use_pty": false,
                "env_keep+": "LANG LC_*", "logfile": "/var/log/a, b", "authenticate": false,
                "timestamp_timeout": -1, "a\\,b": true,
            }),
            "the last of a key wins, a quoted or escaped comma splits nothing, other blocks are not read"
        );
        let none = run(
            &[file(
                "sudo",
                "User daemon is not allowed to run sudo on h.\n",
            )],
            json!({"section": "Matching Defaults entries"}),
        );
        assert_eq!(json!(none.facts), json!({}));
        assert!(none.diagnostics.is_empty(), "{:?}", none.diagnostics);
    }

    #[test]
    fn options_it_cannot_use_are_refused() {
        for (with, says) in [
            (json!({"pattern": "x"}), "unknown field"),
            (json!({"separator": ""}), "empty"),
            (json!({"swap": "/"}), "needs with.nest"),
            (json!({"repeat": "append"}), "kv with"),
            (json!({"nest": ".."}), "kv with"),
            (json!({"negate": ""}), "must not be empty"),
            (json!({"section": ""}), "must not be empty"),
            (json!({"records": ",,"}), "kv with"),
        ] {
            let error = kv(&[], with.as_object().unwrap()).unwrap_err().to_string();
            assert!(error.contains(says), "{with}: {error}");
        }
    }
}
