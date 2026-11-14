// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `options` family: getopt lines, as `auditctl -l` and `iptables-save` print them.

use serde::Deserialize;
use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, Reply, Result};

use crate::words::{split, typed};
use crate::{options as typed_options, text};

/// The typed options of `options`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    split: Vec<String>,
    #[serde(default = "hash")]
    comments: Vec<String>,
}

fn hash() -> Vec<String> {
    vec!["#".to_owned()]
}

/// Whether `word` is a flag: `-x` or `--name`, never a negative number or a bare `-`/`--`.
fn is_flag(word: &str) -> bool {
    let name = word
        .strip_prefix("--")
        .or_else(|| word.strip_prefix('-'))
        .unwrap_or("");
    word.starts_with('-') && name.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// Every line of every input as one record per path in order: each flag, `!`-negated as `! -x`, holds the list of its values, words before any flag sit in `args`.
pub fn flags(inputs: &[Input], with: &Map<String, Value>) -> Result<Reply> {
    let options: Options = typed_options("options", with)?;
    if let Some(bad) = options.split.iter().find(|f| !is_flag(f)) {
        return Err(format!("with.split names {bad}, which is no flag").into());
    }
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, content)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let mut records = Vec::new();
        for (index, line) in content.lines().enumerate() {
            let words = match split(line, &options.comments) {
                Ok(words) if words.is_empty() => continue,
                Ok(words) => words,
                Err(message) => {
                    reply.diagnostics.push(Diagnostic {
                        path: path.to_owned(),
                        line: Some(index as u64 + 1),
                        message,
                    });
                    continue;
                }
            };
            let mut record = record(&words, &options.split);
            record.insert("line".to_owned(), Value::from(index + 1));
            records.push(Value::Object(record));
        }
        reply.facts.insert(path.to_owned(), Value::Array(records));
    }
    Ok(reply)
}

/// One line’s words as a record: a flag takes the next word unless it is a flag, `--name=value` its own value.
fn record(words: &[(String, bool)], split_on_comma: &[String]) -> Map<String, Value> {
    let mut record = Map::from_iter([("args".to_owned(), Value::Array(Vec::new()))]);
    let (mut index, mut negated) = (0, false);
    while let Some((word, quoted)) = words.get(index) {
        index += 1;
        if !quoted && word == "!" && words.get(index).is_some_and(|(w, q)| !q && is_flag(w)) {
            negated = true;
            continue;
        }
        if *quoted || !is_flag(word) {
            push(&mut record, "args", typed(&(word.clone(), *quoted)));
            continue;
        }
        let (name, inline) = match word.split_once('=').filter(|_| word.starts_with("--")) {
            Some((name, value)) => (name, Some((value.to_owned(), false))),
            None => (word.as_str(), None),
        };
        let key = match std::mem::take(&mut negated) {
            true => format!("! {name}"),
            false => name.to_owned(),
        };
        let slot = record
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()));
        let value = inline.or_else(|| {
            let next = words.get(index).filter(|(w, q)| *q || !is_flag(w))?;
            index += 1;
            Some(next.clone())
        });
        let Some((value, quoted)) = value else {
            continue;
        };
        let Value::Array(values) = slot else { continue };
        match !quoted && split_on_comma.iter().any(|f| f == name) {
            true => values.extend(
                value
                    .split(',')
                    .filter(|v| !v.is_empty())
                    .map(|v| typed(&(v.to_owned(), false))),
            ),
            false => values.push(typed(&(value, quoted))),
        }
    }
    record
}

/// Appends `value` to the list at `key`.
fn push(record: &mut Map<String, Value>, key: &str, value: Value) {
    if let Some(Value::Array(values)) = record.get_mut(key) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use systemlint_protocol::{ExecInput, FileInput};

    fn run(stdout: &str, with: Value) -> Reply {
        let exec = Input::Exec(ExecInput {
            argv: vec!["/usr/sbin/auditctl".into(), "-l".into()],
            stdout: stdout.into(),
            stderr: String::new(),
            exit: 0,
        });
        flags(&[exec], with.as_object().unwrap()).unwrap()
    }

    #[test]
    fn audit_lines_become_flags_with_repeats_and_comma_lists() {
        let reply = run(
            "## stock\n-D\n-w /etc/sudoers -p wa -k scope\n-a always,exit -F arch=b64 -S execveat,execve -F auid!=-1 -F key=x\n-e 2 # locked\n",
            json!({"split": ["-a", "-S"]}),
        );
        assert_eq!(
            reply.facts["/usr/sbin/auditctl"],
            json!([
                {"args": [], "-D": [], "line": 2},
                {"args": [], "-w": ["/etc/sudoers"], "-p": ["wa"], "-k": ["scope"], "line": 3},
                {"args": [], "-a": ["always", "exit"], "-F": ["arch=b64", "auid!=-1", "key=x"], "-S": ["execveat", "execve"], "line": 4},
                {"args": [], "-e": [2], "line": 5},
            ])
        );
    }

    #[test]
    fn iptables_lines_keep_negation_long_values_quotes_and_positionals() {
        let reply = run(
            "*filter\n:INPUT DROP [0:0]\n-A INPUT ! -s 10.0.0.0/8 -p tcp --dport=22 --syn -m comment --comment \"-x y\" -j ACCEPT\nCOMMIT\n",
            json!({}),
        );
        assert_eq!(
            reply.facts["/usr/sbin/auditctl"],
            json!([
                {"args": ["*filter"], "line": 1},
                {"args": [":INPUT", "DROP", "0:0"], "line": 2},
                {"args": [], "-A": ["INPUT"], "! -s": ["10.0.0.0/8"], "-p": ["tcp"], "--dport": [22], "--syn": [], "-m": ["comment"], "--comment": ["-x y"], "-j": ["ACCEPT"], "line": 3},
                {"args": ["COMMIT"], "line": 4},
            ])
        );
    }

    #[test]
    fn a_negative_number_is_a_value_and_a_lone_bang_an_argument() {
        let reply = run("-x -1 ! y\n", json!({}));
        assert_eq!(
            reply.facts["/usr/sbin/auditctl"],
            json!([{"args": ["!", "y"], "-x": [-1], "line": 1}])
        );
    }

    #[test]
    fn a_file_keys_by_path_and_an_unclosed_quote_is_named_by_line() {
        let file = Input::File(FileInput {
            path: "/etc/audit/rules.d/a.rules".into(),
            content: Some("-w \"/x\n-e 1\n".into()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        });
        let reply = flags(&[file], &Map::new()).unwrap();
        assert_eq!(
            reply.facts["/etc/audit/rules.d/a.rules"],
            json!([{"args": [], "-e": [1], "line": 2}])
        );
        assert_eq!(reply.diagnostics[0].line, Some(1));
    }

    #[test]
    fn options_it_cannot_use_are_refused() {
        for (with, says) in [
            (json!({"pattern": "x"}), "unknown field"),
            (json!({"split": ["S"]}), "no flag"),
        ] {
            let error = flags(&[], with.as_object().unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains(says), "{with}: {error}");
        }
    }
}
