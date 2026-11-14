// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Authentication configuration: login.defs, pam_limits and PAM service files.

use serde_json::{Value, json};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::text;

/// A diagnostic for one line of one file.
fn note(reply: &mut Reply, path: &str, line: usize, message: String) {
    reply.diagnostics.push(Diagnostic {
        path: path.to_owned(),
        line: Some(line as u64),
        message,
    });
}

/// Every `NAME value` line of login.defs as shadow’s getdef reads it: the last line naming a key wins, surrounding double quotes dropped.
pub fn login_defs(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for (_, content) in inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
    {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            reply.facts.insert(name.to_owned(), Value::from(value));
        }
    }
    reply
}

/// Every pam_limits entry of every input in read order under `entries`: domain, type and item lowercased as pam_limits compares them, value, path and line; text after `#` is a comment.
pub fn limits(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut entries = Vec::new();
    let files: Vec<_> = inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
        .collect();
    for (path, content) in files {
        for (index, line) in content.lines().enumerate() {
            let words: Vec<&str> = line
                .split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            match words[..] {
                [] => {}
                [domain, kind, item, value] => entries.push(json!({
                    "domain": domain, "type": kind.to_lowercase(), "item": item.to_lowercase(),
                    "value": value.to_lowercase(), "path": path, "line": index + 1})),
                _ => note(
                    &mut reply,
                    path,
                    index + 1,
                    format!(
                        "{} fields where pam_limits takes 4, ignored as it does",
                        words.len()
                    ),
                ),
            }
        }
    }
    reply
        .facts
        .insert("entries".to_owned(), Value::from(entries));
    reply
}

/// The next PAM token: a `[…]` group kept whole with its brackets and `\]` unescaped, else a run of non-blanks.
fn token(rest: &mut &str) -> Option<String> {
    *rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    if let Some(inner) = rest.strip_prefix('[') {
        let mut out = String::new();
        let mut chars = inner.char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                '\\' if inner[at + 1..].starts_with(']') => {
                    out.push(']');
                    chars.next();
                }
                ']' => {
                    *rest = &inner[at + 1..];
                    return Some(format!("[{out}]"));
                }
                c => out.push(c),
            }
        }
        *rest = "";
        return Some(format!("[{out}"));
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let word = rest[..end].to_owned();
    *rest = &rest[end..];
    Some(word)
}

/// One PAM line as an entry, or why Linux-PAM would skip it.
fn pam_entry(line: &str, number: usize) -> Result<Value, String> {
    let mut rest = line;
    let kind = token(&mut rest).unwrap_or_default();
    if kind == "@include" {
        let file = token(&mut rest).ok_or("@include names no file")?;
        return Ok(json!({"line": number, "include": file}));
    }
    let silent = kind.starts_with('-');
    let kind = kind.trim_start_matches('-').to_lowercase();
    if !["auth", "account", "password", "session"].contains(&kind.as_str()) {
        return Err(format!(
            "type {kind} is unknown, so Linux-PAM skips the line"
        ));
    }
    let control = token(&mut rest).ok_or("no control")?.to_lowercase();
    let control = control.split_whitespace().collect::<Vec<_>>().join(" ");
    let module = token(&mut rest).ok_or("no module")?;
    let module = module.rsplit('/').next().unwrap_or(&module).to_owned();
    let arguments: Vec<String> = std::iter::from_fn(|| token(&mut rest))
        .map(
            |a| match a.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
                Some(inner) => inner.to_owned(),
                None => a,
            },
        )
        .collect();
    Ok(
        json!({"line": number, "type": kind, "control": control, "module": module, "arguments": arguments, "silent": silent}),
    )
}

/// Every PAM service file keyed by its path, as its list of entries in order: type, control, the module’s file name, arguments, `silent` for a leading `-`, or an `@include`; `#` starts a comment and `\` joins the next line.
pub fn pam(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let files: Vec<_> = inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
        .collect();
    for (path, content) in files {
        let mut entries = Vec::new();
        let (mut joined, mut start) = (String::new(), 0);
        for (index, raw) in content.lines().enumerate() {
            if joined.is_empty() {
                start = index + 1;
            }
            let (body, more) = match raw.strip_suffix('\\') {
                Some(body) => (body, true),
                None => (raw, false),
            };
            joined.push_str(body);
            joined.push(' ');
            if more {
                continue;
            }
            let line = std::mem::take(&mut joined);
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            match pam_entry(line, start) {
                Ok(entry) => entries.push(entry),
                Err(message) => note(&mut reply, path, start, message),
            }
        }
        reply.facts.insert(path.to_owned(), Value::Array(entries));
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::FileInput;

    fn object(facts: impl IntoIterator<Item = (String, Value)>) -> Value {
        Value::Object(facts.into_iter().collect())
    }

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
    fn login_defs_keeps_the_last_value_of_a_key_without_its_quotes() {
        let reply = login_defs(&[file(
            "/etc/login.defs",
            "# comment\nUMASK\t\t022\nPASS_MAX_DAYS 99999\nUMASK 027\nENV_PATH \"PATH=/bin\"\nLOG_OK_LOGINS\n",
        )]);
        assert_eq!(
            object(reply.facts),
            json!({"UMASK": "027", "PASS_MAX_DAYS": "99999", "ENV_PATH": "PATH=/bin", "LOG_OK_LOGINS": ""})
        );
    }

    #[test]
    fn limits_lists_entries_in_read_order_and_skips_a_line_with_the_wrong_field_count() {
        let reply = limits(&[
            file(
                "/etc/security/limits.conf",
                "*  Hard  CORE  0 # no dumps\n@audio - rtprio\n",
            ),
            file(
                "/etc/security/limits.d/90.conf",
                "root hard core Unlimited\n",
            ),
        ]);
        assert_eq!(
            object(reply.facts),
            json!({"entries": [
                {"domain": "*", "type": "hard", "item": "core", "value": "0", "path": "/etc/security/limits.conf", "line": 1},
                {"domain": "root", "type": "hard", "item": "core", "value": "unlimited", "path": "/etc/security/limits.d/90.conf", "line": 1}]})
        );
        assert_eq!(reply.diagnostics[0].line, Some(2));
    }

    #[test]
    fn pam_reads_bracket_controls_silent_types_includes_and_joined_lines() {
        let reply = pam(&[file(
            "/etc/pam.d/common-auth",
            "auth\t[success=1  default=ignore]\tpam_unix.so nullok\n-auth optional /usr/lib/x86_64-linux-gnu/security/pam_faillock.so \\\n  authfail\n@include common-account\nbogus required pam_deny.so\nauth required pam_exec.so [a b\\] c] # tail\n",
        )]);
        assert_eq!(
            object(reply.facts),
            json!({"/etc/pam.d/common-auth": [
                {"line": 1, "type": "auth", "control": "[success=1 default=ignore]", "module": "pam_unix.so", "arguments": ["nullok"], "silent": false},
                {"line": 2, "type": "auth", "control": "optional", "module": "pam_faillock.so", "arguments": ["authfail"], "silent": true},
                {"line": 4, "include": "common-account"},
                {"line": 6, "type": "auth", "control": "required", "module": "pam_exec.so", "arguments": ["a b] c"], "silent": false}]})
        );
        assert_eq!(reply.diagnostics[0].line, Some(5));
    }
}
