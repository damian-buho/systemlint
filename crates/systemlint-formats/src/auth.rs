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
