// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use serde_json::Value;
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("formats", &[("ini", &[]), ("kv", &[]), ("lines", &[]), ("regex", &[]), ("toml", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "kv" => Ok(kv(&request.inputs)),
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
    use systemlint_protocol::{ExecInput, FileInput};

    fn file(path: &str, content: &str) -> Input {
        Input::File(FileInput { path: path.to_owned(), content: Some(content.to_owned()), content_base64: None, stat: None })
    }

    #[test]
    fn describe_lists_the_generic_parsers() {
        let describe = describe();
        assert_eq!(describe.name, "formats");
        assert_eq!(describe.ops.iter().map(|o| o.op.as_str()).collect::<Vec<_>>(), ["ini", "kv", "lines", "regex", "toml"]);
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
    fn other_ops_are_not_implemented() {
        let request = Request { protocol: 1, op: "ini".into(), root: "/".into(), now: None, inputs: vec![], facts: Default::default() };
        assert!(op(request).unwrap_err().to_string().contains("ini"));
    }
}
