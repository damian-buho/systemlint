// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! sshd: the server configuration, from `sshd -T` when it ran, else from the files with `Include` expanded, plus every `Match` block.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

pub mod config;

use config::{MAIN, Raw};

/// `sshd -T -f /dev/null`: the compiled defaults the files are read against.
const DEFAULTS: &str = include_str!("defaults.txt");

/// The package [`DEFAULTS`] was captured from.
pub const DEFAULTS_FROM: &str = "openssh-server 1:10.2p1-2ubuntu3.8";

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("sshd", &[("config", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "config" => server(&request.inputs).map_err(Into::into),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// `source`, `global` (keywords `Match` refuses) keyed by the main file, the `contexts` keyed by it and by each `Match` line, and `defaults` when read from the files.
pub fn server(inputs: &[Input]) -> std::result::Result<Reply, String> {
    let mut reply = Reply::default();
    let mut files = BTreeMap::new();
    let mut effective = None;
    for input in inputs {
        match input {
            Input::File(file) => match &file.content {
                Some(text) => drop(files.insert(file.path.clone(), text.clone())),
                None => reply.diagnostics.push(Diagnostic { path: file.path.clone(), line: None, message: "not UTF-8 text, skipped".to_owned() }),
            },
            Input::Exec(exec) if exec.exit == 0 && !exec.stdout.trim().is_empty() => effective = Some(config::dump(&exec.stdout)),
            Input::Exec(exec) => {
                let reason = exec.stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("no output");
                reply.diagnostics.push(Diagnostic { path: exec.argv.join(" "), line: None, message: format!("exited {}: {reason}; read from the files", exec.exit) });
            }
        }
    }
    let defaults = config::dump(DEFAULTS);
    let mut lines = Vec::new();
    config::expand(MAIN, &files, 0, &mut lines)?;
    let parsed = config::settle(&lines, &defaults);
    reply.diagnostics.extend(parsed.problems.into_iter().map(|(path, line, message)| Diagnostic { path, line, message }));
    let source = match (&effective, files.contains_key(MAIN)) {
        (Some(_), _) => "effective",
        (None, true) => "files",
        (None, false) => "none",
    };
    let (mut fixed, mut contexts) = (Map::new(), Map::new());
    if source != "none" {
        let global: Raw = effective.unwrap_or_else(|| overlay(&defaults, &parsed.global));
        let (shared, rest): (Map<String, Value>, Map<String, Value>) = config::facts(&global).into_iter().partition(|(k, _)| config::MATCH.contains(&k.as_str()));
        fixed.insert(MAIN.to_owned(), Value::Object(rest));
        contexts.insert(MAIN.to_owned(), Value::Object(shared));
        for block in parsed.blocks {
            let mut merged: Map<String, Value> = config::facts(&overlay(&global, &block.raw)).into_iter().filter(|(k, _)| config::MATCH.contains(&k.as_str())).collect();
            merged.insert("match".to_owned(), Value::from(block.criteria));
            contexts.insert(block.key, Value::Object(merged));
        }
    }
    reply.facts.insert("source".to_owned(), Value::from(source));
    reply.facts.insert("global".to_owned(), Value::Object(fixed));
    reply.facts.insert("contexts".to_owned(), Value::Object(contexts));
    if source == "files" {
        reply.facts.insert("defaults".to_owned(), Value::from(DEFAULTS_FROM));
    }
    Ok(reply)
}

// `base` with every keyword `over` sets replacing its value.
fn overlay(base: &Raw, over: &Raw) -> Raw {
    let mut raw = base.clone();
    raw.extend(over.iter().map(|(k, v)| (k.clone(), v.clone())));
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use systemlint_protocol::{ExecInput, FileInput};

    fn file(path: &str, text: &str) -> Input {
        Input::File(FileInput { path: path.into(), content: Some(text.into()), content_base64: None, stat: None })
    }

    fn exec(exit: i32, stdout: &str, stderr: &str) -> Input {
        Input::Exec(ExecInput { argv: vec!["/usr/sbin/sshd".into(), "-T".into()], stdout: stdout.into(), stderr: stderr.into(), exit })
    }

    fn collected(inputs: &[Input]) -> (Value, Vec<Diagnostic>) {
        let reply = server(inputs).unwrap();
        (Value::Object(reply.facts.into_iter().collect()), reply.diagnostics)
    }

    #[test]
    fn describe_lists_config() {
        let describe = describe();
        assert_eq!(describe.name, "sshd");
        assert_eq!(describe.ops.iter().map(|o| o.op.as_str()).collect::<Vec<_>>(), ["config"]);
        assert!(op(Request { protocol: 1, op: "nope".into(), root: "/".into(), now: None, inputs: vec![], facts: Default::default() }).is_err());
    }

    #[test]
    fn the_defaults_fill_what_the_files_leave_unset() {
        let (facts, diagnostics) = collected(&[file(MAIN, "PermitRootLogin no\n")]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!((facts["source"].as_str(), facts["defaults"].as_str()), (Some("files"), Some(DEFAULTS_FROM)));
        let global = &facts["contexts"][MAIN];
        assert_eq!(global["permitrootlogin"], "no");
        assert_eq!(global["passwordauthentication"], "yes");
        assert_eq!(facts["global"][MAIN]["logingracetime"], 120);
        assert_eq!(facts["global"][MAIN]["port"], json!([22]));
        assert!(global.get("logingracetime").is_none(), "a keyword Match refuses lives only under global");
    }

    #[test]
    fn a_successful_sshd_t_wins_and_match_blocks_still_come_from_the_files() {
        let (facts, diagnostics) = collected(&[file(MAIN, "PermitRootLogin yes\nMatch Group sftp\n  X11Forwarding yes\n"), exec(0, "permitrootlogin no\nx11forwarding no\nciphers aes128-ctr\n", "")]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(facts["source"], "effective");
        assert!(facts.get("defaults").is_none());
        assert_eq!(facts["global"], json!({MAIN: {"ciphers": ["aes128-ctr"]}}));
        assert_eq!(facts["contexts"][MAIN], json!({"permitrootlogin": "no", "x11forwarding": "no"}));
        assert_eq!(facts["contexts"]["/etc/ssh/sshd_config:2"], json!({"match": "Group sftp", "permitrootlogin": "no", "x11forwarding": "yes"}));
    }

    #[test]
    fn a_failed_sshd_t_falls_back_to_the_files_and_says_why() {
        let (facts, diagnostics) = collected(&[file(MAIN, "PermitRootLogin yes\n"), exec(1, "", "\nsshd: no hostkeys available -- exiting.\n")]);
        assert_eq!(facts["source"], "files");
        assert_eq!(facts["contexts"][MAIN]["permitrootlogin"], "yes");
        assert_eq!(diagnostics[0].message, "exited 1: sshd: no hostkeys available -- exiting.; read from the files");
        assert_eq!(diagnostics[0].path, "/usr/sbin/sshd -T");
    }

    #[test]
    fn no_server_gives_no_contexts() {
        let (facts, _) = collected(&[exec(127, "", "/usr/sbin/sshd: not found\n")]);
        assert_eq!(facts, json!({"source": "none", "global": {}, "contexts": {}}));
        let (facts, _) = collected(&[]);
        assert_eq!(facts["source"], "none");
    }

    #[test]
    fn a_keyword_match_refuses_is_reported_and_left_out_of_the_block() {
        let (facts, diagnostics) = collected(&[file(MAIN, "Match User backup\n  Ciphers aes128-cbc\n")]);
        assert_eq!((diagnostics[0].line, diagnostics[0].message.as_str()), (Some(2), "ciphers is not allowed in a Match block, so sshd refuses to start"));
        assert!(facts["contexts"]["/etc/ssh/sshd_config:1"].get("ciphers").is_none());
        assert!(facts["global"][MAIN]["ciphers"].as_array().unwrap().iter().all(|c| c != "aes128-cbc"));
    }

    #[test]
    fn a_bad_include_fails_the_op_and_binary_files_are_reported() {
        assert!(server(&[file(MAIN, "Include /srv/ssh.conf\n")]).unwrap_err().contains("/srv/ssh.conf"));
        let binary = Input::File(FileInput { path: "/etc/ssh/sshd_config.d/x.conf".into(), content: None, content_base64: Some("AA==".into()), stat: None });
        let (_, diagnostics) = collected(&[file(MAIN, "Include /etc/ssh/sshd_config.d/*.conf\n"), binary]);
        assert_eq!(diagnostics[0].message, "not UTF-8 text, skipped");
    }
}
