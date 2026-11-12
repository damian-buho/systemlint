// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! sshd: the server configuration, from `sshd -T` when it ran, else from the files with `Include` expanded, plus every `Match` block.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

pub mod config;

use config::{MAIN, Raw};

/// `sshd -T -f /dev/null` per upstream version, oldest first, with the package `.scripts/capture-sshd-defaults.sh` read it from.
pub const DEFAULTS: [(&str, &str, &str); 4] = [
    ("9.2p1", "openssh-server 1:9.2p1-2+deb12u10", include_str!("defaults/9.2p1.txt")),
    ("9.6p1", "openssh-server 1:9.6p1-3ubuntu13.20", include_str!("defaults/9.6p1.txt")),
    ("10.0p1", "openssh-server 1:10.0p1-7+deb13u4", include_str!("defaults/10.0p1.txt")),
    ("10.2p1", "openssh-server 1:10.2p1-2ubuntu3.8", include_str!("defaults/10.2p1.txt")),
];

/// The package whose sshd sets the defaults.
const PACKAGE: &str = "openssh-server";

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("sshd", &[("config", &["apt.installed"])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "config" => server(&request.inputs, &request.facts).map_err(Into::into),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// `source`, `global` (keywords `Match` refuses) keyed by the main file, the `contexts` keyed by it and by each `Match` line, and `defaults` when read from the files.
pub fn server(inputs: &[Input], facts: &BTreeMap<String, Value>) -> std::result::Result<Reply, String> {
    let mut reply = Reply::default();
    let mut files = BTreeMap::new();
    let (mut effective, mut failed) = (None, Vec::new());
    for input in inputs {
        match input {
            Input::File(file) => match &file.content {
                Some(text) => drop(files.insert(file.path.clone(), text.clone())),
                None => reply.diagnostics.push(Diagnostic { path: file.path.clone(), line: None, message: "not UTF-8 text, skipped".to_owned() }),
            },
            Input::Exec(exec) if exec.exit == 0 && !exec.stdout.trim().is_empty() => effective = Some(config::dump(&exec.stdout)),
            Input::Exec(exec) => {
                let reason = exec.stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("no output");
                failed.push((exec.argv.join(" "), format!("exited {}: {reason}", exec.exit)));
            }
        }
    }
    let fallback = if files.contains_key(MAIN) { "read from the files".to_owned() } else { format!("no {MAIN} either, so nothing was read") };
    reply.diagnostics.extend(failed.into_iter().map(|(path, message)| Diagnostic { path, line: None, message: format!("{message}; {fallback}") }));
    let installed = installed(facts);
    let (_, from, table) = defaults_for(installed.as_deref());
    let defaults = config::dump(table);
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
        reply.facts.insert("defaults".to_owned(), Value::from(from));
        if installed.is_none() {
            reply.diagnostics.push(Diagnostic { path: "apt.installed".to_owned(), line: None, message: format!("no {PACKAGE} version installed, so the files are read against the newest defaults, {from}") });
        }
    }
    Ok(reply)
}

// The installed `openssh-server` version, keyed by name or `name:arch`.
fn installed(facts: &BTreeMap<String, Value>) -> Option<String> {
    let packages = facts.get("apt.installed")?.as_object()?;
    let version = packages.iter().find(|(name, _)| name.split(':').next() == Some(PACKAGE)).and_then(|(_, p)| p["version"].as_str());
    version.map(str::to_owned)
}

/// `(major, minor, portable)` of a Debian version such as `1:9.2p1-2+deb12u10`, epoch and revision dropped.
pub fn upstream(version: &str) -> Option<(u32, u32, u32)> {
    let version = version.split_once(':').map_or(version, |(_, v)| v);
    let version = version.rsplit_once('-').map_or(version, |(v, _)| v);
    let (major, rest) = version.split_once('.')?;
    let minor_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    let portable = rest[minor_end..].strip_prefix('p').and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next()).and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major.parse().ok()?, rest[..minor_end].parse().ok()?, portable))
}

/// The newest table no newer than `installed`, the oldest when it predates them all, the newest when unknown.
pub fn defaults_for(installed: Option<&str>) -> (&'static str, &'static str, &'static str) {
    let newest = DEFAULTS[DEFAULTS.len() - 1];
    let Some(wanted) = installed.and_then(upstream) else { return newest };
    DEFAULTS.iter().rev().find(|(v, _, _)| upstream(v).is_some_and(|t| t <= wanted)).copied().unwrap_or(DEFAULTS[0])
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
        collected_on(inputs, json!({PACKAGE: {"version": "1:10.2p1-2ubuntu3.8"}}))
    }

    fn collected_on(inputs: &[Input], installed: Value) -> (Value, Vec<Diagnostic>) {
        let reply = server(inputs, &BTreeMap::from([("apt.installed".to_owned(), installed)])).unwrap();
        (Value::Object(reply.facts.into_iter().collect()), reply.diagnostics)
    }

    #[test]
    fn describe_lists_config() {
        let describe = describe();
        assert_eq!(describe.name, "sshd");
        assert_eq!(describe.ops.iter().map(|o| (o.op.as_str(), o.needs.clone())).collect::<Vec<_>>(), [("config", vec!["apt.installed".to_owned()])]);
        assert!(op(Request { protocol: 1, op: "nope".into(), root: "/".into(), now: None, inputs: vec![], facts: Default::default() }).is_err());
    }

    #[test]
    fn the_defaults_fill_what_the_files_leave_unset() {
        let (facts, diagnostics) = collected(&[file(MAIN, "PermitRootLogin no\n")]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!((facts["source"].as_str(), facts["defaults"].as_str()), (Some("files"), Some("openssh-server 1:10.2p1-2ubuntu3.8")));
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
        let (facts, diagnostics) = collected(&[exec(127, "", "/usr/sbin/sshd: not found\n")]);
        assert_eq!(facts, json!({"source": "none", "global": {}, "contexts": {}}));
        assert_eq!(diagnostics[0].message, "exited 127: /usr/sbin/sshd: not found; no /etc/ssh/sshd_config either, so nothing was read");
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
    fn upstream_drops_epoch_and_revision() {
        assert_eq!(upstream("1:9.2p1-2+deb12u10"), Some((9, 2, 1)));
        assert_eq!(upstream("10.2p1-2ubuntu3.8"), Some((10, 2, 1)));
        assert_eq!(upstream("1:10.0"), Some((10, 0, 0)));
        assert_eq!(upstream("garbage"), None);
    }

    #[test]
    fn defaults_follow_the_installed_version_at_every_edge() {
        let picked = |v: Option<&str>| defaults_for(v).0;
        assert_eq!(picked(Some("1:9.2p1-2+deb12u10")), "9.2p1", "an exact match");
        assert_eq!(picked(Some("1:9.5p1-1")), "9.2p1", "between two tables, the older");
        assert_eq!(picked(Some("1:10.0p2-1")), "10.0p1", "a later portable release of one version");
        assert_eq!(picked(Some("1:9.1p1-1")), "9.2p1", "older than every table, the oldest");
        assert_eq!(picked(Some("1:99.0p1-1")), "10.2p1", "newer than every table, the newest");
        assert_eq!(picked(None), "10.2p1", "unknown, the newest");
        assert!(DEFAULTS.windows(2).all(|w| upstream(w[0].0) < upstream(w[1].0)), "tables oldest first");
    }

    #[test]
    fn an_older_server_reads_its_own_defaults_and_an_unknown_one_says_so() {
        let (facts, diagnostics) = collected_on(&[file(MAIN, "Port 22\n")], json!({"openssh-server:amd64": {"version": "1:9.2p1-2+deb12u10"}}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(facts["defaults"], "openssh-server 1:9.2p1-2+deb12u10");
        assert!(!facts["global"][MAIN]["kexalgorithms"].as_array().unwrap().iter().any(|k| k == "mlkem768x25519-sha256"), "9.2 offers no ML-KEM");
        let (facts, diagnostics) = collected_on(&[file(MAIN, "Port 22\n")], json!({}));
        assert_eq!(facts["defaults"], "openssh-server 1:10.2p1-2ubuntu3.8");
        assert_eq!(diagnostics[0].message, "no openssh-server version installed, so the files are read against the newest defaults, openssh-server 1:10.2p1-2ubuntu3.8");
    }

    #[test]
    fn a_bad_include_fails_the_op_and_binary_files_are_reported() {
        assert!(server(&[file(MAIN, "Include /srv/ssh.conf\n")], &BTreeMap::new()).unwrap_err().contains("/srv/ssh.conf"));
        let binary = Input::File(FileInput { path: "/etc/ssh/sshd_config.d/x.conf".into(), content: None, content_base64: Some("AA==".into()), stat: None });
        let (_, diagnostics) = collected(&[file(MAIN, "Include /etc/ssh/sshd_config.d/*.conf\n"), binary]);
        assert_eq!(diagnostics[0].message, "not UTF-8 text, skipped");
    }
}
