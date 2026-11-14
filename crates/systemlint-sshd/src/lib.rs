// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! sshd: the server configuration as `sshd -T` prints it, globally and per account through `sshd -T -C`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

pub mod authorized;
pub mod config;
pub mod keys;

use config::MAIN;

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new(
        "sshd",
        &[
            ("config", &[]),
            (
                "authorized-key-files",
                &[authorized::ACCOUNTS, "accounts.passwd"],
            ),
            ("authorized-keys", &[keys::NAMED]),
        ],
    )
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "config" => server(&request.inputs).map_err(Into::into),
        "authorized-key-files" => authorized::files(&request.facts).map_err(Into::into),
        "authorized-keys" => keys::authorized(&request.inputs, &request.facts).map_err(Into::into),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// `global` (plain `sshd -T`, keyed by the main file), `accounts` (each `-T -C` run’s `Match`-able keywords, keyed by its `user`), `settings` (see [`settings`]) and the `client` those runs named.
pub fn server(inputs: &[Input]) -> std::result::Result<Reply, String> {
    let mut reply = Reply::default();
    let (mut global, mut accounts, mut client) = (Map::new(), Map::new(), Map::new());
    for input in inputs {
        let Input::Exec(exec) = input else {
            reply.diagnostics.push(Diagnostic {
                path: input_path(input),
                line: None,
                message: "not sshd -T output, skipped".to_owned(),
            });
            continue;
        };
        let connection = connection(&exec.argv);
        let command = exec.argv.join(" ");
        match exec.exit {
            127 if connection.is_none() => reply.diagnostics.push(Diagnostic {
                path: command,
                line: None,
                message: "no sshd here, so no settings were read".to_owned(),
            }),
            127 => {}
            0 if !exec.stdout.trim().is_empty() => {
                let settings = config::facts(&config::dump(&exec.stdout));
                let Some(mut connection) = connection else {
                    global = settings;
                    continue;
                };
                let user = connection
                    .remove("user")
                    .ok_or(format!("{command} names no user"))?;
                client.extend(connection.into_iter().map(|(k, v)| (k, Value::from(v))));
                let kept = settings
                    .into_iter()
                    .filter(|(k, _)| config::MATCH.contains(&k.as_str()));
                accounts.insert(user, Value::Object(kept.collect()));
            }
            exit => {
                let reason = exec
                    .stderr
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("no output");
                return Err(format!("{command} exited {exit}: {reason}"));
            }
        }
    }
    let settings = settings(&global, &accounts);
    let global = match global.is_empty() {
        true => Map::new(),
        false => Map::from_iter([(MAIN.to_owned(), Value::Object(global))]),
    };
    reply
        .facts
        .insert("global".to_owned(), Value::Object(global));
    reply
        .facts
        .insert("accounts".to_owned(), Value::Object(accounts));
    reply
        .facts
        .insert("settings".to_owned(), Value::Object(settings));
    if !client.is_empty() {
        reply
            .facts
            .insert("client".to_owned(), Value::Object(client));
    }
    Ok(reply)
}

/// Each `Match`-able keyword’s global value under the main file, plus every account whose own run settled it otherwise.
pub fn settings(global: &Map<String, Value>, accounts: &Map<String, Value>) -> Map<String, Value> {
    let mut settings = Map::new();
    for keyword in config::MATCH {
        let main = global.get(*keyword);
        let mut subjects: Map<String, Value> = main
            .map(|v| (MAIN.to_owned(), v.clone()))
            .into_iter()
            .collect();
        for (account, own) in accounts {
            match own.get(*keyword) {
                Some(value) if Some(value) != main => {
                    subjects.insert(account.clone(), value.clone());
                }
                _ => {}
            }
        }
        if !subjects.is_empty() {
            settings.insert((*keyword).to_owned(), Value::Object(subjects));
        }
    }
    settings
}

/// The `-C` connection spec of an argv as `key=value` pairs, `None` without one.
pub fn connection(argv: &[String]) -> Option<BTreeMap<String, String>> {
    let spec = argv.iter().skip_while(|a| *a != "-C").nth(1)?;
    Some(
        spec.split(',')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}

// The path or target an input names.
fn input_path(input: &Input) -> String {
    match input {
        Input::File(file) => file.path.clone(),
        Input::Probe(probe) => probe.target.clone(),
        Input::Exec(exec) => exec.argv.join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use systemlint_protocol::{ExecInput, FileInput};

    fn exec(argv: &[&str], exit: i32, stdout: &str, stderr: &str) -> Input {
        Input::Exec(ExecInput {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit,
        })
    }

    fn plain(exit: i32, stdout: &str, stderr: &str) -> Input {
        exec(&["/usr/sbin/sshd", "-T"], exit, stdout, stderr)
    }

    fn account(user: &str, exit: i32, stdout: &str) -> Input {
        let spec = format!("user={user},host=client.invalid,addr=192.0.2.1");
        exec(&["/usr/sbin/sshd", "-T", "-C", &spec], exit, stdout, "")
    }

    fn collected(inputs: &[Input]) -> (Value, Vec<Diagnostic>) {
        let reply = server(inputs).unwrap();
        (
            Value::Object(reply.facts.into_iter().collect()),
            reply.diagnostics,
        )
    }

    #[test]
    fn describe_lists_the_ops_and_their_needs() {
        let describe = describe();
        assert_eq!(describe.name, "sshd");
        assert_eq!(
            describe
                .ops
                .iter()
                .map(|o| (o.op.as_str(), o.needs.clone()))
                .collect::<Vec<_>>(),
            [
                ("config", vec![]),
                (
                    "authorized-key-files",
                    vec![
                        authorized::ACCOUNTS.to_owned(),
                        "accounts.passwd".to_owned()
                    ]
                ),
                ("authorized-keys", vec![keys::NAMED.to_owned()])
            ]
        );
        assert!(
            op(Request {
                protocol: 1,
                op: "nope".into(),
                root: "/".into(),
                now: None,
                inputs: vec![],
                facts: Default::default(),
                with: Default::default(),
            })
            .is_err()
        );
    }

    #[test]
    fn global_comes_from_plain_t_and_each_account_from_its_own_run() {
        let (facts, diagnostics) = collected(&[
            plain(
                0,
                "permitrootlogin no\nx11forwarding no\nciphers aes128-ctr\n",
                "",
            ),
            account(
                "root",
                0,
                "permitrootlogin no\nx11forwarding no\nciphers aes128-ctr\n",
            ),
            account(
                "sftp",
                0,
                "permitrootlogin no\nx11forwarding yes\nciphers aes128-ctr\n",
            ),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            facts["global"],
            json!({MAIN: {"permitrootlogin": "no", "x11forwarding": "no", "ciphers": ["aes128-ctr"]}})
        );
        assert_eq!(
            facts["accounts"]["sftp"],
            json!({"permitrootlogin": "no", "x11forwarding": "yes"}),
            "a keyword Match refuses stays under global only"
        );
        assert_eq!(facts["accounts"]["root"]["x11forwarding"], "no");
        assert_eq!(
            facts["settings"],
            json!({
                "permitrootlogin": {MAIN: "no"},
                "x11forwarding": {MAIN: "no", "sftp": "yes"}
            }),
            "an account appears only where its value differs from global"
        );
        assert_eq!(
            facts["client"],
            json!({"host": "client.invalid", "addr": "192.0.2.1"})
        );
    }

    #[test]
    fn settings_keep_an_account_whose_keyword_global_lacks_and_drop_non_match_keywords() {
        let global = Map::from_iter([("ciphers".to_owned(), json!(["aes128-ctr"]))]);
        let accounts = Map::from_iter([(
            "alice".to_owned(),
            json!({"banner": "/etc/issue.net", "ciphers": ["chacha20"]}),
        )]);
        assert_eq!(
            Value::Object(settings(&global, &accounts)),
            json!({"banner": {"alice": "/etc/issue.net"}})
        );
    }

    #[test]
    fn a_failed_run_fails_the_op_naming_the_command() {
        let error =
            server(&[plain(1, "", "\nsshd: no hostkeys available -- exiting.\n")]).unwrap_err();
        assert_eq!(
            error,
            "/usr/sbin/sshd -T exited 1: sshd: no hostkeys available -- exiting."
        );
        let error = server(&[account("alice", 255, "")]).unwrap_err();
        assert!(
            error.starts_with("/usr/sbin/sshd -T -C user=alice"),
            "{error}"
        );
        assert!(
            server(&[plain(0, " \n", "")])
                .unwrap_err()
                .ends_with("exited 0: no output")
        );
    }

    #[test]
    fn no_server_gives_empty_settings_and_says_so_once() {
        let absent = "/usr/sbin/sshd: not found\n";
        let (facts, diagnostics) = collected(&[
            plain(127, "", absent),
            exec(
                &["/usr/sbin/sshd", "-T", "-C", "user=root"],
                127,
                "",
                absent,
            ),
        ]);
        assert_eq!(facts, json!({"global": {}, "accounts": {}, "settings": {}}));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path, "/usr/sbin/sshd -T");
        let (facts, _) = collected(&[]);
        assert_eq!(facts, json!({"global": {}, "accounts": {}, "settings": {}}));
    }

    #[test]
    fn a_run_without_a_user_fails_and_a_file_is_skipped() {
        assert_eq!(
            server(&[exec(
                &["/usr/sbin/sshd", "-T", "-C", "host=h"],
                0,
                "port 22\n",
                ""
            )])
            .unwrap_err(),
            "/usr/sbin/sshd -T -C host=h names no user"
        );
        let file = Input::File(FileInput {
            path: MAIN.into(),
            content: Some("Port 22\n".into()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        });
        let (_, diagnostics) = collected(&[file]);
        assert_eq!(diagnostics[0].message, "not sshd -T output, skipped");
    }

    #[test]
    fn connection_reads_the_spec_after_c() {
        let argv = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(connection(&argv(&["sshd", "-T"])), None);
        assert_eq!(connection(&argv(&["sshd", "-T", "-C"])), None);
        assert_eq!(
            connection(&argv(&["sshd", "-T", "-C", "user=a,addr=192.0.2.1,junk"])),
            Some(BTreeMap::from([
                ("user".to_owned(), "a".to_owned()),
                ("addr".to_owned(), "192.0.2.1".to_owned())
            ]))
        );
    }
}
