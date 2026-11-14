// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint, schema};
use systemlint::rules::Library;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

const MAIN: &str = "/etc/ssh/sshd_config";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn shipped() -> Collector {
    Collector::parse(&std::fs::read_to_string(repository().join("collectors/sshd.yaml")).unwrap())
        .unwrap()
}

// The shipped collector’s commands answered by `.scripts/capture-sshd-fixture.sh ubuntu:26.04 root backup alice`.
fn document() -> Value {
    let collector = shipped();
    let fixture = repository().join("fixtures/sshd");
    let exec = |argv: Vec<String>, path: PathBuf| {
        Input::Exec(ExecInput {
            argv,
            stdout: std::fs::read_to_string(path).unwrap(),
            stderr: String::new(),
            exit: 0,
        })
    };
    let from = collector.read.exec_from.clone().unwrap();
    let mut inputs = vec![exec(
        collector.read.exec.clone().unwrap(),
        fixture.join("sshd-T.txt"),
    )];
    for account in ["root", "backup", "alice"] {
        let argv = from
            .argv
            .iter()
            .map(|a| a.replace("{key}", account))
            .collect();
        inputs.push(exec(argv, fixture.join(format!("accounts/{account}.txt"))));
    }
    let reply = systemlint_sshd::op(Request {
        protocol: PROTOCOL,
        op: collector.parse.op.clone(),
        root: "/".into(),
        now: None,
        inputs,
        facts: BTreeMap::new(),
        with: Default::default(),
    })
    .unwrap();
    assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    json!({"sshd": Value::Object(reply.facts.into_iter().collect()), "collectors": {"sshd": {"status": "ok", "into": "sshd"}}})
}

fn checks(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &std::fs::read_to_string(repository().join("rulesets/ssh.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("ssh".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["ssh".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    assert_eq!(rules.len(), 17);
    lint(document, &rules, &[], "2026-11-11")
}

fn outcomes(document: &Value) -> Vec<(String, String, Outcome)> {
    checks(document)
        .into_iter()
        .map(|c| (c.rule.clone(), c.subject_text(), c.outcome))
        .collect()
}

#[test]
fn the_collector_runs_sshd_for_root_and_every_login_shell_only() {
    let from = shipped().read.exec_from.unwrap();
    let keep = schema(from.keep.as_ref().unwrap()).unwrap();
    for (entry, kept) in [
        (json!({"uid": 0, "shell": "/usr/sbin/nologin"}), true),
        (json!({"uid": 1000, "shell": "/bin/bash"}), true),
        (json!({"uid": 1000, "shell": ""}), true),
        (json!({"uid": 1, "shell": "/usr/sbin/nologin"}), false),
        (json!({"uid": 1, "shell": "/sbin/nologin"}), false),
        (json!({"uid": 1, "shell": "/bin/false"}), false),
        (json!({"uid": 1, "shell": "/usr/bin/false"}), false),
    ] {
        assert_eq!(keep.is_valid(&entry), kept, "{entry}");
    }
    assert_eq!(
        from.argv[3],
        "user={key},host=client.invalid,addr=192.0.2.1"
    );
    assert!(shipped().privileged, "sshd -T reads the host keys");
}

#[test]
fn each_account_gets_what_its_own_run_settled() {
    let document = document();
    let sshd = &document["sshd"];
    assert_eq!(
        sshd["client"],
        json!({"host": "client.invalid", "addr": "192.0.2.1"})
    );
    assert_eq!(sshd["global"][MAIN]["port"], json!([2222, 22]));
    assert_eq!(
        sshd["global"][MAIN]["logingracetime"], 90,
        "the drop-in’s value wins"
    );
    let backup = &sshd["accounts"]["backup"];
    assert_eq!(
        (
            &backup["passwordauthentication"],
            &backup["permitrootlogin"],
            &backup["x11forwarding"]
        ),
        (&json!("yes"), &json!("forced-commands-only"), &json!("no")),
        "Match User backup Address 192.0.2.0/24 holds the reserved client address"
    );
    assert_eq!(sshd["accounts"]["alice"]["passwordauthentication"], "no");
    assert!(
        sshd["accounts"]["alice"].get("logingracetime").is_none(),
        "a keyword Match refuses lives only under global"
    );
}

#[test]
fn every_ssh_rule_answers_and_the_failures_are_per_account() {
    let outcomes = outcomes(&document());
    assert!(
        outcomes.iter().all(|(_, _, o)| *o != Outcome::Unknown),
        "{outcomes:?}"
    );
    let failing: Vec<(&str, &str)> = outcomes
        .iter()
        .filter(|(_, _, o)| *o == Outcome::Fail)
        .map(|(r, s, _)| (r.as_str(), s.as_str()))
        .collect();
    assert_eq!(failing, FAILING);
}

const FAILING: &[(&str, &str)] = &[
    ("ssh/ciphers", MAIN),
    ("ssh/gateway-ports", "alice"),
    ("ssh/gateway-ports", "backup"),
    ("ssh/gateway-ports", "root"),
    ("ssh/login-grace-time", MAIN),
    ("ssh/password-authentication", "backup"),
    ("ssh/x11-forwarding", "alice"),
    ("ssh/x11-forwarding", "root"),
];

#[test]
fn a_weak_cipher_is_named_in_the_message() {
    let checks = checks(&document());
    let cipher = checks
        .iter()
        .find(|c| c.rule == "ssh/ciphers" && c.outcome == Outcome::Fail)
        .unwrap();
    assert!(
        cipher.message.as_deref().unwrap().contains("aes128-cbc"),
        "{:?}",
        cipher.message
    );
}

#[test]
fn a_host_without_sshd_gives_no_check() {
    let document = json!({"sshd": {"global": {}, "accounts": {}}, "collectors": {"sshd": {"status": "ok", "into": "sshd"}}});
    assert!(checks(&document).is_empty());
}
