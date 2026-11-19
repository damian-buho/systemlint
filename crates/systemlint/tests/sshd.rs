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
    checks_with(document, json!({}))
}

// Like checks, the ruleset’s vars filled from `config` as `check.vars` gives them, else their defaults.
fn checks_with(document: &Value, config: Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &std::fs::read_to_string(repository().join("rulesets/ssh.yaml")).unwrap(),
    )
    .unwrap();
    let mut rulesets = BTreeMap::from([("ssh".to_owned(), ruleset)]);
    let supplied = systemlint::vars::Supplied {
        config: config.as_object().unwrap().clone(),
        env: |_| None,
        ..Default::default()
    };
    systemlint::vars::apply(&mut rulesets, &supplied).unwrap();
    let library = Library::new(rulesets).unwrap();
    let rules: Vec<_> = library
        .select(&["ssh".to_owned(), "*:*".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    assert_eq!(rules.len(), 31);
    lint(document, &rules, &[], "2026-11-11")
        .into_iter()
        .filter(|c| !c.rule.starts_with("ssh/stig-not-"))
        .collect()
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
        (json!({"uid": 0, "login-shell": false}), true),
        (json!({"uid": 1000, "login-shell": true}), true),
        (json!({"uid": 1, "login-shell": false}), false),
        (json!({"uid": 1}), false),
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
fn a_global_setting_fails_once_and_an_account_only_where_its_match_differs() {
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
    ("ssh/access-unlisted", MAIN),
    ("ssh/banner-none", MAIN),
    ("ssh/ciphers", MAIN),
    ("ssh/client-alive-interval", MAIN),
    ("ssh/gateway-ports", MAIN),
    ("ssh/login-grace-time", MAIN),
    ("ssh/max-startups", MAIN),
    ("ssh/password-authentication", "backup"),
    ("ssh/stig-client-alive-count-max", MAIN),
    ("ssh/stig-client-alive-interval", MAIN),
    ("ssh/x11-forwarding", MAIN),
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
    let facts = systemlint_sshd::server(&[]).unwrap().facts;
    let document = json!({"sshd": Value::Object(facts.into_iter().collect()), "collectors": {"sshd": {"status": "ok", "into": "sshd"}}});
    let left: Vec<_> = checks(&document)
        .into_iter()
        .map(|c| (c.subject_text(), c.rule, c.outcome))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn the_auth_tries_and_grace_time_bounds_are_vars_judged_at_their_edge() {
    let document = |tries: u64, grace: u64| json!({"sshd": {"settings": {"maxauthtries": {MAIN: tries}}, "global": {MAIN: {"logingracetime": grace}}}, "collectors": {"sshd": {"status": "ok", "into": "sshd"}}});
    let outcome = |document: &Value, config: Value, rule: &str| {
        let found: Vec<Outcome> = checks_with(document, config)
            .into_iter()
            .filter(|c| c.rule == rule)
            .map(|c| c.outcome)
            .collect();
        assert_eq!(found.len(), 1, "{rule}: {found:?}");
        found[0]
    };
    let (tries, grace) = ("ssh/max-auth-tries", "ssh/login-grace-time");
    assert_eq!(outcome(&document(4, 60), json!({}), tries), Outcome::Pass);
    assert_eq!(outcome(&document(5, 60), json!({}), tries), Outcome::Fail);
    assert_eq!(outcome(&document(4, 60), json!({}), grace), Outcome::Pass);
    assert_eq!(outcome(&document(4, 61), json!({}), grace), Outcome::Fail);
    assert_eq!(
        outcome(&document(4, 0), json!({}), grace),
        Outcome::Fail,
        "0 keeps a connection forever"
    );
    let strict = json!({"ssh-max-auth-tries": 3, "ssh-login-grace-time": 30});
    assert_eq!(
        outcome(&document(4, 30), strict.clone(), tries),
        Outcome::Fail
    );
    assert_eq!(
        outcome(&document(3, 31), strict.clone(), grace),
        Outcome::Fail
    );
    assert_eq!(outcome(&document(3, 30), strict, tries), Outcome::Pass);
}
