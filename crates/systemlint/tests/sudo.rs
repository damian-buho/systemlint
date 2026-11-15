// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use systemlint::collector::Collector;
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

const ACCOUNTS: [&str; 5] = ["alice", "bob", "carol", "dave", "daemon"];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// Each account's grants as the shipped collector parses `.scripts/capture-sudo-fixture.sh ubuntu:26.04 alice bob carol dave daemon` under `sudo`.
fn grants(sudo: &str) -> Value {
    let collector = Collector::parse(
        &std::fs::read_to_string(repository().join("collectors/sudo-grants.yaml")).unwrap(),
    )
    .unwrap();
    let argv = collector.read.exec_from.clone().unwrap().argv;
    let mut grants = Map::new();
    for account in ACCOUNTS {
        let stdout = std::fs::read_to_string(
            repository().join(format!("fixtures/sudo/{sudo}/{account}.txt")),
        )
        .unwrap();
        let input = Input::Exec(ExecInput {
            argv: argv.iter().map(|a| a.replace("{key}", account)).collect(),
            stdout,
            stderr: String::new(),
            exit: 0,
        });
        let request = Request {
            protocol: PROTOCOL,
            op: collector.parse.op.clone(),
            root: "/".to_owned(),
            now: None,
            inputs: vec![input],
            facts: BTreeMap::new(),
            with: collector.parse.with.clone(),
        };
        let reply = systemlint_formats::op(request).unwrap();
        assert!(
            reply.diagnostics.is_empty(),
            "{sudo} {account}: {:?}",
            reply.diagnostics
        );
        grants.insert(
            account.to_owned(),
            Value::Object(reply.facts.into_iter().collect()),
        );
    }
    Value::Object(grants)
}

// The sudo ruleset's (rule, subject, outcome) over grants and visudo's exit status, with sudo on disk or not.
fn judged(grants: Value, check: Option<i32>, installed: bool) -> Vec<(String, String, Outcome)> {
    let binary = if installed {
        json!({"/usr/bin/sudo": {"kind": "file"}})
    } else {
        json!({})
    };
    let mut document = json!({"sudo": {"binary": binary, "grants": grants}, "collectors": {"sudo-binary": {"status": "ok", "into": "sudo.binary"}, "sudo-grants": {"status": "ok", "into": "sudo.grants"}, "sudoers-check": {"status": if check.is_some() { "ok" } else { "error" }, "into": "sudo.check"}}});
    if let Some(exit) = check {
        document["sudo"]["check"] = json!({"exit-status": exit});
    }
    let ruleset = systemlint::yaml::from_str(
        &std::fs::read_to_string(repository().join("rulesets/sudo.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("sudo".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["sudo".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(&document, &rules, &[], "2026-11-15")
        .into_iter()
        .map(|c| (c.rule.clone(), c.subject_label(), c.outcome))
        .collect()
}

#[test]
fn a_nopasswd_grant_fails_its_account_alone_under_either_sudo() {
    for sudo in ["sudo.ws", "sudo-rs"] {
        let mut failing: Vec<String> = judged(grants(sudo), Some(0), true)
            .into_iter()
            .filter(|(rule, _, o)| rule == "sudo/nopasswd" && *o == Outcome::Fail)
            .map(|(_, subject, _)| subject)
            .collect();
        failing.sort();
        assert_eq!(
            failing,
            ["alice", "bob"],
            "{sudo}: an escaped NOPASSWD\\: argument and a sudo group grant pass"
        );
    }
    assert_eq!(
        grants("sudo.ws")["daemon"],
        json!({}),
        "an account sudo does not allow has no grant"
    );
}

#[test]
fn a_sudoers_visudo_rejects_fails_and_a_host_without_sudo_is_not_judged() {
    let check = |exit: Option<i32>| {
        judged(json!({}), exit, true)
            .into_iter()
            .find(|(r, _, _)| r == "sudo/invalid-sudoers")
            .unwrap()
            .2
    };
    assert_eq!(check(Some(0)), Outcome::Pass);
    assert_eq!(check(Some(1)), Outcome::Fail);
    assert_eq!(check(None), Outcome::Unknown, "visudo failed to run");
    assert!(
        judged(grants("sudo-rs"), Some(1), false)
            .iter()
            .all(|(_, _, o)| *o == Outcome::NotApplicable)
    );
}
