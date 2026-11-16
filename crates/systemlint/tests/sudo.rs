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

// The shipped collector `id`’s parse of one captured `file` of `.scripts/capture-sudo-fixture.sh ubuntu:26.04 alice bob carol dave daemon` under `sudo`.
fn parsed(id: &str, sudo: &str, file: &str) -> Value {
    let collector = Collector::parse(
        &std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap();
    let argv = match &collector.read.exec_from {
        Some(each) => each.argv.iter().map(|a| a.replace("{key}", file)).collect(),
        None => collector.read.exec.clone().unwrap(),
    };
    let stdout =
        std::fs::read_to_string(repository().join(format!("fixtures/sudo/{sudo}/{file}.txt")))
            .unwrap();
    let input = Input::Exec(ExecInput {
        argv,
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
        "{id} {sudo} {file}: {:?}",
        reply.diagnostics
    );
    Value::Object(reply.facts.into_iter().collect())
}

// Each account's facts from the shipped collector `id` under `sudo`.
fn accounts(id: &str, sudo: &str) -> Value {
    let facts: Map<String, Value> = ACCOUNTS
        .iter()
        .map(|a| ((*a).to_owned(), parsed(id, sudo, a)))
        .collect();
    Value::Object(facts)
}

// Each account's grants as the shipped collector parses them under `sudo`.
fn grants(sudo: &str) -> Value {
    accounts("sudo-grants", sudo)
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
    let absent = judged(grants("sudo-rs"), Some(1), false);
    let (missing, rest): (Vec<_>, Vec<_>) = absent
        .iter()
        .partition(|(r, _, _)| r == "sudo/not-installed");
    assert_eq!(
        missing.iter().map(|c| c.2).collect::<Vec<_>>(),
        [Outcome::Fail],
        "CIS 5.2.1 asks for sudo"
    );
    assert!(rest.iter().all(|(_, _, o)| *o == Outcome::Skip), "{rest:?}");
}

// The sudo-defaults ruleset's (rule, subject, outcome) over the captures under `sudo`, standard-only rules included.
fn defaults(sudo: &str) -> Vec<(String, String, Outcome)> {
    let document = json!({
        "sudo": {"binary": {"/usr/bin/sudo": {"kind": "file"}}, "version": parsed("sudo-version", sudo, "version"), "defaults": accounts("sudo-defaults", sudo)},
        "collectors": {"sudo-version": {"status": "ok", "into": "sudo.version"}, "sudo-defaults": {"status": "ok", "into": "sudo.defaults"}},
    });
    let text = std::fs::read_to_string(repository().join("rulesets/sudo-defaults.yaml"))
        .unwrap()
        .replace("\"${sudo-timestamp-timeout}\"", "15")
        .replace("${sudo-timestamp-timeout}", "15");
    let ruleset = systemlint::yaml::from_str(&text).unwrap();
    let library = Library::new(BTreeMap::from([("sudo-defaults".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["sudo".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    let mut checks: Vec<_> = lint(&document, &rules, &[], "2026-11-15")
        .into_iter()
        .filter(|c| c.outcome != Outcome::Pass && c.outcome != Outcome::Skip)
        .map(|c| (c.rule.clone(), c.subject_label(), c.outcome))
        .collect();
    checks.sort();
    checks
}

#[test]
fn classic_sudo_defaults_fail_the_accounts_they_apply_to() {
    assert_eq!(
        parsed("sudo-defaults", "sudo.ws", "dave"),
        json!({
            "env_reset": true, "mail_badpass": true,
            "secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
            "use_pty": false, "env_keep+": "LANG LC_*", "logfile": "/var/log/sudo log",
        }),
        "Defaults:dave !use_pty comes after the global use_pty and wins"
    );
    let fail = |rule: &str, subject: &str| {
        (
            format!("sudo-defaults/{rule}"),
            subject.to_owned(),
            Outcome::Fail,
        )
    };
    assert_eq!(
        defaults("sudo.ws"),
        [
            fail("logfile", "alice"),
            fail("logfile", "bob"),
            fail("logfile", "carol"),
            fail("no-authenticate", "bob"),
            fail("no-pty", "dave"),
            fail("timestamp-timeout", "bob"),
            fail("use-pty", "dave"),
        ],
        "daemon may not run sudo, so it has no Defaults to judge"
    );
}

#[test]
fn sudo_rs_prints_no_defaults_so_the_ruleset_is_not_applicable() {
    assert_eq!(
        parsed("sudo-version", "sudo.ws", "version"),
        json!({"1.9.17p2": {}})
    );
    assert_eq!(parsed("sudo-version", "sudo-rs", "version"), json!({}));
    let judged = defaults("sudo-rs");
    assert!(!judged.is_empty());
    assert!(
        judged.iter().all(|(_, _, o)| *o == Outcome::NotApplicable),
        "{judged:?}"
    );
}
