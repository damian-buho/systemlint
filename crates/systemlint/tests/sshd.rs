// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Value, json};
use systemlint::collect::{HashKey, Options, inputs};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

const MAIN: &str = "/etc/ssh/sshd_config";
const MATCH: &str = "/etc/ssh/sshd_config:19";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// The fixture read by the shipped collector under --root, with the captured `sshd -T` added when `effective` is set.
fn document(effective: bool) -> Value {
    let collector = Collector::parse(
        &std::fs::read_to_string(repository().join("collectors/sshd.yaml")).unwrap(),
    )
    .unwrap();
    let options = Options {
        privileged: true,
        root: Root::open(&repository().join("fixtures/sshd")).unwrap(),
        live: false,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
    };
    let mut given = inputs(&collector, &options).unwrap();
    assert!(
        given.iter().all(|i| matches!(i, Input::File(_))),
        "exec never runs under --root"
    );
    if effective {
        let stdout =
            std::fs::read_to_string(repository().join("fixtures/sshd/sshd-T.txt")).unwrap();
        given.push(Input::Exec(ExecInput {
            argv: collector.read.exec.clone().unwrap(),
            stdout,
            stderr: String::new(),
            exit: 0,
        }));
    }
    let reply = systemlint_sshd::op(Request {
        protocol: PROTOCOL,
        op: collector.parse.op.clone(),
        root: "/".into(),
        now: None,
        inputs: given,
        facts: BTreeMap::from([(
            "apt.installed".to_owned(),
            json!({"openssh-server": {"version": "1:10.2p1-2ubuntu3.8"}}),
        )]),
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
fn files_and_sshd_t_give_the_same_global_config_but_listen_addresses() {
    let (mut files, mut effective) = (document(false), document(true));
    assert_eq!(
        (
            files["sshd"]["source"].as_str(),
            effective["sshd"]["source"].as_str()
        ),
        (Some("files"), Some("effective"))
    );
    for document in [&mut files, &mut effective] {
        document["sshd"]["global"][MAIN]
            .as_object_mut()
            .unwrap()
            .remove("listenaddress");
    }
    assert_eq!(files["sshd"]["global"], effective["sshd"]["global"]);
    assert_eq!(
        files["sshd"]["contexts"][MAIN],
        effective["sshd"]["contexts"][MAIN]
    );
    let global = &files["sshd"]["global"][MAIN];
    assert_eq!(
        (
            files["sshd"]["contexts"][MAIN]["permitrootlogin"].as_str(),
            global["logingracetime"].as_u64()
        ),
        (Some("prohibit-password"), Some(90))
    );
    assert_eq!(global["port"], json!([2222, 22]));
    assert_eq!(
        files["sshd"]["contexts"][MATCH]["match"],
        "User backup Address 192.0.2.0/24"
    );
}

#[test]
fn every_ssh_rule_answers_alike_on_files_and_on_sshd_t() {
    let (files, effective) = (outcomes(&document(false)), outcomes(&document(true)));
    assert!(
        files.iter().all(|(_, _, o)| *o != Outcome::Unknown),
        "{files:?}"
    );
    assert_eq!(files, effective);
    let failing: Vec<(&str, &str)> = files
        .iter()
        .filter(|(_, _, o)| *o == Outcome::Fail)
        .map(|(r, s, _)| (r.as_str(), s.as_str()))
        .collect();
    assert_eq!(
        failing,
        [
            ("ssh/ciphers", MAIN),
            ("ssh/gateway-ports", MAIN),
            ("ssh/gateway-ports", MATCH),
            ("ssh/login-grace-time", MAIN),
            ("ssh/password-authentication", MATCH),
            ("ssh/x11-forwarding", MAIN),
        ]
    );
}

#[test]
fn a_weak_cipher_is_named_in_the_message() {
    let checks = checks(&document(true));
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
    let document = json!({"sshd": {"source": "none", "global": {}, "contexts": {}}, "collectors": {"sshd": {"status": "ok", "into": "sshd"}}});
    assert!(checks(&document).is_empty());
}
