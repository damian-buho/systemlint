// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{HashKey, Named, Options, named, read};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

const PASSWD: &str = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\nwww:x:33:33::/var/www:/usr/sbin/nologin\n";
const GLOBAL: &str = "authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u\npubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512,ssh-dss\nrequiredrsasize 1024\n";
const BOB: &str = "authorizedkeysfile /etc/ssh/bob/%u\npubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512,ssh-dss\nrequiredrsasize 1024\n";
const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQVHjXf7wHmfkvbwaZCksrE3U8tnP/3vlEMvEzXpq9E alice@example";
const RSA1024: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/oFCUFv7nvEvg79gmXGcxXUcCKHUQ12f4QoQ55JEelYWCvY33wvX/2p4s9azy7MnsvfjTeq+KWV/Iz9vklm3LeiNr9HUf/nrnFWZ/6ZmsMUjS+PVa9+/s1BqmF9MD9rQzH5ZPFoMMEviFBkIqjtuPzSu+9DSqaGLZNaRvRNwOfw== old";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// A DSA public key line whose prime is 1024 bits, the rest of its numbers one byte each.
fn dsa() -> String {
    let mut prime = vec![0u8, 0x80];
    prime.extend([0u8; 127]);
    let blob = [&b"ssh-dss"[..], &prime, &[1], &[2], &[3]]
        .iter()
        .fold(Vec::new(), |mut v, p| {
            v.extend((p.len() as u32).to_be_bytes());
            v.extend(*p);
            v
        });
    format!("ssh-dss {} bob@old", systemlint_sshd::keys::encode(&blob))
}

// A root holding the accounts and the key files, rebuilt on every run.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("authorized-keys-root");
    let alice = format!("# laptop\n\n{RSA1024}\nnot a key at all\n");
    let entries: [common::Entry; 15] = [
        ("etc", None, 0o755),
        ("etc/passwd", Some(PASSWD), 0o644),
        ("etc/ssh", None, 0o755),
        ("etc/ssh/bob", None, 0o755),
        ("etc/ssh/bob/bob", Some(&dsa()), 0o644),
        ("root", None, 0o700),
        ("root/.ssh", None, 0o700),
        ("root/.ssh/authorized_keys", Some(ED25519), 0o600),
        ("home", None, 0o755),
        ("home/alice", None, 0o750),
        ("home/alice/.ssh", None, 0o700),
        ("home/alice/.ssh/authorized_keys", Some(&alice), 0o600),
        ("home/bob", None, 0o755),
        ("home/bob/.ssh", None, 0o700),
        ("home/bob/.ssh/authorized_keys", Some(ED25519), 0o600),
    ];
    common::build(&root, &entries);
    root
}

fn collector(id: &str) -> Collector {
    Collector::parse(
        &fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap()
}

// One collector through the core, its plugin called in-process with the facts its op needs.
fn run(id: &str, options: &Options, document: &Value, needs: &[&str]) -> Map<String, Value> {
    let c = collector(id);
    let outcomes = &document["collectors"];
    let paths = match c.read.named().next() {
        Some(_) => named(
            &c,
            std::slice::from_ref(&c),
            document.as_object().unwrap(),
            outcomes.as_object().unwrap(),
        )
        .unwrap(),
        None => Named::default(),
    };
    let facts = needs
        .iter()
        .map(|n| {
            (
                n.to_string(),
                n.split('.').fold(document, |v, k| &v[k]).clone(),
            )
        })
        .collect();
    let request = Request {
        protocol: PROTOCOL,
        op: c.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: read(&c, options, &paths).unwrap(),
        facts,
        with: c.parse.with.clone(),
    };
    let reply = match c.parse.plugin.as_str() {
        "sshd" => systemlint_sshd::op(request),
        _ => systemlint_formats::op(request),
    }
    .unwrap();
    reply.facts.into_iter().collect()
}

// The sshd facts `sshd -T` and one `sshd -T -C` per account would give, bob’s run settling a `Match User bob`.
fn sshd() -> Map<String, Value> {
    let run = |spec: Option<&str>, stdout: &str| {
        let mut argv = vec!["/usr/sbin/sshd".to_owned(), "-T".to_owned()];
        argv.extend(
            spec.map(|s| {
                [
                    "-C".to_owned(),
                    format!("user={s},host=client.invalid,addr=192.0.2.1"),
                ]
            })
            .into_iter()
            .flatten(),
        );
        Input::Exec(ExecInput {
            argv,
            stdout: stdout.to_owned(),
            stderr: String::new(),
            exit: 0,
        })
    };
    let inputs = vec![
        run(None, GLOBAL),
        run(Some("root"), GLOBAL),
        run(Some("alice"), GLOBAL),
        run(Some("bob"), BOB),
    ];
    systemlint_sshd::server(&inputs)
        .unwrap()
        .facts
        .into_iter()
        .collect()
}

// Every collector this ruleset reads, in the order the core runs them.
fn document() -> Value {
    let options = Options {
        privileged: true,
        root: Root::open(&root()).unwrap(),
        live: false,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
        network: None,
        containers: false,
        target: None,
    };
    let mut document =
        json!({"sshd": sshd(), "collectors": {"sshd": {"status": "ok", "into": "sshd"}}});
    for (id, needs) in [
        ("accounts-passwd", &[][..]),
        ("ssh-authorized-key-files", &["sshd", "accounts.passwd"]),
        ("ssh-authorized-keys", &["ssh.authorized-key-files"]),
    ] {
        let into = collector(id).into;
        let facts = run(id, &options, &document, needs);
        let mut at = &mut document;
        for key in into.split('.') {
            at = &mut at[key];
        }
        *at = Value::Object(facts);
        document["collectors"][id] = json!({"status": "ok", "into": into});
    }
    document
}

fn checks(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &fs::read_to_string(repository().join("rulesets/authorized-keys.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("authorized-keys".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["authorized-keys".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-13")
}

#[test]
fn each_account_gets_the_files_its_own_sshd_run_or_the_global_one_and_tokens_name() {
    let document = document();
    assert_eq!(
        document["ssh"]["authorized-key-files"],
        json!({
            "alice": ["/home/alice/.ssh/authorized_keys", "/etc/ssh/keys/alice"],
            "bob": ["/etc/ssh/bob/bob"],
            "root": ["/root/.ssh/authorized_keys", "/etc/ssh/keys/root"],
            "www": ["/var/www/.ssh/authorized_keys", "/etc/ssh/keys/www"],
        }),
        "www got no run, so sshd’s global AuthorizedKeysFile holds"
    );
    let keys = &document["ssh"]["authorized-keys"];
    assert_eq!(
        keys["bob"]["files"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["/etc/ssh/bob/bob"],
        "bob’s own run names /etc/ssh/bob only, so ~bob/.ssh/authorized_keys is never read"
    );
    assert_eq!(
        keys["root"]["files"]["/root/.ssh/authorized_keys"]["mode"],
        "0600"
    );
    let alice = &keys["alice"]["keys"]["/home/alice/.ssh/authorized_keys:3"];
    assert_eq!(
        (&alice["type"], &alice["bits"]),
        (&json!("ssh-rsa"), &json!(1024))
    );
    assert_eq!(
        keys["alice"]["keys"].as_object().unwrap().len(),
        1,
        "the comment, blank and garbage lines hold no key"
    );
}

#[test]
fn a_short_rsa_and_an_accepted_dsa_key_fail() {
    let checks = checks(&document());
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Unknown),
        "{checks:#?}"
    );
    let failing: Vec<(&str, String)> = checks
        .iter()
        .filter(|c| c.is_failing())
        .map(|c| (c.rule.as_str(), c.subject_label()))
        .collect();
    assert_eq!(
        failing,
        [
            ("authorized-keys/dsa", "/etc/ssh/bob/bob:1".to_owned()),
            (
                "authorized-keys/rsa-size",
                "/home/alice/.ssh/authorized_keys:3".to_owned()
            ),
        ]
    );
}

// A document of one RSA key per size, under a stock RequiredRSASize.
fn sized(sizes: &[u64], required: u64, algorithms: &[&str]) -> Value {
    let keys: Map<String, Value> = sizes
        .iter()
        .map(|b| (b.to_string(), json!({"type": "ssh-rsa", "bits": b})))
        .collect();
    json!({
        "ssh": {"authorized-keys": {"alice": {"files": {}, "keys": keys}}},
        "sshd": {"global": {"/etc/ssh/sshd_config": {"requiredrsasize": required, "pubkeyacceptedalgorithms": algorithms}}},
        "collectors": {"ssh-authorized-keys": {"status": "ok", "into": "ssh.authorized-keys"}, "sshd": {"status": "ok", "into": "sshd"}},
    })
}

fn outcomes(document: &Value, rule: &str) -> Vec<(String, Outcome)> {
    checks(document)
        .into_iter()
        .filter(|c| c.rule == rule)
        .map(|c| (c.subject_label(), c.outcome))
        .collect()
}

#[test]
fn rsa_size_fails_only_what_sshd_accepts_below_2048_bits() {
    let failing = |document: &Value| -> Vec<String> {
        outcomes(document, "authorized-keys/rsa-size")
            .into_iter()
            .filter(|(_, o)| *o == Outcome::Fail)
            .map(|(s, _)| s)
            .collect()
    };
    let document = sized(&[1023, 1024, 2047, 2048], 1024, &["rsa-sha2-512"]);
    assert_eq!(failing(&document), ["1024", "2047"]);
    assert!(
        failing(&sized(&[1024], 1025, &["rsa-sha2-512"])).is_empty(),
        "a raised RequiredRSASize refuses it"
    );
    assert!(
        failing(&sized(&[1024], 1024, &["ssh-ed25519"])).is_empty(),
        "no RSA algorithm accepted"
    );
    let mut absent = sized(&[1024], 1024, &["rsa-sha2-512"]);
    absent.as_object_mut().unwrap().remove("sshd");
    assert_eq!(
        outcomes(&absent, "authorized-keys/rsa-size")[0].1,
        Outcome::Unknown
    );
}

#[test]
fn dsa_is_judged_only_while_sshd_still_accepts_it() {
    let mut document = sized(&[], 1024, &["ssh-ed25519"]);
    document["ssh"]["authorized-keys"]["alice"]["keys"]["k:1"] =
        json!({"type": "ssh-dss", "bits": 1024});
    assert_eq!(
        outcomes(&document, "authorized-keys/dsa"),
        [("k:1".to_owned(), Outcome::Skip)]
    );
    document["sshd"]["global"]["/etc/ssh/sshd_config"]["pubkeyacceptedalgorithms"] =
        json!(["ssh-dss"]);
    assert_eq!(
        outcomes(&document, "authorized-keys/dsa"),
        [("k:1".to_owned(), Outcome::Fail)]
    );
    document["ssh"]["authorized-keys"]["alice"]["keys"]["k:1"]["type"] = json!("ssh-ed25519");
    assert_eq!(
        outcomes(&document, "authorized-keys/dsa"),
        [("k:1".to_owned(), Outcome::Pass)]
    );
}
