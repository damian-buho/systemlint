// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{HashKey, Named, Options, named, read};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{PROTOCOL, Request};

const PASSWD: &str = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\n";
const GROUP: &str = "root:x:0:\nalice:x:1000:\nbob:x:1001:\nops:x:2000:alice\n";
const SSHD: &str = "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\nPubkeyAcceptedAlgorithms +ssh-dss\nMatch User bob\n  AuthorizedKeysFile /etc/ssh/bob/%u\nMatch Group ops Address 192.0.2.0/24\n  AuthorizedKeysFile /etc/ssh/ops/%U\n";
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

// A root holding the accounts, the sshd config and the key files, rebuilt on every run.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("authorized-keys-root");
    let alice = format!("# laptop\n\n{RSA1024}\nnot a key at all\n");
    let entries: [(&str, Option<&str>, u32); 16] = [
        ("etc", None, 0o755),
        ("etc/passwd", Some(PASSWD), 0o644),
        ("etc/group", Some(GROUP), 0o644),
        ("etc/ssh", None, 0o755),
        ("etc/ssh/sshd_config", Some(SSHD), 0o644),
        ("etc/ssh/bob", None, 0o755),
        ("etc/ssh/bob/bob", Some(&dsa()), 0o644),
        ("root", None, 0o700),
        ("root/.ssh", None, 0o700),
        ("root/.ssh/authorized_keys", Some(ED25519), 0o600),
        ("home", None, 0o755),
        ("home/alice", None, 0o750),
        ("home/alice/.ssh", None, 0o700),
        ("home/alice/.ssh/authorized_keys", Some(&alice), 0o600),
        ("home/bob/.ssh", None, 0o700),
        ("home/bob/.ssh/authorized_keys", Some(ED25519), 0o600),
    ];
    for (path, content, mode) in entries {
        let full = root.join(path);
        match content {
            Some(text) => {
                if full.exists() {
                    fs::set_permissions(&full, fs::Permissions::from_mode(0o600)).unwrap();
                }
                fs::write(&full, text).unwrap();
            }
            None => fs::create_dir_all(&full).unwrap(),
        }
        fs::set_permissions(&full, fs::Permissions::from_mode(mode)).unwrap();
    }
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
    };
    let reply = match c.parse.plugin.as_str() {
        "sshd" => systemlint_sshd::op(request),
        _ => systemlint_formats::op(request),
    }
    .unwrap();
    reply.facts.into_iter().collect()
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
    };
    let mut document = json!({"apt": {"installed": {"openssh-server": {"version": "1:9.6p1-3ubuntu13.20"}}}, "collectors": {}});
    for (id, needs) in [
        ("accounts-passwd", &[][..]),
        ("accounts-group", &[]),
        ("sshd", &["apt.installed"]),
        (
            "ssh-authorized-key-files",
            &["apt.installed", "accounts.passwd", "accounts.group"],
        ),
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
fn each_account_gets_the_files_its_match_blocks_and_tokens_name() {
    let document = document();
    assert_eq!(
        document["ssh"]["authorized-key-files"],
        json!({
            "alice": ["/etc/ssh/ops/1000", "/home/alice/.ssh/authorized_keys", "/etc/ssh/keys/alice"],
            "bob": ["/etc/ssh/bob/bob"],
            "root": ["/root/.ssh/authorized_keys", "/etc/ssh/keys/root"],
        })
    );
    let keys = &document["ssh"]["authorized-keys"];
    assert_eq!(
        keys["bob"]["files"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["/etc/ssh/bob/bob"],
        "bob’s Match block always applies, so ~bob/.ssh/authorized_keys is never read"
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
        "sshd": {"contexts": {"/etc/ssh/sshd_config": {"requiredrsasize": required, "pubkeyacceptedalgorithms": algorithms}}},
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
    document["sshd"]["contexts"]["/etc/ssh/sshd_config"]["pubkeyacceptedalgorithms"] =
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
