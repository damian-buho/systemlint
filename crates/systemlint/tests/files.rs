// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{HashKey, Options, inputs, named, read};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint::vars::{Supplied, apply};
use systemlint_protocol::{PROTOCOL, Request};

const COLLECTORS: [&str; 16] = [
    "files-shadow",
    "files-libraries",
    "files-commands",
    "files-sudoers",
    "files-cron",
    "files-sshd",
    "files-ssh-host-keys",
    "files-apt-keyrings",
    "files-path",
    "files-accounts",
    "files-apt-sources",
    "files-apt-auth",
    "files-boot",
    "files-init",
    "files-audit-config",
    "files-audit-tools",
];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// A root whose modes git cannot keep, rebuilt with explicit modes on every run.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("files-root");
    let entries: [common::Entry; 19] = [
        ("etc", None, 0o755),
        ("etc/passwd", Some("root:x:0:0::/root:/bin/sh\n"), 0o644),
        ("etc/apt", None, 0o755),
        ("etc/apt/auth.conf.d", None, 0o755),
        (
            "etc/apt/auth.conf.d/private.conf",
            Some("machine example.invalid login a password b\n"),
            0o644,
        ),
        ("etc/shadow", Some(""), 0o640),
        ("etc/gshadow", Some(""), 0o640),
        ("etc/sudoers", Some("root ALL=(ALL) ALL\n"), 0o440),
        ("etc/sudoers.d", None, 0o750),
        (
            "etc/sudoers.d/deploy",
            Some("deploy ALL=(ALL) NOPASSWD: ALL\n"),
            0o666,
        ),
        ("etc/ssh", None, 0o755),
        ("etc/ssh/sshd_config", Some("PermitRootLogin no\n"), 0o644),
        ("etc/ssh/ssh_host_ed25519_key", Some("private\n"), 0o644),
        ("etc/ssh/ssh_host_ed25519_key.pub", Some("public\n"), 0o644),
        ("etc/crontab", Some(""), 0o644),
        ("etc/init.d", None, 0o755),
        ("etc/init.d/ssh", Some("#!/bin/sh\n"), 0o757),
        ("usr", None, 0o755),
        ("usr/bin", None, 0o755),
    ];
    common::build(&root, &entries);
    root
}

// The options every files test reads its root with.
fn options() -> Options {
    Options {
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
    }
}

// Each files collector read through the core and parsed by the formats library in-process.
fn document() -> Value {
    let options = options();
    let (mut groups, mut outcomes) = (Map::new(), Map::new());
    for id in COLLECTORS {
        let c = Collector::parse(
            &fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
        )
        .unwrap();
        let request = Request {
            protocol: PROTOCOL,
            op: c.parse.op.clone(),
            root: "/".to_owned(),
            now: None,
            inputs: inputs(&c, &options).unwrap(),
            facts: BTreeMap::new(),
            with: c.parse.with.clone(),
        };
        let reply = systemlint_formats::op(request).unwrap();
        assert!(
            reply.diagnostics.is_empty(),
            "{id}: {} diagnostics",
            reply.diagnostics.len()
        );
        groups.insert(
            c.into.strip_prefix("files.").unwrap().to_owned(),
            Value::Object(reply.facts.into_iter().collect()),
        );
        outcomes.insert(id.to_owned(), json!({"status": "ok", "into": c.into}));
    }
    json!({"files": groups, "collectors": outcomes})
}

fn checks(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &fs::read_to_string(repository().join("rulesets/files.yaml")).unwrap(),
    )
    .unwrap();
    let mut rulesets = BTreeMap::from([("files".to_owned(), ruleset)]);
    let supplied = Supplied {
        env: |_| None,
        ..Supplied::default()
    };
    apply(&mut rulesets, &supplied).unwrap();
    let library = Library::new(rulesets).unwrap();
    let rules: Vec<_> = library
        .select(&["files".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    assert_eq!(rules.len(), 17);
    lint(document, &rules, &[], "2026-11-11")
}

#[test]
fn a_0644_host_key_and_a_0666_sudoers_drop_in_fail_and_nothing_else_does() {
    let mut document = document();
    document["accounts"] = json!({"group": {"shadow": {"gid": 42}}});
    assert_eq!(
        document["files"]["sudoers"]["/etc/sudoers.d/deploy"]["mode"],
        "0666"
    );
    assert_eq!(
        document["files"]["cron"].as_object().unwrap().len(),
        1,
        "a missing cron.d is no subject"
    );
    let checks = checks(&document);
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Unknown),
        "{checks:#?}"
    );
    let found: Vec<(&str, String)> = checks
        .iter()
        .filter(|c| {
            c.is_failing()
                && !["files/owner", "files/accounts-group", "files/shadow-group"]
                    .contains(&c.rule.as_str())
        })
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    assert_eq!(
        found,
        [
            (
                "files/apt-auth-readable",
                "/etc/apt/auth.conf.d/private.conf".to_owned()
            ),
            (
                "files/group-writable",
                "sudoers, /etc/sudoers.d/deploy".to_owned()
            ),
            (
                "files/ssh-host-key-mode",
                "/etc/ssh/ssh_host_ed25519_key".to_owned()
            ),
            ("files/world-writable", "init, /etc/init.d/ssh".to_owned()),
            (
                "files/world-writable",
                "sudoers, /etc/sudoers.d/deploy".to_owned()
            ),
        ]
    );
    let host_key = checks
        .iter()
        .find(|c| c.rule == "files/ssh-host-key-mode" && c.is_failing())
        .unwrap();
    assert!(
        host_key.message.as_deref().unwrap().contains("mode “0644”"),
        "{:?}",
        host_key.message
    );
    let root = rustix::process::geteuid().is_root();
    let owners: Vec<_> = checks.iter().filter(|c| c.rule == "files/owner").collect();
    assert_eq!(owners.len(), 16);
    assert!(
        owners.iter().all(|c| c.is_failing() != root),
        "a test file is owned by the runner: root passes, anyone else fails"
    );
}

#[test]
fn the_shadow_and_host_key_patterns_take_0640_or_stricter_at_every_edge() {
    let mut document = json!({"files": {"shadow": {}}, "collectors": {"files-shadow": {"status": "ok", "into": "files.shadow"}}});
    for mode in [
        "0000", "0400", "0600", "0640", "0200", "0644", "0660", "0740", "0641", "4640", "0650",
    ] {
        document["files"]["shadow"][mode] =
            json!({"mode": mode, "uid": 0, "world-writable": false, "group-writable": false});
    }
    let failing: Vec<String> = checks(&document)
        .into_iter()
        .filter(|c| c.rule == "files/shadow-mode" && c.is_failing())
        .map(|c| c.subject_text())
        .collect();
    assert_eq!(failing, ["0641", "0644", "0650", "0660", "0740", "4640"]);
}

#[test]
fn each_mode_cap_fails_the_first_mode_beyond_it_and_leaves_symlinks_alone() {
    let cases = [
        (
            "accounts",
            "files/accounts-mode",
            ["0644", "0444", "0600"],
            ["0645", "0654", "0744", "2644"],
        ),
        (
            "apt-auth",
            "files/apt-auth-readable",
            ["0640", "0603", "0600"],
            ["0644", "0604", "0605", "0607"],
        ),
        (
            "boot",
            "files/bootloader-readable",
            ["0600", "0400", "0700"],
            ["0610", "0601", "0640", "4600"],
        ),
        (
            "audit-config",
            "files/audit-config-mode",
            ["0640", "0600", "0440"],
            ["0641", "0644", "0650", "0740"],
        ),
    ];
    for (group, rule, pass, fail) in cases {
        let mut document = json!({"files": {group: {"/link": {"kind": "symlink", "mode": "0777", "uid": 0, "world-writable": false, "group-writable": false}}}, "collectors": {format!("files-{group}"): {"status": "ok", "into": format!("files.{group}")}}});
        for mode in pass.iter().chain(fail.iter()) {
            document["files"][group][*mode] = json!({"kind": "file", "mode": mode, "uid": 0, "world-writable": false, "group-writable": false});
        }
        let judged: Vec<(String, Outcome)> = checks(&document)
            .into_iter()
            .filter(|c| c.rule == rule)
            .map(|c| (c.subject_text(), c.outcome))
            .collect();
        for mode in pass {
            assert!(
                judged.contains(&(mode.to_owned(), Outcome::Pass)),
                "{rule} at {mode}: {judged:?}"
            );
        }
        for mode in fail {
            assert!(
                judged.contains(&(mode.to_owned(), Outcome::Fail)),
                "{rule} at {mode}: {judged:?}"
            );
        }
        assert!(
            judged.contains(&("/link".to_owned(), Outcome::Skip)),
            "{rule} on a symlink: {judged:?}"
        );
    }
}

#[test]
fn a_writable_library_or_python_path_entry_fails_the_files_rules_and_a_relative_one_is_left_to_env()
{
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("search-path-root");
    common::build(
        &root,
        &[
            ("opt", None, 0o755),
            ("opt/lib", None, 0o777),
            ("opt/py", None, 0o755),
        ],
    );
    let options = Options {
        root: Root::open(&root).unwrap(),
        ..options()
    };
    let c = Collector::parse(
        &fs::read_to_string(repository().join("collectors/files-search-path.yaml")).unwrap(),
    )
    .unwrap();
    let facts = json!({"env": {"units": {"app.service": {"library-path": ["/opt/lib", "", "rel"], "python-path": ["/opt/py"]}}, "files": {}, "defaults": {}}});
    let outcomes = Map::new();
    let paths = named(&c, &[], facts.as_object().unwrap(), &outcomes).unwrap();
    let request = Request {
        protocol: PROTOCOL,
        op: c.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: read(&c, &options, &paths).unwrap(),
        facts: BTreeMap::new(),
        with: c.parse.with.clone(),
    };
    let reply = systemlint_formats::op(request).unwrap();
    assert_eq!(
        reply.facts.keys().collect::<Vec<_>>(),
        ["/opt/lib", "/opt/py"]
    );
    let document = json!({"files": {"search-path": reply.facts}, "collectors": {"files-search-path": {"status": "ok", "into": c.into}}});
    let checks = checks(&document);
    let failing: Vec<(&str, String)> = checks
        .iter()
        .filter(|c| c.is_failing() && c.rule != "files/owner")
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    assert_eq!(
        failing,
        [
            ("files/group-writable", "search-path, /opt/lib".to_owned()),
            ("files/world-writable", "search-path, /opt/lib".to_owned())
        ]
    );
}
