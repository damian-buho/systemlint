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

const PASSWD: &str = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\nsvc:x:999:999::/nonexistent:/usr/sbin/nologin\nodd:x:998:998::/etc/passwd:/usr/sbin/nologin\nrel:x:997:997::relative:/bin/sh\n";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// A root of three homes with explicit modes, rebuilt on every run.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ssh-user-root");
    let entries: [(&str, Option<&str>, u32); 13] = [
        ("etc", None, 0o755),
        ("etc/passwd", Some(PASSWD), 0o644),
        ("root", None, 0o700),
        ("root/.ssh", None, 0o700),
        ("root/.ssh/authorized_keys", Some(""), 0o600),
        ("home", None, 0o755),
        ("home/alice", None, 0o750),
        ("home/alice/.ssh", None, 0o755),
        ("home/alice/.ssh/authorized_keys", Some(""), 0o666),
        ("home/alice/.ssh/id_ed25519.pub", Some(""), 0o644),
        ("home/bob", None, 0o755),
        ("home/bob/.ssh", None, 0o700),
        ("home/bob/.ssh/known_hosts", Some(""), 0o644),
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
    let link = root.join("home/alice/.ssh/config");
    if fs::symlink_metadata(&link).is_err() {
        std::os::unix::fs::symlink("/elsewhere/config", &link).unwrap();
    }
    root
}

// One collector’s request through the core, parsed by the formats library in-process.
fn run(id: &str, options: &Options, named: &Named) -> Map<String, Value> {
    let c = Collector::parse(
        &fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap();
    let request = Request {
        protocol: PROTOCOL,
        op: c.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: read(&c, options, named).unwrap(),
        facts: BTreeMap::new(),
        with: Default::default(),
    };
    systemlint_formats::op(request)
        .unwrap()
        .facts
        .into_iter()
        .collect()
}

// The passwd facts, then each ssh-user collector over the homes they name.
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
    };
    let mut document =
        json!({"accounts": {"passwd": run("accounts-passwd", &options, &Named::default())}});
    let mut outcomes = json!({"accounts-passwd": {"status": "ok", "into": "accounts.passwd"}});
    for (id, group) in [
        ("ssh-user-directories", "directories"),
        ("ssh-user-files", "files"),
    ] {
        let c = Collector::parse(
            &fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
        )
        .unwrap();
        let paths = named(
            &c,
            std::slice::from_ref(&c),
            document.as_object().unwrap(),
            outcomes.as_object().unwrap(),
        )
        .unwrap();
        document["ssh-user"][group] = Value::Object(run(id, &options, &paths));
        outcomes[id] = json!({"status": "ok", "into": c.into});
    }
    document["collectors"] = outcomes;
    document
}

// The checks of the selected ssh-user rules over a document.
fn checks(document: &Value, selector: &str) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &fs::read_to_string(repository().join("rulesets/ssh-user.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("ssh-user".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&[selector.to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-13")
}

#[test]
fn every_home_s_ssh_is_stated_and_only_open_or_world_writable_entries_fail() {
    let document = document();
    let keys = |group: &str| -> Vec<String> {
        document["ssh-user"][group]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(
        keys("directories"),
        ["/home/alice/.ssh", "/home/bob/.ssh", "/root/.ssh"],
        "an absent, file or relative home names nothing"
    );
    assert_eq!(
        keys("files"),
        [
            "/home/alice/.ssh/authorized_keys",
            "/home/alice/.ssh/config",
            "/home/alice/.ssh/id_ed25519.pub",
            "/home/bob/.ssh/known_hosts",
            "/root/.ssh/authorized_keys",
        ]
    );
    let checks = checks(&document, "ssh-user");
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Unknown),
        "{checks:#?}"
    );
    let failing: Vec<(&str, String)> = checks
        .iter()
        .filter(|c| c.is_failing())
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    assert_eq!(
        failing,
        [
            ("ssh-user/directory-mode", "/home/alice/.ssh".to_owned()),
            (
                "ssh-user/world-writable",
                "files, /home/alice/.ssh/authorized_keys".to_owned()
            ),
        ],
        "a symlink’s booleans are false, so config passes"
    );
}

#[test]
fn the_directory_mode_takes_any_owner_and_group_bits_and_no_bit_for_others() {
    let mut document = json!({"ssh-user": {"directories": {}}, "collectors": {"ssh-user-directories": {"status": "ok", "into": "ssh-user.directories"}}});
    for mode in [
        "0700", "0750", "0770", "2770", "0000", "0701", "0704", "0755", "1707",
    ] {
        document["ssh-user"]["directories"][mode] = json!({"mode": mode, "world-writable": false});
    }
    let failing: Vec<String> = checks(&document, "ssh-user/directory-mode")
        .into_iter()
        .filter(|c| c.is_failing())
        .map(|c| c.subject_text())
        .collect();
    assert_eq!(failing, ["0701", "0704", "0755", "1707"]);
}
