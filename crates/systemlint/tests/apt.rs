// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{HashKey, Options, inputs, lookup, rfc3339};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{Describe, ExecInput, Input, PROTOCOL, Reply, Request};

// The rules of the apt ruleset a default run selects.
const DEFAULT_RULES: usize = 16;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collector(id: &str) -> Collector {
    Collector::parse(
        &std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap()
}

// Each shipped collector in an order that meets its needs, read through the core and parsed by the plugin library in-process.
fn document(root: &str) -> Value {
    let options = Options {
        privileged: true,
        root: Root::open(&repository().join("fixtures").join(root)).unwrap(),
        live: false,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
        network: None,
        containers: false,
    };
    let mut facts = Map::new();
    let mut outcomes = Map::new();
    for id in [
        "os-release",
        "apt-lists",
        "apt-sources",
        "apt-installed",
        "apt-config",
    ] {
        let c = collector(id);
        let (describe, op): (Describe, fn(Request) -> systemlint_protocol::Result<Reply>) =
            match c.parse.plugin.as_str() {
                "apt" => (systemlint_apt::describe(), systemlint_apt::op),
                _ => (systemlint_formats::describe(), systemlint_formats::op),
            };
        let needs = &describe
            .ops
            .iter()
            .find(|o| o.op == c.parse.op)
            .unwrap()
            .needs;
        let given = needs
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    lookup(&facts, n)
                        .unwrap_or_else(|| panic!("{id} needs {n}"))
                        .clone(),
                )
            })
            .collect();
        let request = Request {
            protocol: PROTOCOL,
            op: c.parse.op.clone(),
            root: "/".to_owned(),
            now: Some(rfc3339(options.now)),
            inputs: match &c.read.exec {
                Some(argv) => vec![captured(root, argv)],
                None => inputs(&c, &options).unwrap(),
            },
            facts: given,
            with: c.parse.with.clone(),
        };
        let reply = op(request).unwrap();
        assert!(
            reply.diagnostics.is_empty(),
            "{id}: {:?}",
            reply.diagnostics
        );
        let (parent, leaf) = c.into.split_once('.').unwrap();
        facts.entry(parent).or_insert_with(|| json!({}))[leaf] =
            Value::Object(reply.facts.into_iter().collect());
        outcomes.insert(id.to_owned(), json!({"status": "ok", "into": c.into}));
    }
    facts.insert("collectors".to_owned(), Value::Object(outcomes));
    Value::Object(facts)
}

// A command collector's input as the fixture's capture holds it (.scripts/capture-apt-config-fixture.sh).
fn captured(root: &str, argv: &[String]) -> Input {
    let path = repository()
        .join("fixtures")
        .join(root)
        .join("apt-config-dump.txt");
    Input::Exec(ExecInput {
        argv: argv.to_vec(),
        stdout: std::fs::read_to_string(path).unwrap(),
        stderr: String::new(),
        exit: 0,
    })
}

fn checks(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &std::fs::read_to_string(repository().join("rulesets/apt.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("apt".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["default".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    assert_eq!(rules.len(), DEFAULT_RULES);
    lint(document, &rules, &[], "2026-11-11")
}

fn failures(document: &Value) -> Vec<Check> {
    let checks = checks(document);
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Unknown),
        "{checks:#?}"
    );
    checks.into_iter().filter(Check::is_failing).collect()
}

#[test]
fn the_apt_rules_apply_to_debian_ubuntu_and_their_derivatives_alone() {
    let mut document = document("apt-misconfigured");
    let judged = failures(&document)
        .iter()
        .filter(|c| c.rule != "apt/security-suite")
        .count();
    for (release, applies) in [
        (json!({"ID": "debian"}), true),
        (json!({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}), true),
        (json!({"ID": "pop", "ID_LIKE": "ubuntu"}), true),
        (json!({"ID": "kali", "ID_LIKE": "debian"}), true),
        (json!({"ID": "fedora"}), false),
        (
            json!({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}),
            false,
        ),
        (json!({"ID": "x", "ID_LIKE": "notdebian ubuntus"}), false),
        (json!({"ID": "debian-like"}), false),
    ] {
        document["os"]["release"] = release.clone();
        let checks = checks(&document);
        let outcomes: Vec<Outcome> = checks.iter().map(|c| c.outcome).collect();
        match applies {
            true => assert_eq!(
                checks
                    .iter()
                    .filter(|c| c.is_failing() && c.rule != "apt/security-suite")
                    .count(),
                judged,
                "{release}: {outcomes:?}"
            ),
            false => assert!(
                checks.len() == DEFAULT_RULES
                    && outcomes.iter().all(|o| *o == Outcome::NotApplicable),
                "{release}: {outcomes:?}"
            ),
        }
    }
    document["os"]["release"] = json!({"ANSI_COLOR": "0;38;2;60;110;180", "ID": "rocky", "ID_LIKE": "rhel centos fedora", "NAME": "Rocky Linux"});
    let reason = checks(&document)[0].reason.clone();
    assert_eq!(
        reason.as_deref(),
        Some(
            "ruleset apt: when os.release.ID is “rocky” and os.release.ID_LIKE is “rhel centos fedora”"
        ),
        "the reason names only the keys the guard reads"
    );
}

#[test]
fn kiota_docker_on_questing_under_resolute_fails_stale_suite_alone() {
    let document = document("ubuntu-26.04");
    assert_eq!(
        document["apt"]["installed"]["docker-ce"]["version"],
        "5:29.4.1-1~ubuntu.25.10~questing"
    );
    let lists = document["apt"]["lists"].as_object().unwrap();
    assert_eq!(
        lists["/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_resolute_InRelease"]["age-days"],
        201
    );
    let failures = failures(&document);
    let found: Vec<(&str, String)> = failures
        .iter()
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    assert_eq!(
        found,
        [(
            "apt/stale-suite",
            "/etc/apt/sources.list.d/docker.sources:5".to_owned()
        )]
    );
    assert!(
        failures[0]
            .message
            .as_deref()
            .unwrap()
            .contains("suite “questing”"),
        "{:?}",
        failures[0].message
    );
    assert_eq!(
        failures[0].fix.as_deref(),
        Some("set the suite to “resolute”, or waive it when the vendor publishes no newer suite")
    );
}

#[test]
fn every_apt_rule_fails_once_on_the_misconfigured_root_and_a_disabled_source_is_skipped() {
    let failures = failures(&document("apt-misconfigured"));
    let found: Vec<(&str, String)> = failures
        .iter()
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    let (list, mirror) = (
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d/mirror.list:5",
    );
    let mut expected = [
        ("apt/allow-downgrade-to-insecure", String::new()),
        ("apt/allow-insecure-repositories", String::new()),
        ("apt/allow-unauthenticated", String::new()),
        ("apt/allow-weak-repositories", String::new()),
        ("apt/check-date-off", String::new()),
        ("apt/duplicate", format!("{list}:5")),
        ("apt/duplicate", mirror.to_owned()),
        ("apt/https", format!("{list}:5")),
        ("apt/insecure-options", format!("{list}:7")),
        ("apt/key-conflict", format!("{list}:5")),
        ("apt/key-conflict", format!("{list}:6")),
        ("apt/key-conflict", format!("{list}:7")),
        ("apt/key-conflict", mirror.to_owned()),
        ("apt/shared-keyring", format!("{list}:6")),
        ("apt/security-suite", String::new()),
        ("apt/signed-by", format!("{list}:5")),
        (
            "apt/stale-release",
            "/etc/apt/sources.list.d/expired.sources:5".to_owned(),
        ),
        ("apt/stale-suite", format!("{list}:9")),
        ("apt/stale-uri", format!("{list}:10")),
        ("apt/versioned-uri", format!("{list}:8")),
    ];
    let mut sorted = found.clone();
    sorted.sort();
    expected.sort();
    assert_eq!(sorted, expected);
    assert!(!found.iter().any(|(_, s)| s.contains("off.sources")));
    let fix = |rule: &str| {
        failures
            .iter()
            .find(|c| c.rule == rule)
            .and_then(|c| c.fix.clone())
            .unwrap()
    };
    assert_eq!(
        fix("apt/stale-suite"),
        "set the suite to “llvm-toolchain-resolute-22”, or waive it when the vendor publishes no newer suite"
    );
    assert_eq!(
        fix("apt/stale-uri"),
        "point the source at “https://download.opensuse.org/repositories/devel:/languages:/crystal/xUbuntu_26.04/”, or waive it when the vendor publishes no build for this release"
    );
}
