// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{Options, inputs, lookup, rfc3339};
use systemlint::collector::Collector;
use systemlint::judge::{Check, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{Describe, PROTOCOL, Reply, Request};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collector(id: &str) -> Collector {
    Collector::parse(&std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap()).unwrap()
}

// Each shipped collector in an order that meets its needs, read through the core and parsed by the plugin library in-process.
fn document(root: &str) -> Value {
    let options = Options { root: Root::open(&repository().join("fixtures").join(root)).unwrap(), live: false, now: UNIX_EPOCH + Duration::from_secs(1_794_398_400), timeout: Duration::from_secs(60) };
    let mut facts = Map::new();
    let mut outcomes = Map::new();
    for id in ["os-release", "apt-lists", "apt-sources", "apt-installed"] {
        let c = collector(id);
        let (describe, op): (Describe, fn(Request) -> systemlint_protocol::Result<Reply>) = match c.parse.plugin.as_str() {
            "apt" => (systemlint_apt::describe(), systemlint_apt::op),
            _ => (systemlint_formats::describe(), systemlint_formats::op),
        };
        let needs = &describe.ops.iter().find(|o| o.op == c.parse.op).unwrap().needs;
        let given = needs.iter().map(|n| (n.clone(), lookup(&facts, n).unwrap_or_else(|| panic!("{id} needs {n}")).clone())).collect();
        let request = Request { protocol: PROTOCOL, op: c.parse.op.clone(), root: "/".to_owned(), now: Some(rfc3339(options.now)), inputs: inputs(&c, &options).unwrap(), facts: given };
        let reply = op(request).unwrap();
        assert!(reply.diagnostics.is_empty(), "{id}: {:?}", reply.diagnostics);
        let (parent, leaf) = c.into.split_once('.').unwrap();
        facts.entry(parent).or_insert_with(|| json!({}))[leaf] = Value::Object(reply.facts.into_iter().collect());
        outcomes.insert(id.to_owned(), json!({"status": "ok", "into": c.into}));
    }
    facts.insert("collectors".to_owned(), Value::Object(outcomes));
    Value::Object(facts)
}

fn failures(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(&std::fs::read_to_string(repository().join("rulesets/apt.yaml")).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([("apt".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library.select(&["apt".to_owned()]).unwrap().into_iter().map(|(id, spec)| compile(&id, spec).unwrap()).collect();
    assert_eq!(rules.len(), 9);
    let checks = lint(document, &rules, &[], "2026-11-11");
    assert!(checks.iter().all(|c| c.outcome != systemlint::judge::Outcome::Unknown), "{checks:#?}");
    checks.into_iter().filter(Check::is_failing).collect()
}

#[test]
fn kiota_docker_on_questing_under_resolute_fails_stale_suite_alone() {
    let document = document("ubuntu-26.04");
    assert_eq!(document["apt"]["installed"]["docker-ce"]["version"], "5:29.4.1-1~ubuntu.25.10~questing");
    let lists = document["apt"]["lists"].as_object().unwrap();
    assert_eq!(lists["/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_resolute_InRelease"]["age-days"], 201);
    let failures = failures(&document);
    let found: Vec<(&str, String)> = failures.iter().map(|c| (c.rule.as_str(), c.subject_text())).collect();
    assert_eq!(found, [("apt/stale-suite", "/etc/apt/sources.list.d/docker.sources:5".to_owned())]);
    assert!(failures[0].message.as_deref().unwrap().contains("suite “questing”"), "{:?}", failures[0].message);
}

#[test]
fn every_apt_rule_fails_once_on_the_misconfigured_root_and_a_disabled_source_is_skipped() {
    let failures = failures(&document("apt-misconfigured"));
    let found: Vec<(&str, String)> = failures.iter().map(|c| (c.rule.as_str(), c.subject_text())).collect();
    let (list, mirror) = ("/etc/apt/sources.list", "/etc/apt/sources.list.d/mirror.list:5");
    let mut expected = [
        ("apt/duplicate", format!("{list}:5")),
        ("apt/duplicate", mirror.to_owned()),
        ("apt/https", format!("{list}:5")),
        ("apt/insecure-options", format!("{list}:7")),
        ("apt/key-conflict", format!("{list}:5")),
        ("apt/key-conflict", format!("{list}:6")),
        ("apt/key-conflict", format!("{list}:7")),
        ("apt/key-conflict", mirror.to_owned()),
        ("apt/shared-keyring", format!("{list}:6")),
        ("apt/signed-by", format!("{list}:5")),
        ("apt/stale-release", "/etc/apt/sources.list.d/expired.sources:5".to_owned()),
        ("apt/versioned-uri", format!("{list}:8")),
    ];
    let mut sorted = found.clone();
    sorted.sort();
    expected.sort();
    assert_eq!(sorted, expected);
    assert!(!found.iter().any(|(_, s)| s.contains("off.sources")));
}
