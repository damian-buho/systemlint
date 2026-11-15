// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::collector::Collector;
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// The shipped collector's reply to one nft run.
fn run(stdout: &str, exit: i32) -> systemlint_protocol::Result<Value> {
    let collector = Collector::parse(
        &std::fs::read_to_string(repository().join("collectors/nftables.yaml")).unwrap(),
    )
    .unwrap();
    let request = Request {
        protocol: PROTOCOL,
        op: collector.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: vec![Input::Exec(ExecInput {
            argv: collector.read.exec.clone().unwrap(),
            stdout: stdout.to_owned(),
            stderr: "Operation not permitted".to_owned(),
            exit,
        })],
        facts: BTreeMap::new(),
        with: collector.parse.with.clone(),
    };
    let reply = systemlint_firewall::op(request)?;
    assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    Ok(Value::Object(reply.facts.into_iter().collect()))
}

// The hooks of `fixtures/nftables/<name>.json`, captured by `.scripts/capture-nftables-fixture.sh`.
fn hooks(name: &str) -> Value {
    let path = repository().join(format!("fixtures/nftables/{name}.json"));
    run(&std::fs::read_to_string(path).unwrap(), 0).unwrap()
}

#[test]
fn stock_debian_ruleset_filters_nothing() {
    let hooks = hooks("stock");
    for family in ["ipv4", "ipv6"] {
        assert_eq!(
            hooks[family]["input"],
            json!({"policy": "accept", "drops": false, "chains": ["inet filter input"]})
        );
        assert_eq!(
            hooks[family]["prerouting"],
            json!({"policy": "accept", "drops": false, "chains": []})
        );
    }
}

#[test]
fn a_reject_reached_through_jump_then_goto_filters_both_families() {
    let hooks = hooks("jump");
    assert_eq!(hooks["ipv4"]["input"]["drops"], true);
    assert_eq!(hooks["ipv6"]["input"]["drops"], true);
    assert_eq!(hooks["ipv4"]["input"]["policy"], "accept");
}

#[test]
fn an_ip_table_filters_ipv4_alone() {
    let hooks = hooks("ipv4-only");
    assert_eq!(
        hooks["ipv4"]["input"],
        json!({"policy": "drop", "drops": false, "chains": ["ip filter input"]})
    );
    assert_eq!(hooks["ipv6"]["input"]["chains"], json!([]));
}

#[test]
fn forward_drops_leave_input_open_and_a_verdict_map_counts() {
    let hooks = hooks("docker");
    assert_eq!(
        hooks["ipv4"]["input"],
        json!({"policy": "accept", "drops": false, "chains": ["ip filter INPUT"]}),
        "the DOCKER-ISOLATION drop is reached from FORWARD only, and a chain no hook reaches counts nowhere"
    );
    assert_eq!(
        hooks["ipv4"]["forward"],
        json!({"policy": "drop", "drops": true, "chains": ["ip filter FORWARD"]})
    );
    assert_eq!(hooks["ipv6"]["input"]["drops"], true, "23 : drop in a vmap");
    assert_eq!(
        hooks["ipv6"]["forward"]["chains"],
        json!([]),
        "a bridge chain is no IP hook"
    );
}

#[test]
fn a_failed_or_garbled_nft_run_fails_the_op() {
    assert!(run("", 1).is_err(), "nft refused without CAP_NET_ADMIN");
    assert!(run("table inet filter {", 0).is_err());
    assert!(run("{}", 0).is_err());
}

// The nftables ruleset's outcomes by rule over the hooks of a fixture, nftables.service and IPv6's sysctl.
fn judge(name: &str, unit: Value, disable_ipv6: i64) -> Vec<(String, Outcome)> {
    let path = repository().join("rulesets/nftables.yaml");
    let parsed = systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([("nftables".to_owned(), parsed)])).unwrap();
    let rules: Vec<_> = library
        .select(&["nftables".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    let document = json!({
        "nftables": {"hooks": hooks(name)},
        "systemd": {"state": {"nftables.service": unit}},
        "sysctl": {"settings": {"net": {"ipv6": {"conf": {"all": {"disable_ipv6": disable_ipv6}}}}}},
        "collectors": {
            "nftables": {"status": "ok", "into": "nftables.hooks"},
            "systemd-state": {"status": "ok", "into": "systemd.state"},
            "sysctl": {"status": "ok", "into": "sysctl.settings"},
        },
    });
    lint(&document, &rules, &[], "2026-11-15")
        .into_iter()
        .map(|c| (c.rule.clone(), c.outcome))
        .collect()
}

fn unit(enabled: bool, active: &str) -> Value {
    json!({"enabled": enabled, "masked": false, "active": active, "sub": "exited"})
}

#[test]
fn nftables_rules_fail_an_enabled_service_that_filters_nothing() {
    use Outcome::{Fail, NotApplicable, Pass, Skip};
    let outcomes = |name, unit, ipv6| {
        judge(name, unit, ipv6)
            .into_iter()
            .map(|(_, o)| o)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        judge("stock", unit(true, "active"), 0),
        [
            ("nftables/ipv4-input-open".to_owned(), Fail),
            ("nftables/ipv6-input-open".to_owned(), Fail),
            ("nftables/service-failed".to_owned(), Pass),
        ]
    );
    assert_eq!(
        outcomes("stock", unit(false, "inactive"), 0),
        [NotApplicable; 3],
        "a ruleset never loaded is no finding"
    );
    assert_eq!(
        outcomes("stock", unit(true, "active"), 1),
        [Fail, Skip, Pass],
        "IPv6 switched off in the kernel"
    );
    assert_eq!(
        outcomes("ipv4-only", unit(true, "active"), 0),
        [Pass, Fail, Pass]
    );
    assert_eq!(
        outcomes("jump", unit(true, "failed"), 0),
        [Pass, Pass, Fail]
    );
    assert_eq!(
        outcomes("docker", unit(true, "active"), 0),
        [Fail, Pass, Pass]
    );
}
