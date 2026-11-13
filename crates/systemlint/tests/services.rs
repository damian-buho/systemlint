// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Value, json};
use systemlint::collect::{HashKey, Options, inputs};
use systemlint::collector::Collector;
use systemlint::source::Root;
use systemlint_protocol::{Input, PROTOCOL, Request};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// One shipped collector read from the fixture root under --root and parsed by the formats library in-process.
fn facts(id: &str) -> Value {
    let c = Collector::parse(
        &std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap();
    let options = Options {
        privileged: true,
        root: Root::open(&repository().join("fixtures/services")).unwrap(),
        live: false,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
    };
    let given = inputs(&c, &options).unwrap();
    assert!(
        given.iter().all(|i| matches!(i, Input::File(_))),
        "exec never runs under --root"
    );
    let reply = systemlint_formats::op(Request {
        protocol: PROTOCOL,
        op: c.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: given,
        facts: BTreeMap::new(),
    })
    .unwrap();
    assert!(
        reply.diagnostics.is_empty(),
        "{id}: {:?}",
        reply.diagnostics
    );
    Value::Object(reply.facts.into_iter().collect())
}

#[test]
fn sysctl_under_root_applies_the_files_in_systemd_order() {
    let sysctl = facts("sysctl");
    assert_eq!(sysctl["source"], "files");
    assert_eq!(
        sysctl["settings"],
        json!({"kernel": {"kptr_restrict": 1}, "net": {"ipv4": {"ip_forward": 1}}})
    );
}

#[test]
fn ufw_conf_and_binary_land_where_the_ufw_ruleset_reads_them() {
    assert_eq!(facts("ufw"), json!({"ENABLED": "no", "LOGLEVEL": "low"}));
    assert_eq!(
        facts("ufw-binary")
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["/usr/sbin/ufw"]
    );
}

#[test]
fn docker_daemon_json_lands_as_is() {
    assert_eq!(
        facts("docker-daemon"),
        json!({"icc": false, "live-restore": true, "insecure-registries": ["registry.lan:5000"]})
    );
}

#[test]
fn systemd_units_are_keyed_by_path_and_a_masked_unit_is_skipped() {
    let units = facts("systemd-units");
    let paths: Vec<&String> = units.as_object().unwrap().keys().collect();
    assert_eq!(
        paths,
        [
            "/etc/systemd/system/app.service.d/override.conf",
            "/usr/lib/systemd/system/app.service",
            "/usr/lib/systemd/system/clean.service"
        ]
    );
    assert_eq!(
        units["/usr/lib/systemd/system/app.service"]["Service"]["EnvironmentFile"],
        json!(["-/etc/default/app"])
    );
}

#[test]
fn systemd_state_reads_wants_links_and_masks_under_root() {
    assert_eq!(
        facts("systemd-state"),
        json!({
            "app.service": {"enabled": true, "masked": false},
            "clean.service": {"enabled": false, "masked": false},
            "clean.timer": {"enabled": true, "masked": false},
            "masked.service": {"enabled": false, "masked": true},
        })
    );
}
