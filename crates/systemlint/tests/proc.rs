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
use systemlint_protocol::{PROTOCOL, Request};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// The processes-services collector read from the fixture root as if live, parsed in-process.
fn services() -> Value {
    let c = Collector::parse(
        &std::fs::read_to_string(repository().join("collectors/processes-services.yaml")).unwrap(),
    )
    .unwrap();
    let options = Options {
        privileged: true,
        root: Root::open(&repository().join("fixtures/services")).unwrap(),
        live: true,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
        network: None,
        containers: false,
    };
    let request = Request {
        protocol: PROTOCOL,
        op: c.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: inputs(&c, &options).unwrap(),
        facts: BTreeMap::new(),
        with: c.parse.with.clone(),
    };
    let reply = systemlint_proc::op(request).unwrap();
    assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
    Value::Object(reply.facts.into_iter().collect())
}

#[test]
fn services_hold_only_the_executable_system_files_deleted_under_them() {
    assert_eq!(
        services(),
        json!({
            "app.service": {"pids": [100, 101], "replaced": ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]},
            "containerd.service": {"pids": [150], "replaced": []},
        }),
        "locale data, memfd and shm are no code, and a container is left out"
    );
}
