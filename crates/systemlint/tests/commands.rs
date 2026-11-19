// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::collector::Collector;
use systemlint_protocol::{ExecInput, Input, PROTOCOL, Request};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// The shipped collector `id`’s parse of the captured `fixtures/<file>.txt`, diagnostics included.
fn parsed(id: &str, file: &str) -> (Value, usize) {
    let collector = Collector::parse(
        &std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
    )
    .unwrap();
    let stdout =
        std::fs::read_to_string(repository().join(format!("fixtures/{file}.txt"))).unwrap();
    let request = Request {
        protocol: PROTOCOL,
        op: collector.parse.op.clone(),
        root: "/".to_owned(),
        now: None,
        inputs: vec![Input::Exec(ExecInput {
            argv: collector.read.exec.clone().unwrap(),
            stdout,
            stderr: String::new(),
            exit: 0,
        })],
        facts: BTreeMap::new(),
        with: collector.parse.with.clone(),
    };
    let reply = systemlint_formats::op(request).unwrap();
    (
        Value::Object(reply.facts.into_iter().collect()),
        reply.diagnostics.len(),
    )
}

#[test]
fn tcp_owners_are_keyed_by_port_with_the_first_program() {
    let (facts, diagnostics) = parsed("ports-owners-tcp", "ports/ss-tcp");
    assert_eq!(
        facts,
        json!({
            "22": {"program": "sshd"},
            "53": {"program": "systemd-resolve"},
            "80": {"program": "nginx"},
        }),
        "IPv4 and IPv6 of one service are one fact; a socket without a process is left out"
    );
    assert_eq!(diagnostics, 0, "a repeated port of one program is no clash");
}

#[test]
fn udp_owners_are_keyed_by_port_with_the_first_program() {
    let (facts, diagnostics) = parsed("ports-owners-udp", "ports/ss-udp");
    assert_eq!(
        facts,
        json!({"5353": {"program": "avahi-daemon"}, "323": {"program": "chronyd"}})
    );
    assert_eq!(diagnostics, 0);
}

#[test]
fn running_processes_are_listed_per_command_name() {
    let (facts, diagnostics) = parsed("processes-running", "processes/ps");
    assert_eq!(diagnostics, 0, "{facts}");
    let pids: Vec<_> = facts["chronyd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["pid"].clone(), p["ppid"].clone(), p["user"].clone()))
        .collect();
    assert_eq!(
        pids,
        [
            (json!(650), json!(1), json!("_chrony")),
            (json!(655), json!(650), json!("_chrony"))
        ],
        "a name run twice keeps every process"
    );
    assert_eq!(facts["tmux:"][0]["more"], json!(["server"]), "{facts}");
}
