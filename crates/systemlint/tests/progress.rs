// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use serde_json::json;
use systemlint::collector::Collector;
use systemlint::progress::{commands, finished};

fn collector(id: &str, exec: Option<&str>) -> Collector {
    let read = exec.map_or_else(
        || "files: [/etc/x]".to_owned(),
        |e| format!("exec: [{}]", e.replace(' ', ", ")),
    );
    systemlint::yaml::from_str(&format!(
        "id: {id}\ninto: {id}\nread: {{{read}}}\nparse: {{plugin: kv, op: parse}}\n"
    ))
    .unwrap()
}

#[test]
fn a_run_under_one_second_ends_silently() {
    assert_eq!(finished(Duration::from_millis(999), &[], &[]), None);
    assert_eq!(
        finished(Duration::from_millis(1000), &[], &[]).as_deref(),
        Some("Collected in 1.0 s.")
    );
    assert_eq!(
        finished(
            Duration::from_millis(2340),
            &["sshd -T".to_owned(), "id".to_owned()],
            &[]
        )
        .as_deref(),
        Some("Collected in 2.3 s; ran sshd -T, id.")
    );
}

#[test]
fn a_run_that_reached_the_network_always_names_its_targets() {
    assert_eq!(
        finished(Duration::ZERO, &[], &["kiota.ch:443".to_owned()]).as_deref(),
        Some("Collected in 0.0 s; asked the network about kiota.ch:443.")
    );
}

#[test]
fn only_a_live_collector_that_ended_ok_ran_its_command() {
    let collectors = [
        collector("sshd", Some("sshd -T")),
        collector("broken", Some("false")),
        collector("files", None),
    ];
    let outcomes =
        json!({"sshd": {"status": "ok"}, "broken": {"status": "error"}, "files": {"status": "ok"}});
    let host = json!({"meta": {"subject": {"kind": "host"}}, "collectors": outcomes});
    assert_eq!(commands(&host, &collectors), ["sshd -T"]);
    let root = json!({"meta": {"subject": {"kind": "root"}}, "collectors": outcomes});
    assert!(
        commands(&root, &collectors).is_empty(),
        "under --root no command runs"
    );
}

#[test]
fn an_exec_from_command_is_named_once_per_fact_map() {
    let sshd: Collector = systemlint::yaml::from_str("id: sshd\ninto: sshd\nread: {exec: [/usr/sbin/sshd, -T], exec-from: {each: accounts.passwd, argv: [/usr/sbin/sshd, -T, -C, 'user={key}']}}\nparse: {plugin: sshd, op: config}\n").unwrap();
    let host =
        json!({"meta": {"subject": {"kind": "host"}}, "collectors": {"sshd": {"status": "ok"}}});
    assert_eq!(
        commands(&host, &[sshd]),
        [
            "/usr/sbin/sshd -T",
            "/usr/sbin/sshd -T -C user={key} per accounts.passwd entry"
        ]
    );
}
