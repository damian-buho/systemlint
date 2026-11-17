// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::time::Duration;

use serde_json::json;
use systemlint::judge::{Outcome, compile, lint};
use systemlint::report::lint_textfile_targets;
use systemlint::runner::{Inside, OUTPUT_CAP, bounding, run};
use systemlint::source::Root;
use systemlint::targets::discover;

const A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const C: &str = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffff";

/// Writes one fake process: its cgroup, parent and namespace PIDs.
fn process(root: &Path, pid: u32, ppid: u32, cgroup: &str, nspid: &str) {
    let dir = root.join(format!("proc/{pid}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
    std::fs::write(dir.join("stat"), format!("{pid} (sh) S {ppid} 0 0\n")).unwrap();
    std::fs::write(dir.join("status"), format!("Name:\tsh\nNSpid:\t{nspid}\n")).unwrap();
}

#[test]
fn discover_finds_each_container_once_with_its_parent_and_name() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("targets-discover");
    let _ = std::fs::remove_dir_all(&root);
    process(&root, 1, 0, "/init.scope", "1");
    process(
        &root,
        10,
        5,
        &format!("/system.slice/docker-{A}.scope"),
        "10\t1",
    );
    process(
        &root,
        11,
        10,
        &format!("/system.slice/docker-{A}.scope"),
        "11\t2",
    );
    process(
        &root,
        20,
        11,
        &format!("/system.slice/docker-{A}.scope/docker/{B}"),
        "20\t9\t1",
    );
    process(
        &root,
        30,
        5,
        &format!("/system.slice/docker-{C}.scope"),
        "30\t1",
    );
    let config = root.join(format!("var/lib/docker/containers/{A}"));
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.v2.json"), r#"{"Name": "/outer"}"#).unwrap();
    let namespace = |pid: u32| match pid {
        10 | 30 => Some((1, 10)),
        20 => Some((1, 20)),
        _ => Some((1, 0)),
    };
    let found = discover(&Root::open(&root).unwrap(), &namespace);
    let keys: Vec<(&str, u32, u32, Option<&str>)> = found
        .iter()
        .map(|f| (f.key.as_str(), f.pid, f.inner, f.parent.as_deref()))
        .collect();
    assert_eq!(
        keys,
        [
            ("outer", 10, 1, None),
            ("outer/fedcba987654", 20, 1, Some("outer"))
        ],
        "C shares A’s mount namespace, B is named by its short ID"
    );
    assert_eq!(found[1].subject()["kind"], "container");
}

#[test]
fn a_process_root_reads_proc_self_as_the_container_init() {
    let pid = std::process::id();
    let root = Root::process(pid, pid).unwrap();
    let mine = root.read("/proc/self/status", OUTPUT_CAP).unwrap();
    assert!(String::from_utf8_lossy(&mine).contains(&format!("Pid:\t{pid}\n")));
    assert!(
        root.read("/proc/net/tcp", OUTPUT_CAP).is_ok(),
        "/proc/net names the init’s"
    );
}

#[test]
fn a_command_inside_exits_as_it_did_through_the_middle_process() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let inside = Inside::of(std::process::id(), &status).unwrap();
    assert_eq!(
        inside.namespaces, 0,
        "this process shares its own namespaces"
    );
    assert_eq!(Some(inside.bounding), bounding(&status));
    let first = Path::new("/bin/true");
    // A first wait installs wait-timeout’s SIGCHLD handler, which the middle process inherits.
    run(first, &[], None, Duration::from_secs(600), OUTPUT_CAP, None).unwrap();
    let output = run(
        Path::new("/bin/sh"),
        &["-c", "echo inside; exit 3"],
        None,
        Duration::from_secs(600),
        OUTPUT_CAP,
        Some(inside),
    )
    .unwrap();
    assert_eq!(
        (output.code(), output.stdout.as_slice()),
        (3, &b"inside\n"[..])
    );
}

#[test]
fn a_rule_over_a_host_collector_is_not_applicable_in_a_container() {
    let document = json!({"collectors": {"sysctl": {"status": "skipped", "host": true, "into": "sysctl.settings", "reason": "judged on the host"}}});
    let rule = compile(
        "sysctl/x",
        systemlint::yaml::from_str("fact: sysctl.settings.kernel\nexpect: {const: 1}\n").unwrap(),
    )
    .unwrap();
    let checks = lint(&document, &[rule], &[], "2026-11-16");
    assert_eq!(checks[0].outcome, Outcome::NotApplicable);
}

#[test]
fn textfile_keeps_one_help_per_family_and_labels_each_container() {
    let empty = json!({});
    let text = lint_textfile_targets(&empty, &[], &[("web", &empty, &[])]);
    assert_eq!(
        text.matches("# HELP systemlint_checks ").count(),
        1,
        "{text}"
    );
    assert!(
        text.contains("systemlint_checks{target=\"web\",outcome=\"pass\"} 0"),
        "{text}"
    );
    assert!(
        text.contains("systemlint_privileged{target=\"web\"} 0"),
        "{text}"
    );
    assert!(text.contains("\nsystemlint_privileged 0\n"), "{text}");
}
