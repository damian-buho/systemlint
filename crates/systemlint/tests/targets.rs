// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::report::{lint_human_targets, lint_textfile_targets};
use systemlint::runner::{Inside, OUTPUT_CAP, bounding, run};
use systemlint::source::Root;
use systemlint::targets::{changed, discover};

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
fn a_rule_over_an_absent_program_is_not_applicable_and_over_a_refused_read_not_run() {
    let rule = compile(
        "ssh/x",
        systemlint::yaml::from_str("fact: sshd.global\nexpect: {const: 1}\n").unwrap(),
    )
    .unwrap();
    let outcome = |sshd: Value| {
        lint(
            &json!({"collectors": {"sshd": sshd}}),
            std::slice::from_ref(&rule),
            &[],
            "2026-11-16",
        )[0]
        .outcome
    };
    let absent = json!({"status": "skipped", "absent": true, "into": "sshd", "reason": "needs /usr/sbin/sshd, which is not installed"});
    assert_eq!(outcome(absent), Outcome::NotApplicable);
    let refused = json!({"status": "skipped", "into": "sshd", "reason": "can’t run /usr/sbin/sshd without root"});
    assert_eq!(outcome(refused), Outcome::Unknown);
}

#[test]
fn human_prints_one_block_per_rule_across_targets_and_names_where_it_holds() {
    let rule = compile(
        "x/mode",
        systemlint::yaml::from_str("title: Open file\nfact: files.*\nexpect: {const: 0}\n")
            .unwrap(),
    )
    .unwrap();
    let doc = |files: Value| json!({"files": files});
    let (open, other, shut) = (
        doc(json!({"/a": 1})),
        doc(json!({"/b": 1})),
        doc(json!({"/a": 0})),
    );
    let judged = |d: &Value| lint(d, std::slice::from_ref(&rule), &[], "2026-11-16");
    let (host, a, b, c, d) = (
        judged(&open),
        judged(&open),
        judged(&open),
        judged(&other),
        judged(&shut),
    );
    let targets = [
        ("a", &open, a.as_slice()),
        ("b", &open, b.as_slice()),
        ("c", &other, c.as_slice()),
        ("d", &shut, d.as_slice()),
    ];
    let text = lint_human_targets(&open, &host, 0, &targets, (false, false, false));
    assert_eq!(text.matches("[x/mode] Open file").count(), 1, "{text}");
    assert!(text.contains("In the host, a, b:\n- /a"), "{text}");
    assert!(text.contains("In c:\n- /b"), "{text}");
    assert!(
        text.contains("\nhost  "),
        "one summary row per target: {text}"
    );
    assert!(text.contains("\nd     "), "{text}");
    let most = [
        ("a", &open, a.as_slice()),
        ("b", &open, b.as_slice()),
        ("d", &shut, d.as_slice()),
    ];
    let text = lint_human_targets(&open, &host, 0, &most, (true, false, false));
    assert!(
        text.contains("In the host and every container but d:\n"),
        "{text}"
    );
    let all = [("a", &open, a.as_slice())];
    let text = lint_human_targets(&open, &host, 0, &all, (true, false, false));
    assert!(
        text.contains("In the host and every container:\n"),
        "{text}"
    );
}

#[test]
fn changed_lists_a_writable_layer_as_the_container_sees_it() {
    let upper = Path::new(env!("CARGO_TARGET_TMPDIR")).join("targets-upper");
    let _ = std::fs::remove_dir_all(&upper);
    std::fs::create_dir_all(upper.join("etc/pam.d")).unwrap();
    std::fs::write(upper.join("etc/pam.d/su"), "").unwrap();
    let paths = changed(upper.to_str().unwrap()).unwrap();
    assert_eq!(paths, ["/etc", "/etc/pam.d", "/etc/pam.d/su"]);
    assert_eq!(changed("/nonexistent/systemlint-upper"), None);
}

#[test]
fn human_says_which_image_ships_a_path_the_container_never_changed() {
    let rule = |id: &str, fact: &str| {
        let yaml = format!("fact: {fact}.*\nexpect: {{const: 0}}\n");
        compile(id, systemlint::yaml::from_str(&yaml).unwrap()).unwrap()
    };
    let document = json!({
        "meta": {"subject": {"kind": "container", "image": "kiota.ch/b19/ubuntu", "changed": ["/etc", "/etc/b"]}},
        "collectors": {"mounts-active": {"status": "ok", "into": "mounts", "live": true}},
        "files": {"/etc/a": 1, "/etc/b": 1, "/etc/a:7": 1, "/etc/b:7": 1},
        "mounts": {"/tmp": 1},
    });
    let rules = [rule("x/mode", "files"), rule("x/mount", "mounts")];
    let checks = lint(&document, &rules, &[], "2026-11-16");
    let text = systemlint::report::lint_human(&document, &checks, 0, true, false, false);
    assert!(
        text.contains("- files./etc/a:7: 0 was expected, as kiota.ch/b19/ubuntu ships it.\n")
            && text.contains("- files./etc/b:7: 0 was expected.\n"),
        "a path:line subject is judged by its path: {text}"
    );
    assert!(
        text.contains("- mounts./tmp: 0 was expected.\n"),
        "a live collector reads running state, never the image: {text}"
    );
    assert!(
        text.contains("- files./etc/a: 0 was expected, as kiota.ch/b19/ubuntu ships it.\n"),
        "{text}"
    );
    assert!(
        text.contains("- files./etc/b: 0 was expected.\n"),
        "changed in the container: {text}"
    );
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
