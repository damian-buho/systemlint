// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::report::{lint_human_targets, lint_textfile_targets};
use systemlint::runner::{Inside, OUTPUT_CAP, apparmor_label, bounding, filtered, run};
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
        Some(&inside),
    )
    .unwrap();
    assert_eq!(
        (output.code(), output.stdout.as_slice()),
        (3, &b"inside\n"[..])
    );
}

#[test]
fn a_container_is_named_by_its_key_name_or_short_id() {
    let found = systemlint::targets::Found {
        key: "ci/runner".to_owned(),
        name: "runner".to_owned(),
        engine: "docker",
        id: "0123456789ab".to_owned(),
        pid: 1,
        inner: 1,
        parent: Some("ci".to_owned()),
        image: None,
        upper: None,
    };
    for pattern in [
        "ci/runner",
        "runner",
        "0123456789ab",
        "ci/*",
        "run*",
        "*",
        "0123*",
    ] {
        assert!(found.named(pattern), "{pattern}");
    }
    for pattern in ["ci", "runner2", "0123456789a", "web", ""] {
        assert!(!found.named(pattern), "{pattern}");
    }
}

#[test]
fn an_apparmor_label_drops_its_mode_and_unconfined_is_none() {
    assert_eq!(
        apparmor_label("docker-default (enforce)\n"),
        Some("docker-default")
    );
    assert_eq!(apparmor_label("a//&b (mixed)\n"), Some("a//&b"));
    assert_eq!(
        apparmor_label("lxc-x_</var/lib/lxc>\n"),
        Some("lxc-x_</var/lib/lxc>")
    );
    assert_eq!(apparmor_label("unconfined\n"), None);
    assert_eq!(apparmor_label("\n"), None);
}

#[test]
fn only_seccomp_mode_2_is_a_filter() {
    assert!(filtered("Name:\tx\nSeccomp:\t2\nSeccomp_filters:\t1\n"));
    assert!(!filtered("Seccomp:\t1\n"));
    assert!(!filtered("Seccomp:\t0\n"));
    assert!(!filtered("Name:\tx\n"));
}

#[test]
fn a_command_whose_apparmor_label_cannot_be_applied_does_not_run() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let mut inside = Inside::of(std::process::id(), &status).unwrap();
    inside.apparmor = Some("systemlint-no-such-profile".to_owned());
    let ran = run(
        Path::new("/bin/true"),
        &[],
        None,
        Duration::from_secs(600),
        OUTPUT_CAP,
        Some(&inside),
    );
    assert!(ran.is_err(), "{ran:?}");
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
        text.contains("In the host and every container except d:\n"),
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
fn human_prints_a_subject_shared_by_containers_once_beside_the_ones_they_differ_in() {
    let yaml = "fact: files.*\nexpect: {const: 0}\nremedy: {chown: 0}\n";
    let rules = [compile("x/owner", systemlint::yaml::from_str(yaml).unwrap()).unwrap()];
    let doc = |image: &str, files: Value| json!({"meta": {"subject": {"kind": "container", "image": image, "changed": []}}, "files": files});
    let (a, b) = (
        doc("kiota.ch/o9s/a", json!({"/a": 1, "/c": 1})),
        doc("kiota.ch/o9s/b", json!({"/a": 1})),
    );
    let (ja, jb) = (
        lint(&a, &rules, &[], "2026-11-17"),
        lint(&b, &rules, &[], "2026-11-17"),
    );
    let host = json!({"files": {}});
    let targets = [("a", &a, ja.as_slice()), ("b", &b, jb.as_slice())];
    let text = lint_human_targets(&host, &[], 0, &targets, (true, false, false));
    assert_eq!(text.matches("- files./a:").count(), 1, "{text}");
    assert!(
        text.contains(
            "In every container, as each image ships it:\n- files./a: 0 was expected.\nFix where each image’s build adds it: add it owned by root, with “COPY --chown=0:0” or “install --owner=root --group=root”, then rebuild it.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "In a, as kiota.ch/o9s/a ships it:\n- files./c: 0 was expected.\nFix where the image’s build adds it: add it owned by root, with “COPY --chown=0:0” or “install --owner=root --group=root”, then rebuild it.\n"
        ),
        "{text}"
    );
}

#[test]
fn human_keeps_each_targets_closing_text_with_its_own_subjects() {
    let compiled =
        |id: &str, yaml: &str| compile(id, systemlint::yaml::from_str(yaml).unwrap()).unwrap();
    let rules = [
        compiled(
            "x/fix",
            "fact: mounts.*\nexpect: {const: 0}\nfix: remount {subject}\n",
        ),
        compiled(
            "x/mode",
            "fact: files.*\nexpect: {const: 0}\nremedy: {chmod: o-r}\n",
        ),
    ];
    let host = json!({"mounts": {"/dev/shm": 1, "/tmp": 1}, "files": {"/a": 1, "/b": 1}});
    let doc = |files: Value| json!({"meta": {"subject": {"kind": "container", "image": "i", "changed": ["/a", "/b"]}}, "mounts": {}, "files": files});
    let (m, c) = (
        json!({"mounts": {"/tmp": 1}, "files": {}}),
        doc(json!({"/a": 1})),
    );
    let n = doc(json!({"/b": 1}));
    let judged = |d: &Value| lint(d, &rules, &[], "2026-11-18");
    let (jh, jm, jc, jn) = (judged(&host), judged(&m), judged(&c), judged(&n));
    let targets = [
        ("m", &m, jm.as_slice()),
        ("c", &c, jc.as_slice()),
        ("n", &n, jn.as_slice()),
    ];
    let text = lint_human_targets(&host, &jh, 0, &targets, (true, false, false));
    assert_eq!(text.matches("In m:").count(), 1, "{text}");
    assert!(
        text.contains("In m:\n- mounts./tmp: 0 was expected.\nFix: remount /tmp.\n"),
        "{text}"
    );
    assert_eq!(text.matches("In the host:").count(), 1, "{text}");
    assert!(
        text.contains(
            "  Run: chmod o-r /b\nOr make every change at once:\n  systemlint fix --tags x/mode\n"
        ),
        "{text}"
    );
}

#[test]
fn human_fixes_a_shipped_path_in_the_image_build_and_never_offers_fix_in_a_container() {
    let yaml = "fact: files.*\nexpect: {const: 0}\nremedy: {chown: 0}\n";
    let rules = [compile("x/owner", systemlint::yaml::from_str(yaml).unwrap()).unwrap()];
    let document = json!({
        "meta": {"subject": {"kind": "container", "image": "kiota.ch/b19/ubuntu", "changed": ["/etc/d"]}},
        "files": {"/etc/a": 1, "/etc/b c": 1, "/etc/d": 1, "/etc/e": 0},
    });
    let checks = lint(&document, &rules, &[], "2026-11-17");
    let text = systemlint::report::lint_human(&document, &checks, 0, true, false, false);
    assert!(
        text.contains("Fix where the image’s build adds “/etc/a”, “/etc/b c”: add them owned by root, with “COPY --chown=0:0” or “install --owner=root --group=root”, then rebuild it.\n"),
        "one step gathers every shipped path: {text}"
    );
    assert!(
        text.contains("- files./etc/d: 0 was expected.\n  Run: chown 0 /etc/d\n"),
        "the container’s own change keeps its command: {text}"
    );
    assert!(
        !text.contains("systemlint fix"),
        "fix reaches no container: {text}"
    );
    assert!(!text.contains("Run: chown 0 /etc/a"), "{text}");
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
