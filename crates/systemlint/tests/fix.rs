// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::fix::{Change, Lines, Remedy, apply, cleared, line_sha256, plan};
use systemlint::judge::{compile, lint};
use systemlint::source::Root;

fn base(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("fix")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn shipped(rule: &str) -> Remedy {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/files.yaml"),
    )
    .unwrap();
    let rules: Value = systemlint::yaml::from_str(&text).unwrap();
    serde_json::from_value(rules["rules"][rule]["remedy"].clone()).unwrap()
}

fn chmod(spec: &str, path: &str) -> Change {
    Change {
        rule: "test/rule".into(),
        path: path.into(),
        line: None,
        remedy: Remedy::Chmod(spec.into()),
    }
}

#[test]
fn a_symbolic_clear_sets_the_bits_of_each_who() {
    assert_eq!(cleared("o-w"), Ok(0o002));
    assert_eq!(cleared("a-w"), Ok(0o222));
    assert_eq!(cleared("u-xs,g-wxs,o-rwxt"), Ok(0o7137));
    assert_eq!(cleared("ugo-rwx"), Ok(0o777));
}

#[test]
fn a_chmod_that_adds_sets_or_is_malformed_is_refused() {
    for spec in ["o+w", "o=r", "z-w", "o-q", "-w", "o-", "", "o-w,"] {
        assert!(cleared(spec).is_err(), "{spec}");
    }
}

#[test]
fn a_chown_to_anyone_but_root_is_refused() {
    assert_eq!(Remedy::Chown(0).validate(), Ok(()));
    assert!(
        Remedy::Chown(1)
            .validate()
            .unwrap_err()
            .contains("only chown 0")
    );
    assert!(
        compile(
            "test/rule",
            systemlint::yaml::from_str("fact: a\nexpect: {const: 0}\nremedy: {chown: 1000}\n")
                .unwrap()
        )
        .is_err()
    );
}

#[test]
fn a_chgrp_to_any_group_but_root_is_refused() {
    assert_eq!(Remedy::Chgrp(0).validate(), Ok(()));
    assert!(
        Remedy::Chgrp(1)
            .validate()
            .unwrap_err()
            .contains("only chgrp 0")
    );
    assert!(
        compile(
            "test/rule",
            systemlint::yaml::from_str("fact: a\nexpect: {const: 0}\nremedy: {chgrp: 1000}\n")
                .unwrap()
        )
        .is_err()
    );
    assert_eq!(
        Remedy::Chgrp(0).command("/etc/sudoers"),
        "chgrp 0 /etc/sudoers"
    );
}

#[test]
fn a_command_quotes_a_path_with_spaces_or_quotes() {
    assert_eq!(
        Remedy::Chown(0).command("/etc/shadow"),
        "chown 0 /etc/shadow"
    );
    assert_eq!(
        Remedy::Chmod("o-w".into()).command("/etc/a b"),
        "chmod o-w '/etc/a b'"
    );
    assert_eq!(
        Remedy::Chmod("o-w".into()).command("/etc/it's"),
        r"chmod o-w '/etc/it'\''s'"
    );
}

#[test]
fn the_shipped_mode_remedy_makes_every_failing_mode_pass() {
    // The rules’ pattern ^0[0246][04]0$: no special bit, no owner execute, group read at most, nothing for others.
    let passes =
        |m: u32| m & 0o7000 == 0 && m & 0o100 == 0 && matches!((m >> 3) & 7, 0 | 4) && m & 7 == 0;
    for rule in ["files/shadow-mode", "files/ssh-host-key-mode"] {
        let Remedy::Chmod(spec) = shipped(rule) else {
            panic!("{rule} has no chmod remedy")
        };
        let mask = cleared(&spec).unwrap();
        for mode in (0..=0o7777).filter(|m| !passes(*m)) {
            assert!(passes(mode & !mask), "{rule}: {mode:04o} stays failing");
        }
    }
}

#[test]
fn a_plan_lists_each_failing_path_once() {
    let rule = |id: &str| {
        compile(
            id,
            systemlint::yaml::from_str(
                "fact: files.*.*.world-writable\nexpect: {const: false}\nremedy: {chmod: o-w}\n",
            )
            .unwrap(),
        )
        .unwrap()
    };
    let document = json!({"files": {"cron": {"/etc/crontab": {"world-writable": true}, "/etc/cron.d": {"world-writable": false}}}});
    let rules = [rule("a/rule"), rule("b/rule")];
    let changes = plan(
        &lint(&document, &rules, &[], "2026-11-12"),
        &rules,
        &document,
    )
    .changes;
    assert_eq!(
        changes.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
        ["/etc/crontab"]
    );
}

#[test]
fn applying_a_chmod_clears_the_bits_once() {
    let dir = base("chmod");
    let file = dir.join("file");
    std::fs::write(&file, "").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let root = Root::open(&dir).unwrap();
    assert_eq!(
        apply(&root, &chmod("o-w", "/file")).unwrap(),
        Some(("0666".into(), "0664".into()))
    );
    assert_eq!(
        apply(&root, &chmod("o-w", "/file")).unwrap(),
        None,
        "a re-run changes nothing"
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
        0o664
    );
}

#[test]
fn applying_to_a_symlink_or_a_fifo_is_refused() {
    let dir = base("special");
    std::fs::write(dir.join("target"), "").unwrap();
    std::fs::set_permissions(dir.join("target"), std::fs::Permissions::from_mode(0o666)).unwrap();
    std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        dir.join("fifo"),
        rustix::fs::Mode::from_raw_mode(0o666),
    )
    .unwrap();
    let root = Root::open(&dir).unwrap();
    assert!(
        apply(&root, &chmod("o-w", "/link"))
            .unwrap_err()
            .to_string()
            .contains("symbolic link now")
    );
    assert!(apply(&root, &chmod("o-w", "/fifo")).is_err());
    assert_eq!(
        std::fs::metadata(dir.join("target"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o666,
        "the link target is untouched"
    );
}

// The keys of a test authorized_keys file, line 2 being the DSA key a rule fails.
const KEYS: &str = "ssh-ed25519 AAAA one\nssh-dss AAAA two\r\n# note\nssh-ed25519 AAAA three";

// A plan disabling DSA lines over a document whose line 2 carries the hash `sha`, or none.
fn dsa_plan(sha: Option<String>) -> Vec<Change> {
    let mut key = json!({"type": "ssh-dss"});
    if let Some(sha) = sha {
        key["line-sha256"] = json!(sha);
    }
    let document = json!({"ssh": {"authorized-keys": {"alice": {"keys": {"/keys:2": key, "/keys:1": {"type": "ssh-ed25519"}}}}}});
    let rules = [dsa_rule()];
    plan(
        &lint(&document, &rules, &[], "2026-11-12"),
        &rules,
        &document,
    )
    .changes
}

// The rule that comments out every DSA line.
fn dsa_rule() -> systemlint::judge::Rule {
    compile(
        "a/dsa",
        systemlint::yaml::from_str(
            "fact: ssh.authorized-keys.*.keys.*.type\nexpect: {not: {pattern: ^ssh-dss}}\nremedy: {disable-line: authorized-keys}\n",
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn a_line_remedy_never_disables_the_last_line_of_any_owner() {
    let dss =
        |n: u32| json!({"type": "ssh-dss", "line-sha256": line_sha256(&format!("ssh-dss {n}"))});
    let document = json!({"ssh": {"authorized-keys": {
        "alice": {"keys": {"/a:1": dss(1), "/a:2": dss(2), "/a:3": {"type": "ssh-ed25519"}}},
        "bob": {"keys": {"/b:1": dss(1), "/b:2": dss(2)}},
        "carol": {"keys": {"/a:1": dss(1)}},
    }}});
    let rules = [dsa_rule()];
    let planned = plan(
        &lint(&document, &rules, &[], "2026-11-12"),
        &rules,
        &document,
    );
    let subjects = |changes: Vec<Change>| changes.iter().map(Change::subject).collect::<Vec<_>>();
    assert_eq!(
        subjects(planned.changes),
        ["/a:2", "/b:1"],
        "alice keeps her ed25519 key, bob his second"
    );
    assert_eq!(
        planned
            .kept
            .iter()
            .map(|(c, why)| format!("{} {why}", c.subject()))
            .collect::<Vec<_>>(),
        [
            "/a:1 it is the last line left for carol",
            "/b:2 it is the last line left for bob"
        ],
        "a line two accounts share is kept when either would lose its last"
    );
}

#[test]
fn a_line_remedy_comments_out_only_the_line_the_lint_hashed() {
    let dir = base("line");
    std::fs::write(dir.join("keys"), KEYS).unwrap();
    let root = Root::open(&dir).unwrap();
    let changes = dsa_plan(Some(line_sha256("ssh-dss AAAA two")));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].subject(), "/keys:2");
    assert_eq!(
        changes[0].remedy.command(&changes[0].subject()),
        "sed -i '2s/^/#/' /keys"
    );
    assert_eq!(
        apply(&root, &changes[0]).unwrap(),
        Some(("active".into(), "commented out".into()))
    );
    assert_eq!(
        apply(&root, &changes[0]).unwrap(),
        None,
        "a re-run changes nothing"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("keys")).unwrap(),
        KEYS.replace("ssh-dss", "#ssh-dss"),
        "every other byte is kept, CRLF and the unterminated last line included"
    );
}

#[test]
fn a_line_remedy_refuses_a_changed_line_and_plans_nothing_without_a_hash() {
    let dir = base("line-changed");
    std::fs::write(dir.join("keys"), KEYS).unwrap();
    let root = Root::open(&dir).unwrap();
    let changes = dsa_plan(Some(line_sha256("ssh-dss AAAA other")));
    assert!(
        apply(&root, &changes[0])
            .unwrap_err()
            .to_string()
            .contains("changed since the lint")
    );
    let mut gone = changes[0].clone();
    gone.line = Some((5, line_sha256("")));
    assert!(
        apply(&root, &gone)
            .unwrap_err()
            .to_string()
            .contains("line 5 is gone")
    );
    assert_eq!(std::fs::read_to_string(dir.join("keys")).unwrap(), KEYS);
    assert_eq!(
        dsa_plan(None),
        [],
        "a subject with no line hash is never changed"
    );
}

#[test]
fn an_apt_line_remedy_disables_a_one_line_source_never_a_paragraph_nor_the_only_source() {
    let rules = [compile(
        "apt/insecure-options",
        systemlint::yaml::from_str(
            "fact: apt.sources.*.insecure-options\nexpect: {maxItems: 0}\nremedy: {disable-line: apt-list}\n",
        )
        .unwrap(),
    )
    .unwrap()];
    let one = json!({"insecure-options": ["trusted"], "line-sha256": line_sha256("deb [trusted=yes] https://c.example/ /")});
    let document = json!({"apt": {"sources": {
        "/e/c.list:1": one,
        "/e/a.sources:1": {"insecure-options": ["trusted"]},
        "/e/b.list:1": {"insecure-options": []},
    }}});
    let checks = lint(&document, &rules, &[], "2026-11-13");
    let run = |s: &str| {
        checks
            .iter()
            .find(|c| c.subject_label() == s)
            .unwrap()
            .remedy
            .clone()
    };
    assert_eq!(
        run("/e/c.list:1").as_deref(),
        Some("sed -i '1s/^/#/' /e/c.list")
    );
    assert_eq!(
        run("/e/a.sources:1"),
        None,
        "a deb822 paragraph spans lines, so no Run line"
    );
    let changes = plan(&checks, &rules, &document).changes;
    assert_eq!(
        changes.iter().map(Change::subject).collect::<Vec<_>>(),
        ["/e/c.list:1"]
    );
    let only = json!({"apt": {"sources": {"/e/c.list:1": one}}});
    let kept = plan(&lint(&only, &rules, &[], "2026-11-13"), &rules, &only).kept;
    assert_eq!(
        kept.iter()
            .map(|(c, why)| format!("{} {why}", c.subject()))
            .collect::<Vec<_>>(),
        ["/e/c.list:1 it is the last line left for this host"]
    );
}

#[test]
fn a_line_remedy_names_a_syntax_whose_every_line_grants() {
    assert_eq!(
        serde_json::from_value::<Remedy>(json!({"disable-line": "authorized-keys"})).unwrap(),
        Remedy::DisableLine(Lines::AuthorizedKeys)
    );
    assert_eq!(
        serde_json::from_value::<Remedy>(json!({"disable-line": "apt-list"})).unwrap(),
        Remedy::DisableLine(Lines::AptList)
    );
    assert!(serde_json::from_value::<Remedy>(json!({"disable-line": "sudoers"})).is_err());
}

fn drop_in(yaml: &str) -> Remedy {
    systemlint::yaml::from_str(yaml).unwrap()
}

#[test]
fn a_drop_in_writes_only_lines_that_turn_something_off() {
    let ok = |yaml: &str| drop_in(yaml).validate();
    assert!(ok("drop-in: {into: modprobe, name: install-atm, lines: ['install atm /bin/false', 'blacklist usb_storage']}").is_ok());
    assert!(
        ok("drop-in: {into: apt, name: weak, lines: ['APT::Install-Recommends \"0\";']}").is_ok()
    );
    for refused in [
        "drop-in: {into: modprobe, name: x, lines: ['install atm /bin/sh -c id']}",
        "drop-in: {into: modprobe, name: x, lines: ['options atm x=1']}",
        "drop-in: {into: modprobe, name: x, lines: ['blacklist a b']}",
        "drop-in: {into: apt, name: x, lines: ['APT::Install-Recommends \"1\";']}",
        "drop-in: {into: modprobe, name: ../x, lines: ['blacklist atm']}",
        "drop-in: {into: modprobe, name: X, lines: ['blacklist atm']}",
        "drop-in: {into: modprobe, name: x, lines: []}",
    ] {
        assert!(ok(refused).is_err(), "{refused}");
    }
    let lines = |n: usize| {
        format!(
            "drop-in: {{into: modprobe, name: x, lines: [{}]}}",
            vec!["'blacklist a'"; n].join(", ")
        )
    };
    assert!(ok(&lines(16)).is_ok());
    assert!(ok(&lines(17)).is_err(), "at most 16 lines");
    let name = |n: usize| {
        format!(
            "drop-in: {{into: modprobe, name: {}, lines: ['blacklist a']}}",
            "a".repeat(n)
        )
    };
    assert!(ok(&name(64)).is_ok());
    assert!(ok(&name(65)).is_err(), "a name of at most 64 characters");
}

#[test]
fn applying_a_drop_in_writes_it_once_and_leaves_a_file_with_other_lines() {
    let dir = base("drop-in");
    std::fs::create_dir_all(dir.join("etc/modprobe.d")).unwrap();
    let root = Root::open(&dir).unwrap();
    let change = |name: &str| Change {
        rule: "test/rule".into(),
        path: format!("/etc/modprobe.d/60-systemlint-{name}.conf"),
        line: None,
        remedy: drop_in(&format!(
            "drop-in: {{into: modprobe, name: {name}, lines: ['install atm /bin/false']}}"
        )),
    };
    assert_eq!(
        apply(&root, &change("atm")).unwrap(),
        Some(("absent".into(), "written".into()))
    );
    let written = dir.join("etc/modprobe.d/60-systemlint-atm.conf");
    assert_eq!(
        std::fs::read_to_string(&written).unwrap(),
        "install atm /bin/false\n"
    );
    assert_eq!(
        std::fs::metadata(&written).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        apply(&root, &change("atm")).unwrap(),
        None,
        "a re-run changes nothing"
    );
    std::fs::write(
        dir.join("etc/modprobe.d/60-systemlint-mine.conf"),
        "blacklist atm\n",
    )
    .unwrap();
    let error = apply(&root, &change("mine")).unwrap_err();
    assert!(error.to_string().contains("other lines"), "{error}");
    assert_eq!(
        std::fs::read_to_string(dir.join("etc/modprobe.d/60-systemlint-mine.conf")).unwrap(),
        "blacklist atm\n"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dir.join("etc/modprobe.d"))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporary file is left: {leftovers:?}"
    );
}
