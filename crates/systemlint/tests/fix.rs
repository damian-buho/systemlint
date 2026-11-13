// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::fix::{Change, Remedy, apply, cleared, plan};
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
    let changes = plan(&lint(&document, &rules, &[], "2026-11-12"), &rules);
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
