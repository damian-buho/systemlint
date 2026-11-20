// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::fix::{Change, Lines, Remedy, apply, cleared, line_sha256, plan, unit_of};
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
        "drop-in: {into: apt, name: x, lines: ['APT::Install-Recommends \"0\";'], unload: true}",
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
fn a_drop_in_without_a_fix_shows_the_file_it_writes_as_the_fix_steps() {
    let yaml = |lines: &str| {
        format!(
            "fact: v\nexpect: {{const: 0}}\nremedy: {{drop-in: {{into: apt, name: quiet, lines: [{lines}]}}}}\n"
        )
    };
    let steps = |lines: &str| {
        let rule =
            systemlint::judge::compile("x/apt", systemlint::yaml::from_str(&yaml(lines)).unwrap())
                .unwrap();
        rule.spec.fix.unwrap().text()
    };
    assert!(
        steps(r#"'APT::Install-Suggests "0";'"#)
            .contains("Write this line to “/etc/apt/apt.conf.d/99-systemlint-quiet.conf”:"),
        "one line"
    );
    assert!(
        steps(r#"'APT::Install-Suggests "0";', 'APT::Install-Recommends "0";'"#)
            .contains("Write these lines to “/etc/apt/apt.conf.d/99-systemlint-quiet.conf”:"),
        "two lines"
    );
    let own = "fact: v\nexpect: {const: 0}\nfix: write it yourself\nremedy: {drop-in: {into: apt, name: quiet, lines: ['APT::Install-Suggests \"0\";']}}\n";
    let rule =
        systemlint::judge::compile("x/apt", systemlint::yaml::from_str(own).unwrap()).unwrap();
    assert_eq!(
        rule.spec.fix.unwrap().text(),
        "write it yourself",
        "a rule’s own fix wins"
    );
}

#[test]
fn an_unloading_drop_in_shows_and_runs_the_unload_after_the_file() {
    let remedy = "drop-in: {into: modprobe, name: block-atm-autoloading, lines: ['install atm /bin/false'], unload: true}";
    let Remedy::DropIn(drop) = drop_in(remedy) else {
        unreachable!()
    };
    assert_eq!(
        drop.steps().text(),
        systemlint::rules::Fix::Steps(vec![
            systemlint::rules::Step::Say(
                "Write this line to “/etc/modprobe.d/60-systemlint-block-atm-autoloading.conf”:"
                    .into()
            ),
            systemlint::rules::Step::Show(systemlint::rules::Shown::Lines(vec![
                "install atm /bin/false".into()
            ])),
            systemlint::rules::Step::Say("Unload it from the running kernel:".into()),
            systemlint::rules::Step::Show(systemlint::rules::Shown::Run("modprobe -r atm".into())),
        ])
        .text()
    );
    assert!(drop_in(remedy).command("").ends_with(" && modprobe -r atm"));
    let dir = base("drop-in-unload");
    std::fs::create_dir_all(dir.join("etc/modprobe.d")).unwrap();
    let change = Change {
        rule: "test/loaded".into(),
        path: drop.path(),
        line: None,
        remedy: drop_in(remedy),
    };
    assert_eq!(
        apply(&Root::open(&dir).unwrap(), &change).unwrap(),
        Some(("absent".into(), "written".into())),
        "under another root the running kernel is left alone"
    );
}

#[test]
fn an_unload_picks_the_listed_modules_in_either_spelling() {
    let listed =
        "usb_storage 86016 0 - Live 0x0\nfirewire_core 1 0 - Live 0x0\natm 1 0 - Live 0x0\n";
    assert_eq!(
        systemlint::fix::loaded(listed, &["usb-storage", "firewire_core", "cramfs", "at"]),
        ["usb-storage", "firewire_core"]
    );
    assert!(systemlint::fix::loaded("", &["atm"]).is_empty());
}

#[test]
fn a_module_with_one_user_is_in_use_and_none_is_not() {
    let listed = "overlay 229376 1 - Live 0x0\nusb_storage 90112 0 - Live 0x0\n";
    assert_eq!(
        systemlint::fix::in_use(listed, &["overlay", "usb-storage", "udf"]),
        [("overlay", 1)]
    );
}

#[test]
fn a_plan_writes_one_drop_in_once_unloading_when_either_rule_asks() {
    let rule = |id: &str, unload: bool| {
        let yaml = format!(
            "fact: v\nexpect: {{const: 0}}\nremedy: {{drop-in: {{into: modprobe, name: block-atm-autoloading, lines: ['install atm /bin/false'], unload: {unload}}}}}\n"
        );
        compile(id, systemlint::yaml::from_str(&yaml).unwrap()).unwrap()
    };
    let document = json!({"v": 1});
    let rules = [rule("a/written", false), rule("b/loaded", true)];
    let changes = plan(
        &lint(&document, &rules, &[], "2026-11-18"),
        &rules,
        &document,
    )
    .changes;
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        matches!(&changes[0].remedy, Remedy::DropIn(d) if d.unload),
        "{changes:?}"
    );
}

#[test]
fn applying_a_drop_in_writes_it_once_adds_to_a_file_of_admitted_lines_and_leaves_any_other() {
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
    let mine = dir.join("etc/modprobe.d/60-systemlint-mine.conf");
    std::fs::write(&mine, "blacklist atm\n").unwrap();
    assert_eq!(
        apply(&root, &change("mine")).unwrap(),
        Some(("1 line".into(), "2 lines".into()))
    );
    assert_eq!(
        std::fs::read_to_string(&mine).unwrap(),
        "blacklist atm\ninstall atm /bin/false\n"
    );
    assert_eq!(
        apply(&root, &change("mine")).unwrap(),
        None,
        "a re-run adds nothing"
    );
    for other in ["options atm x=1\n", "blacklist atm"] {
        std::fs::write(&mine, other).unwrap();
        let error = apply(&root, &change("mine")).unwrap_err();
        assert!(
            error.to_string().contains("other lines"),
            "{other:?}: {error}"
        );
        assert_eq!(std::fs::read_to_string(&mine).unwrap(), other);
    }
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

#[test]
fn a_sysctl_drop_in_writes_only_a_listed_key_at_a_hardened_value() {
    let ok = |line: &str| {
        drop_in(&format!(
            "drop-in: {{into: sysctl, name: x, lines: ['{line}']}}"
        ))
        .validate()
    };
    for admitted in [
        "kernel.kptr_restrict = 1",
        "kernel.kptr_restrict = 2",
        "net.ipv4.conf.all.send_redirects = 0",
        "net.ipv6.conf.enx0826ae3aa571.accept_redirects = 0",
        "net.ipv6.conf.{subject}.accept_redirects = 0",
    ] {
        assert!(ok(admitted).is_ok(), "{admitted}");
    }
    for refused in [
        "kernel.kptr_restrict = 0",
        "kernel.core_pattern = |/tmp/x",
        "net.ipv4.conf.all.send_redirects = 1",
        "net.ipv4.conf.a.b.send_redirects = 0",
        "net.ipv4.conf..send_redirects = 0",
        "kernel.kptr_restrict=1",
    ] {
        assert!(ok(refused).is_err(), "{refused}");
    }
}

#[test]
fn a_sudoers_drop_in_takes_a_dotless_0440_file_that_visudo_passed() {
    let ok = |line: &str| {
        drop_in(&format!(
            "drop-in: {{into: sudoers, name: x, lines: ['{line}']}}"
        ))
        .validate()
    };
    assert!(ok("Defaults use_pty").is_ok());
    assert!(ok("Defaults logfile=\"/var/log/sudo.log\"").is_ok());
    for refused in [
        "Defaults !authenticate",
        "Defaults use_pty ",
        "Defaults logfile=/tmp/x",
        "ALL ALL=(ALL) NOPASSWD: ALL",
    ] {
        assert!(ok(refused).is_err(), "{refused}");
    }
    let dir = base("sudoers");
    std::fs::create_dir_all(dir.join("etc/sudoers.d")).unwrap();
    let root = Root::open(&dir).unwrap();
    let Remedy::DropIn(drop) =
        drop_in("drop-in: {into: sudoers, name: use-pty, lines: [Defaults use_pty]}")
    else {
        unreachable!()
    };
    assert_eq!(drop.path(), "/etc/sudoers.d/99-systemlint-use-pty");
    let change = Change {
        rule: "test/rule".into(),
        path: drop.path(),
        line: None,
        remedy: Remedy::DropIn(drop),
    };
    let written = dir.join("etc/sudoers.d/99-systemlint-use-pty");
    match Path::new("/usr/sbin/visudo").exists() {
        true => {
            assert_eq!(
                apply(&root, &change).unwrap(),
                Some(("absent".into(), "written".into()))
            );
            assert_eq!(
                std::fs::read_to_string(&written).unwrap(),
                "Defaults use_pty\n"
            );
            assert_eq!(
                std::fs::metadata(&written).unwrap().permissions().mode() & 0o777,
                0o440
            );
        }
        false => {
            let error = apply(&root, &change).unwrap_err();
            assert!(error.to_string().contains("visudo"), "{error}");
            assert!(!written.exists());
        }
    }
}

#[test]
fn a_mask_names_only_a_unit_systemd_could_name() {
    let long = |n: usize| format!("{}.service", "a".repeat(n - ".service".len()));
    for named in [
        "avahi-daemon.service",
        "getty@tty1.service",
        "update-notifier-motd.timer",
        "/etc/systemd/system/cups.socket",
        &long(255),
    ] {
        assert!(unit_of(named).is_some(), "{named}");
    }
    for refused in [
        ".service",
        "-x.service",
        ".x.service",
        "a b.service",
        "x.conf",
        "x",
        "",
        "/etc/systemd/system/",
        &long(256),
    ] {
        assert_eq!(unit_of(refused), None, "{refused}");
    }
}

#[test]
fn a_mask_plans_one_systemctl_mask_per_failing_unit() {
    let yaml =
        "fact: systemd.state.*\nexpect: {properties: {masked: {const: true}}}\nremedy: mask\n";
    let rule = compile("t/mask", systemlint::yaml::from_str(yaml).unwrap()).unwrap();
    let document = json!({"systemd": {"state": {"cups.socket": {"masked": false}, "own.service": {"masked": false}, "a b.service": {"masked": false}, "off.service": {"masked": true}}}});
    let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-20");
    let planned = plan(&checks, &[rule], &document).changes;
    let paths: Vec<&str> = planned.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/etc/systemd/system/cups.socket",
            "/etc/systemd/system/own.service"
        ],
        "a unit name with a blank is left out"
    );
    assert_eq!(
        planned[0].remedy.command(&planned[0].path),
        "systemctl mask --now cups.socket"
    );
}

#[test]
fn a_subject_drop_in_writes_every_failing_subject_into_one_file() {
    let yaml = "fact: n.*.r\nexpect: {const: 0}\nremedy: {drop-in: {into: sysctl, name: r, lines: ['net.ipv6.conf.default.accept_redirects = 0', 'net.ipv6.conf.{subject}.accept_redirects = 0']}}\n";
    let rule = compile("t/r", systemlint::yaml::from_str(yaml).unwrap()).unwrap();
    let document = json!({"n": {"eth0": {"r": 1}, "wl-p": {"r": 1}, "default": {"r": 1}, "a b": {"r": 1}, "ok": {"r": 0}}});
    let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-20");
    let planned = plan(&checks, &[rule], &document).changes;
    assert_eq!(planned.len(), 1, "{planned:?}");
    let Remedy::DropIn(drop) = &planned[0].remedy else {
        panic!("{planned:?}")
    };
    assert_eq!(drop.path(), "/etc/sysctl.d/99-systemlint-r.conf");
    assert_eq!(
        drop.lines,
        [
            "net.ipv6.conf.default.accept_redirects = 0",
            "net.ipv6.conf.eth0.accept_redirects = 0",
            "net.ipv6.conf.wl-p.accept_redirects = 0",
        ],
        "a subject with a blank is left out, a repeated line written once"
    );
}

#[test]
fn a_set_key_writes_only_a_listed_value_and_only_over_what_the_lint_read() {
    let ok = |key: &str, value: &str| {
        drop_in(&format!(
            "set-key: {{file: login-defs, key: {key}, value: '{value}'}}"
        ))
        .validate()
    };
    for (key, value) in [
        ("UMASK", "027"),
        ("UMASK", "077"),
        ("ENCRYPT_METHOD", "SHA512"),
        ("ENCRYPT_METHOD", "YESCRYPT"),
    ] {
        assert!(ok(key, value).is_ok(), "{key} {value}");
    }
    for (key, value) in [
        ("UMASK", "022"),
        ("UMASK", "27"),
        ("ENCRYPT_METHOD", "MD5"),
        ("PASS_MAX_DAYS", "1"),
        ("umask", "027"),
    ] {
        assert!(ok(key, value).is_err(), "{key} {value}");
    }
    let yaml = "fact: auth.login-defs\nexpect: {required: [UMASK], properties: {UMASK: {pattern: '^0[0-7]?[2367]7$'}}}\nremedy: {set-key: {file: login-defs, key: UMASK, value: '027'}}\n";
    let rule = compile("t/umask", systemlint::yaml::from_str(yaml).unwrap()).unwrap();
    let dir = base("set-key");
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    let defs = dir.join("etc/login.defs");
    let root = Root::open(&dir).unwrap();
    let planned = |umask: Value| {
        let document = json!({"auth": {"login-defs": umask}});
        let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-20");
        plan(&checks, std::slice::from_ref(&rule), &document).changes
    };
    let change = planned(json!({"UMASK": "022"})).remove(0);
    assert_eq!(change.path, "/etc/login.defs");
    assert_eq!(
        change.remedy.command(&change.path),
        "sed --in-place 's/^UMASK[[:space:]].*/UMASK 027/' /etc/login.defs"
    );
    std::fs::write(
        &defs,
        "# UMASK 022\nUMASK\t022\nMAIL_DIR /var/mail\nUMASK 022\n",
    )
    .unwrap();
    std::fs::set_permissions(&defs, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        apply(&root, &change).unwrap(),
        Some(("UMASK 022".into(), "UMASK 027".into()))
    );
    assert_eq!(
        std::fs::read_to_string(&defs).unwrap(),
        "# UMASK 022\nUMASK 027\nMAIL_DIR /var/mail\nUMASK 027\n"
    );
    assert_eq!(
        std::fs::metadata(&defs).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        apply(&root, &change).unwrap(),
        None,
        "a re-run changes nothing"
    );
    std::fs::write(&defs, "UMASK 002\n").unwrap();
    let error = apply(&root, &change).unwrap_err();
    assert!(
        error.to_string().contains("changed since the lint"),
        "{error}"
    );
    assert_eq!(std::fs::read_to_string(&defs).unwrap(), "UMASK 002\n");
    let absent = planned(json!({})).remove(0);
    assert_eq!(
        absent.remedy.command(&absent.path),
        "echo 'UMASK 027' >> /etc/login.defs"
    );
    std::fs::write(&defs, "MAIL_DIR /var/mail").unwrap();
    assert_eq!(
        apply(&root, &absent).unwrap(),
        Some(("UMASK unset".into(), "UMASK 027".into()))
    );
    assert_eq!(
        std::fs::read_to_string(&defs).unwrap(),
        "MAIL_DIR /var/mail\nUMASK 027\n"
    );
}

#[test]
fn a_daemon_json_set_key_merges_through_jq_keeping_every_other_key() {
    let ok = |value: &str| {
        drop_in(&format!(
            "set-key: {{file: docker-daemon, key: log-opts.max-size, value: '{value}'}}"
        ))
        .validate()
    };
    for value in ["10m", "100m"] {
        assert!(ok(value).is_ok(), "{value}");
    }
    for value in ["9m", "101m", "1g", ""] {
        assert!(ok(value).is_err(), "{value}");
    }
    let yaml = "fact: docker.daemon\nexpect: {required: [log-opts], properties: {log-opts: {required: [max-size]}}}\nremedy: {set-key: {file: docker-daemon, key: log-opts.max-size, value: 100m}}\n";
    let rule = compile("t/logs", systemlint::yaml::from_str(yaml).unwrap()).unwrap();
    let document = json!({"docker": {"daemon": {"log-opts": {"max-file": "3"}}}});
    let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-20");
    let change = plan(&checks, std::slice::from_ref(&rule), &document)
        .changes
        .remove(0);
    assert_eq!(change.path, "/etc/docker/daemon.json");
    assert_eq!(
        change.remedy.command(&change.path),
        "{ cat /etc/docker/daemon.json 2>/dev/null || echo '{}'; } | jq --arg value 100m 'setpath([\"log-opts\",\"max-size\"]; $value)' > /etc/docker/daemon.json.new && dockerd --validate --config-file /etc/docker/daemon.json.new && mv /etc/docker/daemon.json.new /etc/docker/daemon.json && systemctl restart docker.service"
    );
    if !Path::new("/usr/bin/jq").exists() {
        assert!(apply(&Root::open(&base("daemon-json-no-jq")).unwrap(), &change).is_err());
        return;
    }
    let dir = base("daemon-json");
    std::fs::create_dir_all(dir.join("etc/docker")).unwrap();
    let daemon = dir.join("etc/docker/daemon.json");
    let root = Root::open(&dir).unwrap();
    std::fs::write(&daemon, r#"{"icc": false, "log-opts": {"max-file": "3"}}"#).unwrap();
    assert_eq!(
        apply(&root, &change).unwrap(),
        Some((
            "log-opts.max-size unset".into(),
            "log-opts.max-size 100m".into()
        ))
    );
    let merged: Value = serde_json::from_str(&std::fs::read_to_string(&daemon).unwrap()).unwrap();
    assert_eq!(
        merged,
        json!({"icc": false, "log-opts": {"max-file": "3", "max-size": "100m"}})
    );
    assert_eq!(
        apply(&root, &change).unwrap(),
        None,
        "a re-run changes nothing"
    );
    std::fs::write(&daemon, r#"{"log-opts": {"max-size": "1g"}}"#).unwrap();
    let error = apply(&root, &change).unwrap_err();
    assert!(
        error.to_string().contains("changed since the lint"),
        "{error}"
    );
    std::fs::remove_file(&daemon).unwrap();
    assert!(
        apply(&root, &change).is_ok(),
        "a missing file starts from {{}}"
    );
    let created: Value = serde_json::from_str(&std::fs::read_to_string(&daemon).unwrap()).unwrap();
    assert_eq!(created, json!({"log-opts": {"max-size": "100m"}}));
}

#[test]
fn a_reserved_ports_drop_in_writes_one_line_of_the_reserved_ports_and_every_failing_one() {
    const LINE: &str = "net.ipv4.ip_local_reserved_ports = {facts.sysctl.settings.net.ipv4.ip_local_reserved_ports},{subject}";
    let ok = |line: &str| {
        drop_in(&format!(
            "drop-in: {{into: sysctl, name: p, lines: ['{line}']}}"
        ))
        .validate()
    };
    for admitted in [LINE, "net.ipv4.ip_local_reserved_ports = 1,65535,8000-8080"] {
        assert!(ok(admitted).is_ok(), "{admitted}");
    }
    for refused in [
        "net.ipv4.ip_local_reserved_ports = {facts.os.release.ID}",
        "net.ipv4.ip_local_reserved_ports = 0",
        "net.ipv4.ip_local_reserved_ports = 65536",
        "net.ipv4.ip_local_reserved_ports = 9-8",
        "net.ipv4.ip_local_reserved_ports = 1 2",
        "kernel.sysrq = {facts.sysctl.settings.net.ipv4.ip_local_reserved_ports}",
    ] {
        assert!(ok(refused).is_err(), "{refused}");
    }
    let yaml = format!(
        "fact: ports.*\nexpect: {{const: ok}}\nmessage: \"{{subject}} outside {{facts.sysctl.settings.net.ipv4.ip_local_reserved_ports}}\"\nremedy: {{drop-in: {{into: sysctl, name: p, lines: ['{LINE}']}}}}\n"
    );
    let rule = compile("t/p", systemlint::yaml::from_str(&yaml).unwrap()).unwrap();
    let lines = |reserved: Value| {
        let document = json!({"ports": {"2375": "no", "9000": "no", "22": "ok"}, "sysctl": {"settings": {"net": {"ipv4": {"ip_local_reserved_ports": reserved}}}}});
        let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-20");
        let messages: Vec<String> = checks.iter().filter_map(|c| c.message.clone()).collect();
        let planned = plan(&checks, std::slice::from_ref(&rule), &document).changes;
        assert_eq!(planned.len(), 1, "{planned:?}");
        let Remedy::DropIn(drop) = &planned[0].remedy else {
            panic!("{planned:?}")
        };
        (drop.lines.clone(), messages)
    };
    let (written, messages) = lines(json!([{"from": 22, "to": 22}, {"from": 8000, "to": 8080}]));
    assert_eq!(
        written,
        ["net.ipv4.ip_local_reserved_ports = 22,8000-8080,2375,9000"]
    );
    assert_eq!(messages[0], "2375 outside 22,8000-8080");
    let (written, messages) = lines(json!([]));
    assert_eq!(written, ["net.ipv4.ip_local_reserved_ports = 2375,9000"]);
    assert_eq!(messages[0], "2375 outside none");
    let dir = base("reserved-ports");
    std::fs::create_dir_all(dir.join("etc/sysctl.d")).unwrap();
    let file = dir.join("etc/sysctl.d/99-systemlint-p.conf");
    std::fs::write(
        &file,
        "net.ipv4.ip_local_reserved_ports = 2375\nkernel.sysrq = 0\n",
    )
    .unwrap();
    let change = Change {
        rule: "t/p".into(),
        path: "/etc/sysctl.d/99-systemlint-p.conf".into(),
        line: None,
        remedy: drop_in(
            "drop-in: {into: sysctl, name: p, lines: ['net.ipv4.ip_local_reserved_ports = 2375,9000']}",
        ),
    };
    assert_eq!(
        apply(&Root::open(&dir).unwrap(), &change).unwrap(),
        Some(("2 lines".into(), "2 lines".into()))
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "kernel.sysrq = 0\nnet.ipv4.ip_local_reserved_ports = 2375,9000\n",
        "the older line of the key gives way"
    );
}
