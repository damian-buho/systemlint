// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;

// Every check of one shipped ruleset over a document, as (rule, subject, outcome).
fn judge(ruleset: &str, document: &Value) -> Vec<(String, String, Outcome)> {
    scored(ruleset, document)
        .into_iter()
        .map(|(rule, subject, outcome, _)| (rule, subject, outcome))
        .collect()
}

// Like judge, with each check’s score.
fn scored(ruleset: &str, document: &Value) -> Vec<(String, String, Outcome, Option<f64>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../rulesets/{ruleset}.yaml"));
    let parsed = systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([(ruleset.to_owned(), parsed)])).unwrap();
    let rules: Vec<_> = library
        .select(&[ruleset.to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-12")
        .into_iter()
        .map(|c| (c.rule.clone(), c.subject_label(), c.outcome, c.score))
        .collect()
}

// A facts document holding the given sysctl settings, nested by their dots.
fn sysctl(settings: Value) -> Value {
    json!({"sysctl": {"source": "effective", "settings": settings}, "collectors": {"sysctl": {"status": "ok", "into": "sysctl"}}})
}

// The settings object for one dotted key.
fn key(dotted: &str, value: Value) -> Value {
    dotted
        .rsplit('.')
        .fold(value, |inner, part| json!({part: inner}))
}

// The outcome of one rule when only its key is set, or unset with None.
fn one(ruleset: &str, rule: &str, dotted: &str, value: Option<Value>) -> Outcome {
    let document = sysctl(value.map_or(json!({}), |v| key(dotted, v)));
    let checks = judge(ruleset, &document);
    checks
        .into_iter()
        .find(|(r, _, _)| r == rule)
        .unwrap_or_else(|| panic!("{rule} gave no check"))
        .2
}

#[test]
fn every_sysctl_rule_passes_at_its_edge_fails_beyond_it_and_is_unknown_unset() {
    let edges = [
        ("kernel", "kernel/aslr", "kernel.randomize_va_space", 2, 1),
        (
            "kernel",
            "kernel/kptr-restrict",
            "kernel.kptr_restrict",
            1,
            0,
        ),
        (
            "kernel",
            "kernel/dmesg-restrict",
            "kernel.dmesg_restrict",
            1,
            0,
        ),
        (
            "kernel",
            "kernel/ptrace-scope",
            "kernel.yama.ptrace_scope",
            1,
            0,
        ),
        (
            "kernel",
            "kernel/unprivileged-bpf",
            "kernel.unprivileged_bpf_disabled",
            1,
            0,
        ),
        (
            "kernel",
            "kernel/perf-events",
            "kernel.perf_event_paranoid",
            2,
            1,
        ),
        (
            "kernel",
            "kernel/tty-ldisc-autoload",
            "dev.tty.ldisc_autoload",
            0,
            1,
        ),
        (
            "coredump",
            "coredump/suid-dumpable",
            "fs.suid_dumpable",
            0,
            1,
        ),
        (
            "fs-protected",
            "fs-protected/symlinks",
            "fs.protected_symlinks",
            1,
            0,
        ),
        (
            "fs-protected",
            "fs-protected/hardlinks",
            "fs.protected_hardlinks",
            1,
            0,
        ),
        (
            "fs-protected",
            "fs-protected/fifos",
            "fs.protected_fifos",
            1,
            0,
        ),
        (
            "fs-protected",
            "fs-protected/regular",
            "fs.protected_regular",
            1,
            0,
        ),
        (
            "ip-flood",
            "ip-flood/syncookies",
            "net.ipv4.tcp_syncookies",
            1,
            0,
        ),
        (
            "ip-flood",
            "ip-flood/broadcast-echo",
            "net.ipv4.icmp_echo_ignore_broadcasts",
            1,
            0,
        ),
    ];
    for (ruleset, rule, dotted, pass, fail) in edges {
        assert_eq!(
            one(ruleset, rule, dotted, Some(json!(pass))),
            Outcome::Pass,
            "{rule} at {pass}"
        );
        assert_eq!(
            one(ruleset, rule, dotted, Some(json!(fail))),
            Outcome::Fail,
            "{rule} at {fail}"
        );
        assert_eq!(
            one(ruleset, rule, dotted, None),
            Outcome::Unknown,
            "{rule} unset"
        );
    }
}

#[test]
fn suid_dumpable_accepts_a_root_only_crash_handler_and_rejects_anything_above() {
    assert_eq!(
        one(
            "coredump",
            "coredump/suid-dumpable",
            "fs.suid_dumpable",
            Some(json!(2))
        ),
        Outcome::Pass
    );
    assert_eq!(
        one(
            "coredump",
            "coredump/suid-dumpable",
            "fs.suid_dumpable",
            Some(json!(3))
        ),
        Outcome::Fail
    );
}

#[test]
fn ipv4_redirects_are_judged_per_interface_but_loopback_and_skipped_where_it_forwards() {
    let conf = json!({"all": {"accept_redirects": 0, "forwarding": 0}, "eth0": {"accept_redirects": 1, "forwarding": 0}, "docker0": {"accept_redirects": 1, "forwarding": 1}, "lo": {"accept_redirects": 1, "forwarding": 0}});
    let checks = judge(
        "ip-routing",
        &sysctl(json!({"net": {"ipv4": {"conf": conf}}})),
    );
    let redirects: Vec<_> = checks
        .iter()
        .filter(|(r, _, _)| r == "ip-routing/ipv4-redirects")
        .map(|(_, s, o)| (s.as_str(), *o))
        .collect();
    assert_eq!(
        redirects,
        [
            ("all", Outcome::Pass),
            ("docker0", Outcome::Skip),
            ("eth0", Outcome::Fail)
        ]
    );
}

#[test]
fn ipv6_redirects_leave_all_and_loopback_out_and_skip_a_forwarding_interface() {
    let conf = json!({"all": {"accept_redirects": 1, "forwarding": 0}, "default": {"accept_redirects": 0, "forwarding": 0}, "eth0": {"accept_redirects": 1, "forwarding": 1}, "wlan0": {"accept_redirects": 1, "forwarding": 0}, "lo": {"accept_redirects": 1, "forwarding": 0}});
    let checks = judge(
        "ip-routing",
        &sysctl(json!({"net": {"ipv6": {"conf": conf}}})),
    );
    let redirects: Vec<_> = checks
        .iter()
        .filter(|(r, _, _)| r == "ip-routing/ipv6-redirects")
        .map(|(_, s, o)| (s.as_str(), *o))
        .collect();
    assert_eq!(
        redirects,
        [
            ("default", Outcome::Pass),
            ("eth0", Outcome::Skip),
            ("wlan0", Outcome::Fail)
        ]
    );
}

#[test]
fn ipv4_source_routing_fails_an_interface_only_when_all_allows_it_too() {
    let route = |all: u8, eth0: u8| {
        let conf =
            json!({"all": {"accept_source_route": all}, "eth0": {"accept_source_route": eth0}});
        let checks = judge(
            "ip-routing",
            &sysctl(json!({"net": {"ipv4": {"conf": conf}}})),
        );
        checks
            .into_iter()
            .filter(|(r, _, _)| r == "ip-routing/ipv4-source-route")
            .map(|(_, s, o)| (s, o))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        route(0, 1),
        [("eth0".to_owned(), Outcome::Pass)],
        "all off overrides the interface"
    );
    assert_eq!(route(1, 0), [("eth0".to_owned(), Outcome::Pass)]);
    assert_eq!(route(1, 1), [("eth0".to_owned(), Outcome::Fail)]);
}

// A document with the ufw collectors' facts: the binary paths found and ufw.conf, absent with None, and no unit state.
fn ufw(binaries: &[&str], conf: Option<Value>) -> Value {
    let binary: serde_json::Map<String, Value> = binaries
        .iter()
        .map(|p| ((*p).to_owned(), json!({"exists": true, "type": "file"})))
        .collect();
    let mut document = json!({"ufw": {"binary": binary}, "systemd": {"state": {}}, "collectors": {"ufw-binary": {"status": "ok", "into": "ufw.binary"}, "ufw": {"status": "ok", "into": "ufw.conf"}, "systemd-state": {"status": "ok", "into": "systemd.state"}}});
    if let Some(conf) = conf {
        document["ufw"]["conf"] = conf;
    }
    document
}

#[test]
fn ufw_switched_off_fails_only_where_its_program_exists() {
    let outcome = |document: &Value| {
        judge("ufw", document)
            .into_iter()
            .filter(|(rule, _, _)| rule == "ufw/disabled")
            .map(|(_, _, o)| o)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        outcome(&ufw(&[], Some(json!({"ENABLED": "no"})))),
        [Outcome::NotApplicable],
        "a leftover ufw.conf without the program"
    );
    assert_eq!(
        outcome(&ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": "yes"})))),
        [Outcome::Pass]
    );
    assert_eq!(
        outcome(&ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": "no"})))),
        [Outcome::Fail]
    );
    assert_eq!(
        outcome(&ufw(&["/usr/sbin/ufw"], None)),
        [Outcome::Unknown],
        "the program without its configuration"
    );
}

// The ufw service rules' outcomes, by rule, for ufw.conf's ENABLED and the systemd state of every unit.
fn ufw_service(enabled: &str, state: Value) -> Vec<(String, Outcome)> {
    let mut document = ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": enabled})));
    document["systemd"]["state"] = state;
    judge("ufw", &document)
        .into_iter()
        .filter(|(rule, _, _)| rule != "ufw/disabled" && rule != "ufw/service-failed")
        .map(|(rule, _, o)| (rule, o))
        .collect()
}

// The outcomes of ufw/service-failed for ufw.conf's ENABLED and the systemd state of every unit.
fn ufw_failed(enabled: &str, state: Value) -> Vec<Outcome> {
    let mut document = ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": enabled})));
    document["systemd"]["state"] = state;
    judge("ufw", &document)
        .into_iter()
        .filter(|(rule, _, _)| rule == "ufw/service-failed")
        .map(|(_, _, o)| o)
        .collect()
}

#[test]
fn ufw_service_fails_when_failed_and_stays_quiet_without_a_manager() {
    let unit = |active: &str| json!({"ufw.service": {"enabled": true, "masked": false, "active": active, "sub": "x"}, "ssh.service": {"enabled": true, "masked": false, "active": "failed"}});
    assert_eq!(ufw_failed("yes", unit("failed")), [Outcome::Fail]);
    assert_eq!(ufw_failed("yes", unit("active")), [Outcome::Pass]);
    assert_eq!(
        ufw_failed("yes", unit("inactive")),
        [Outcome::Pass],
        "not started yet is ufw/service-disabled’s case"
    );
    assert_eq!(
        ufw_failed("no", unit("failed")),
        [Outcome::Skip],
        "ufw/disabled already reports it"
    );
    assert_eq!(
        ufw_failed(
            "yes",
            json!({"ufw.service": {"enabled": true, "masked": false}})
        ),
        [Outcome::Skip],
        "--root has no active state: skip, neither a pass nor unknown"
    );
    let mut failed = ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": "yes"})));
    failed["systemd"] = json!({});
    failed["collectors"]["systemd-state"] =
        json!({"status": "error", "into": "systemd.state", "reason": "x"});
    assert!(
        judge("ufw", &failed)
            .into_iter()
            .any(|(rule, _, o)| rule == "ufw/service-failed" && o == Outcome::Unknown),
        "a failed collector stays unknown"
    );
    assert_eq!(
        ufw_failed("yes", json!({})),
        [],
        "no ufw.service unit: nothing to start"
    );
}

#[test]
fn ufw_service_fails_masked_or_without_a_link_only_once_ufw_is_switched_on() {
    let unit = |enabled: bool, masked: bool| json!({"ufw.service": {"enabled": enabled, "masked": masked}, "ssh.service": {"enabled": false, "masked": true}});
    let (masked, disabled) = (
        "ufw/service-masked".to_owned(),
        "ufw/service-disabled".to_owned(),
    );
    assert_eq!(
        ufw_service("yes", unit(true, false)),
        [
            (disabled.clone(), Outcome::Pass),
            (masked.clone(), Outcome::Pass)
        ]
    );
    assert_eq!(
        ufw_service("yes", unit(false, false)),
        [
            (disabled.clone(), Outcome::Fail),
            (masked.clone(), Outcome::Pass)
        ]
    );
    assert_eq!(
        ufw_service("yes", unit(true, true)),
        [
            (disabled.clone(), Outcome::Skip),
            (masked.clone(), Outcome::Fail)
        ],
        "a mask is one finding, not two"
    );
    assert_eq!(
        ufw_service("no", unit(false, true)),
        [
            (disabled.clone(), Outcome::Skip),
            (masked.clone(), Outcome::Skip)
        ],
        "ufw/disabled already reports it"
    );
    assert_eq!(
        ufw_service(
            "yes",
            json!({"ssh.service": {"enabled": false, "masked": true}})
        ),
        [],
        "no ufw.service unit: nothing to start"
    );
}

// The outcome of tmp/sticky on one directory's stat, or with no tmp.dirs at all on None.
fn tmp(stat: Option<Value>) -> Vec<Outcome> {
    let mut document = json!({"collectors": {"tmp-dirs": {"status": "ok", "into": "tmp.dirs"}}});
    if let Some(stat) = stat {
        document["tmp"] = json!({"dirs": {"/tmp": stat}});
    }
    judge("tmp", &document)
        .into_iter()
        .map(|(_, _, o)| o)
        .collect()
}

#[test]
fn a_world_writable_temporary_directory_fails_only_without_the_sticky_bit() {
    assert_eq!(
        tmp(Some(
            json!({"exists": true, "mode": "1777", "world-writable": true})
        )),
        [Outcome::Pass]
    );
    assert_eq!(
        tmp(Some(
            json!({"exists": true, "mode": "0777", "world-writable": true})
        )),
        [Outcome::Fail]
    );
    assert_eq!(
        tmp(Some(
            json!({"exists": true, "mode": "3777", "world-writable": true})
        )),
        [Outcome::Pass],
        "setgid beside sticky"
    );
    assert_eq!(
        tmp(Some(
            json!({"exists": true, "mode": "2777", "world-writable": true})
        )),
        [Outcome::Fail],
        "setgid alone"
    );
    assert_eq!(
        tmp(Some(
            json!({"exists": true, "mode": "0775", "world-writable": false})
        )),
        [Outcome::Pass],
        "no other user writes it"
    );
    assert_eq!(tmp(Some(json!({"exists": false}))), [Outcome::Pass]);
    assert_eq!(tmp(None), [Outcome::Unknown]);
}

// The outcome of apt/security-suite for an os-release and the given sources, absent on None.
fn security(release: Value, sources: Option<Value>) -> Outcome {
    let mut document = json!({"os": {"release": release}, "collectors": {"os-release": {"status": "ok", "into": "os.release"}, "apt-sources": {"status": "ok", "into": "apt.sources"}}});
    if let Some(sources) = sources {
        document["apt"] = json!({"sources": sources});
    }
    judge("apt", &document)
        .into_iter()
        .find(|(r, _, _)| r == "apt/security-suite")
        .unwrap()
        .2
}

#[test]
fn a_stable_release_without_an_enabled_binary_security_suite_fails() {
    let noble = json!({"ID": "ubuntu", "VERSION_ID": "24.04"});
    let source = |enabled: bool, types: &[&str], suites: &[&str]| json!({"enabled": enabled, "types": types, "suites": suites});
    let with = |s: Value| {
        Some(
            json!({"/etc/apt/sources.list.d/ubuntu.sources:1": source(true, &["deb"], &["noble", "noble-updates"]), "/etc/apt/sources.list.d/ubuntu.sources:7": s}),
        )
    };
    assert_eq!(
        security(
            noble.clone(),
            with(source(true, &["deb"], &["noble-security"]))
        ),
        Outcome::Pass
    );
    assert_eq!(
        security(
            noble.clone(),
            with(source(false, &["deb"], &["noble-security"]))
        ),
        Outcome::Fail,
        "disabled"
    );
    assert_eq!(
        security(
            noble.clone(),
            with(source(true, &["deb-src"], &["noble-security"]))
        ),
        Outcome::Fail,
        "source packages only"
    );
    assert_eq!(
        security(
            noble.clone(),
            with(source(true, &["deb"], &["noble-backports"]))
        ),
        Outcome::Fail
    );
    assert_eq!(
        security(noble.clone(), Some(json!({}))),
        Outcome::Fail,
        "no source at all"
    );
    assert_eq!(security(noble, None), Outcome::Unknown);
    assert_eq!(
        security(
            json!({"ID": "debian", "VERSION_CODENAME": "forky"}),
            Some(json!({}))
        ),
        Outcome::Skip,
        "testing and unstable carry no VERSION_ID"
    );
    assert_eq!(
        security(
            json!({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2026.3"}),
            Some(json!({}))
        ),
        Outcome::Skip,
        "a rolling derivative"
    );
    assert_eq!(
        security(
            json!({"ID": "raspbian", "ID_LIKE": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"}),
            Some(json!({}))
        ),
        Outcome::Skip,
        "a derivative without a security suite"
    );
    for (release, base) in [
        (
            json!({"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "VERSION_ID": "22.2", "UBUNTU_CODENAME": "noble"}),
            "noble",
        ),
        (
            json!({"ID": "pop", "ID_LIKE": "ubuntu debian", "UBUNTU_CODENAME": "noble"}),
            "noble",
        ),
        (
            json!({"ID": "linuxmint", "ID_LIKE": "debian", "DEBIAN_CODENAME": "trixie"}),
            "trixie",
        ),
    ] {
        let suite = format!("{base}-security");
        let sources = |suites: &[&str]| {
            Some(
                json!({"/etc/apt/sources.list.d/base.list:1": {"enabled": true, "types": ["deb"], "suites": suites}}),
            )
        };
        assert_eq!(
            security(release.clone(), sources(&[base])),
            Outcome::Fail,
            "{release}"
        );
        assert_eq!(
            security(release.clone(), sources(&[base, &suite])),
            Outcome::Pass,
            "{release}"
        );
    }
}

#[test]
fn every_rule_carrying_a_lynis_reference_is_tagged_lynis_and_back() {
    for entry in
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets")).unwrap()
    {
        let path = entry.unwrap().path();
        let ruleset: Value =
            systemlint::yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for (id, rule) in ruleset["rules"].as_object().unwrap() {
            let tagged = rule["tags"]
                .as_array()
                .is_some_and(|t| t.contains(&json!("lynis")));
            let cited = rule["references"].as_array().is_some_and(|r| {
                r.iter().any(|r| {
                    r["url"]
                        .as_str()
                        .unwrap()
                        .starts_with("https://cisofy.com/lynis/controls/")
                })
            });
            assert_eq!(tagged, cited, "{id} in {}", path.display());
        }
    }
}

// A document with the accounts collectors' facts: passwd, group and shadow entries by name.
fn accounts(passwd: Value, group: Value, shadow: Value) -> Value {
    json!({"accounts": {"passwd": passwd, "group": group, "shadow": shadow}, "collectors": {
        "accounts-passwd": {"status": "ok", "into": "accounts.passwd"},
        "accounts-group": {"status": "ok", "into": "accounts.group"},
        "accounts-shadow": {"status": "ok", "into": "accounts.shadow"}}})
}

// One passwd entry with the given uid and password word, never repeated.
fn user(uid: u32, password: &str) -> Value {
    json!({"uid": uid, "password": password, "shadowed": []})
}

// The (subject, outcome) pairs one accounts rule gives.
fn account_rule(rule: &str, document: &Value) -> Vec<(String, Outcome)> {
    judge("accounts", document)
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, s, o)| (s, o))
        .collect()
}

#[test]
fn a_second_uid_zero_fails_once_and_a_shared_uid_fails_every_holder() {
    let document = accounts(
        json!({"root": user(0, "shadow"), "toor": user(0, "shadow"), "bin": user(1, "shadow"), "a": user(1000, "shadow"), "b": user(1000, "shadow"), "c": user(1001, "shadow")}),
        json!({}),
        json!({}),
    );
    assert_eq!(
        account_rule("accounts/uid-zero", &document),
        [
            ("a".into(), Outcome::Pass),
            ("b".into(), Outcome::Pass),
            ("bin".into(), Outcome::Pass),
            ("c".into(), Outcome::Pass),
            ("toor".into(), Outcome::Fail),
        ],
        "uid 1 is the edge: only 0 is root"
    );
    assert_eq!(
        account_rule("accounts/uid-unique", &document),
        [
            ("a".into(), Outcome::Fail),
            ("b".into(), Outcome::Fail),
            ("bin".into(), Outcome::Pass),
            ("c".into(), Outcome::Pass),
            ("root".into(), Outcome::Skip),
            ("toor".into(), Outcome::Skip),
        ],
        "uid 0 is accounts/uid-zero’s finding, not a second one"
    );
}

#[test]
fn a_shared_gid_and_a_repeated_name_fail() {
    let group = |gid: u32, shadowed: Value| json!({"gid": gid, "shadowed": shadowed});
    let document = accounts(
        json!({"root": {"uid": 0, "password": "shadow", "shadowed": [9]}}),
        json!({"adm": group(4, json!([])), "tty": group(5, json!([])), "wheel": group(5, json!([12, 14]))}),
        json!({}),
    );
    assert_eq!(
        account_rule("accounts/gid-unique", &document),
        [
            ("adm".into(), Outcome::Pass),
            ("tty".into(), Outcome::Fail),
            ("wheel".into(), Outcome::Fail),
        ]
    );
    assert_eq!(
        account_rule("accounts/group-repeated", &document),
        [
            ("adm".into(), Outcome::Pass),
            ("tty".into(), Outcome::Pass),
            ("wheel".into(), Outcome::Fail),
        ]
    );
    assert_eq!(
        account_rule("accounts/user-repeated", &document),
        [("root".into(), Outcome::Fail)]
    );
}

#[test]
fn an_empty_password_fails_where_the_system_reads_it() {
    let document = accounts(
        json!({"open": user(1000, "empty"), "viashadow": user(1001, "shadow"), "locked": user(1002, "shadow"), "inline": user(1003, "hash")}),
        json!({}),
        json!({"open": {"password": "hash"}, "viashadow": {"password": "empty"}, "locked": {"password": "locked"}, "inline": {"password": "empty"}}),
    );
    assert_eq!(
        account_rule("accounts/passwd-empty-password", &document),
        [
            ("inline".into(), Outcome::Pass),
            ("locked".into(), Outcome::Pass),
            ("open".into(), Outcome::Fail),
            ("viashadow".into(), Outcome::Pass),
        ]
    );
    assert_eq!(
        account_rule("accounts/shadow-empty-password", &document),
        [
            ("inline".into(), Outcome::Skip),
            ("locked".into(), Outcome::Pass),
            ("open".into(), Outcome::Skip),
            ("viashadow".into(), Outcome::Fail),
        ],
        "shadow counts only where /etc/passwd defers to it"
    );
    let mut unprivileged = document.clone();
    unprivileged["accounts"]
        .as_object_mut()
        .unwrap()
        .remove("shadow");
    unprivileged["collectors"]["accounts-shadow"] =
        json!({"status": "skipped", "into": "accounts.shadow", "reason": "privileged"});
    assert_eq!(
        account_rule("accounts/shadow-empty-password", &unprivileged),
        [(String::new(), Outcome::Unknown)],
        "an unprivileged run never reads as a pass"
    );
}

// A facts document holding the given mount tables, `active` skipped as under --root unless given.
fn mounts(active: Option<Value>, fstab: Value) -> Vec<(String, String, Outcome)> {
    let mut document = json!({"mounts": {"fstab": fstab}, "collectors": {"mounts-fstab": {"status": "ok", "into": "mounts.fstab"}, "mounts-active": {"status": "skipped", "reason": "live", "into": "mounts.active"}}});
    if let Some(active) = active {
        document["mounts"]["active"] = active;
        document["collectors"]["mounts-active"] = json!({"status": "ok", "into": "mounts.active"});
    }
    let mut checks = judge("mounts", &document);
    checks.sort();
    checks
}

#[test]
fn a_world_writable_mount_without_nosuid_or_nodev_fails() {
    let at = |options: &[&str]| json!({"/tmp": {"options": options}, "/dev/shm": {"options": ["rw", "nosuid", "nodev"]}, "/home": {"options": ["rw"]}});
    let row = |rule: &str, subject: &str, outcome| (rule.to_owned(), subject.to_owned(), outcome);
    assert_eq!(
        mounts(Some(at(&["rw", "nodev"])), at(&["rw"])),
        [
            row("mounts/fstab-nodev", "/dev/shm", Outcome::Skip),
            row("mounts/fstab-nodev", "/tmp", Outcome::Skip),
            row("mounts/fstab-nosuid", "/dev/shm", Outcome::Skip),
            row("mounts/fstab-nosuid", "/tmp", Outcome::Skip),
            row("mounts/nodev", "/dev/shm", Outcome::Pass),
            row("mounts/nodev", "/tmp", Outcome::Pass),
            row("mounts/nosuid", "/dev/shm", Outcome::Pass),
            row("mounts/nosuid", "/tmp", Outcome::Fail),
        ],
        "a live run judges the active table alone and skips fstab, never /home"
    );
    assert_eq!(
        mounts(None, at(&["nosuid", "noexec"])),
        [
            row("mounts/fstab-nodev", "/dev/shm", Outcome::Pass),
            row("mounts/fstab-nodev", "/tmp", Outcome::Fail),
            row("mounts/fstab-nosuid", "/dev/shm", Outcome::Pass),
            row("mounts/fstab-nosuid", "/tmp", Outcome::Pass),
            row("mounts/nodev", "", Outcome::Skip),
            row("mounts/nosuid", "", Outcome::Skip),
        ],
        "a root run judges the declared table and skips the live one"
    );
    assert!(
        mounts(Some(json!({"/": {"options": ["rw"]}})), json!({})).is_empty(),
        "no separate /tmp mount, no check"
    );
}

// The disk checks of one mount, its usage given or its collector failed when None.
fn disk(usage: Option<Value>, filesystem: &str) -> Vec<(String, String, Outcome, Option<f64>)> {
    let mut document = json!({"mounts": {"active": {"/srv": {"filesystem": filesystem}}}, "collectors": {"mounts-active": {"status": "ok", "into": "mounts.active"}, "mounts-usage": {"status": "error", "reason": "can’t statfs /srv", "into": "mounts.usage"}}});
    if let Some(usage) = usage {
        document["mounts"]["usage"] = json!({"/srv": usage});
        document["collectors"]["mounts-usage"] = json!({"status": "ok", "into": "mounts.usage"});
    }
    let mut checks = scored("disk", &document);
    checks.sort_by(|a, b| a.0.cmp(&b.0));
    checks
}

#[test]
fn a_filesystem_fails_from_90_percent_used_scored_on_a_curve() {
    let outcome = |blocks: u64, inodes: u64| {
        disk(
            Some(json!({"blocks": blocks, "inodes": inodes, "read-only": false})),
            "ext4",
        )
        .into_iter()
        .map(|(rule, _, outcome, score)| (rule, outcome, score.map(|s| (s * 10.0).round() / 10.0)))
        .collect::<Vec<_>>()
    };
    let row = |rule: &str, outcome, score: Option<f64>| (rule.to_owned(), outcome, score);
    assert_eq!(
        outcome(89, 89),
        [
            row("disk/full", Outcome::Pass, None),
            row("disk/inodes", Outcome::Pass, None)
        ]
    );
    assert_eq!(
        outcome(90, 98),
        [
            row("disk/full", Outcome::Fail, Some(3.3)),
            row("disk/inodes", Outcome::Fail, Some(6.6))
        ],
        "90 % is a warning, 98 % an error"
    );
}

#[test]
fn a_disk_rule_skips_read_only_overlay_and_uncounted_filesystems_and_never_passes_unread() {
    let outcomes = |usage: Option<Value>, filesystem: &str| {
        disk(usage, filesystem)
            .into_iter()
            .map(|(rule, _, outcome, _)| (rule, outcome))
            .collect::<Vec<_>>()
    };
    let both = |outcome| {
        vec![
            ("disk/full".to_owned(), outcome),
            ("disk/inodes".to_owned(), outcome),
        ]
    };
    let full = json!({"blocks": 100, "inodes": 100, "read-only": false});
    assert_eq!(
        outcomes(
            Some(json!({"blocks": 100, "inodes": 100, "read-only": true})),
            "squashfs"
        ),
        both(Outcome::Skip),
        "a read-only image is always full"
    );
    assert_eq!(
        outcomes(Some(full.clone()), "overlay"),
        both(Outcome::Skip),
        "an overlay repeats the disk under it"
    );
    assert_eq!(
        outcomes(Some(json!({"read-only": false})), "proc"),
        both(Outcome::Skip),
        "proc counts no blocks"
    );
    assert_eq!(
        outcomes(None, "ext4"),
        both(Outcome::Unknown),
        "a failed statfs never passes"
    );
    let refused = |filesystem: &str| {
        let document = json!({"mounts": {"active": {"/srv": {"filesystem": filesystem}}, "usage": {}}, "collectors": {"mounts-active": {"status": "ok", "into": "mounts.active"}, "mounts-usage": {"status": "ok", "into": "mounts.usage", "unreadable": {"/srv": "permission denied"}}}});
        judge("disk", &document)
            .into_iter()
            .map(|(rule, _, outcome)| (rule, outcome))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        refused("fuse.sshfs"),
        both(Outcome::Unknown),
        "a mount the run may not reach never passes"
    );
    assert_eq!(
        refused("nsfs"),
        both(Outcome::Skip),
        "a namespace handle is no storage, reachable or not"
    );
    let root = json!({"collectors": {"mounts-active": {"status": "skipped", "reason": "live", "into": "mounts.active"}, "mounts-usage": {"status": "skipped", "reason": "live", "into": "mounts.usage"}}});
    assert_eq!(
        judge("disk", &root),
        [
            ("disk/full".to_owned(), String::new(), Outcome::Skip),
            ("disk/inodes".to_owned(), String::new(), Outcome::Skip)
        ],
        "a --root run skips what it never collects"
    );
}
