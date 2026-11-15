// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::vars::{Supplied, apply};

// Every check of one shipped ruleset over a document, as (rule, subject, outcome).
fn judge(ruleset: &str, document: &Value) -> Vec<(String, String, Outcome)> {
    scored(ruleset, document)
        .into_iter()
        .map(|(rule, subject, outcome, _)| (rule, subject, outcome))
        .collect()
}

// Like judge, with each check’s score.
fn scored(ruleset: &str, document: &Value) -> Vec<(String, String, Outcome, Option<f64>)> {
    checks(ruleset, document)
        .into_iter()
        .map(|c| (c.rule.clone(), c.subject_label(), c.outcome, c.score))
        .collect()
}

// The messages one rule of a shipped ruleset prints over a document.
fn judge_messages(ruleset: &str, document: &Value, rule: &str) -> Vec<String> {
    checks(ruleset, document)
        .into_iter()
        .filter(|c| c.rule == rule)
        .filter_map(|c| c.message)
        .collect()
}

// Every check of one shipped ruleset over a document.
fn checks(ruleset: &str, document: &Value) -> Vec<systemlint::judge::Check> {
    checks_with(ruleset, document, json!({}))
}

// Like checks, its vars filled from `config` as `check.vars` gives them, else their defaults.
fn checks_with(ruleset: &str, document: &Value, config: Value) -> Vec<systemlint::judge::Check> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../rulesets/{ruleset}.yaml"));
    let parsed = systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut rulesets = BTreeMap::from([(ruleset.to_owned(), parsed)]);
    let supplied = Supplied {
        config: config.as_object().unwrap().clone(),
        env: |_| None,
        ..Supplied::default()
    };
    apply(&mut rulesets, &supplied).unwrap();
    let library = Library::new(rulesets).unwrap();
    let rules: Vec<_> = library
        .select(&[ruleset.to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-12")
}

// A facts document holding the given sysctl settings, nested by their dots.
fn sysctl(settings: Value) -> Value {
    json!({"sysctl": {"settings": settings}, "collectors": {"sysctl": {"status": "ok", "into": "sysctl.settings"}}})
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

#[test]
fn shadow_ageing_fails_past_each_cis_bound_and_only_for_a_usable_password() {
    let age = |password: &str, max: Value, min: Value, warn: Value, inactive: Value| json!({"password": password, "max-days": max, "min-days": min, "warn-days": warn, "inactive-days": inactive});
    let document = accounts(
        json!({}),
        json!({}),
        json!({"edge": age("hash", json!(365), json!(1), json!(7), json!(45)),
               "past": age("hash", json!(366), json!(0), json!(6), json!(46)),
               "unset": age("hash", Value::Null, Value::Null, Value::Null, Value::Null),
               "low": age("hash", json!(0), json!(1), json!(7), json!(0)),
               "daemon": age("locked", json!(99999), json!(0), json!(0), Value::Null)}),
    );
    let expected = [
        ("daemon".into(), Outcome::Skip),
        ("edge".into(), Outcome::Pass),
        ("low".into(), Outcome::Pass),
        ("past".into(), Outcome::Fail),
        ("unset".into(), Outcome::Fail),
    ];
    for rule in ["min-days", "warn-days", "inactive-days"] {
        assert_eq!(
            account_rule(&format!("accounts/password-{rule}"), &document),
            expected,
            "{rule}"
        );
    }
    let mut zero = expected.clone();
    zero[2].1 = Outcome::Fail;
    assert_eq!(
        account_rule("accounts/password-max-days", &document),
        zero,
        "a maximum of 0 expires every password at once"
    );
    let daily: Vec<_> = checks_with("accounts", &document, json!({"password-max-days": 1}))
        .into_iter()
        .filter(|c| c.rule == "accounts/password-max-days")
        .map(|c| (c.subject_label(), c.outcome))
        .collect();
    assert_eq!(
        daily,
        [
            ("daemon".into(), Outcome::Skip),
            ("edge".into(), Outcome::Fail),
            ("low".into(), Outcome::Fail),
            ("past".into(), Outcome::Fail),
            ("unset".into(), Outcome::Fail),
        ],
        "a site asking for daily rotation sets the bound to 1"
    );
    let message = judge_messages("accounts", &document, "accounts/password-max-days");
    assert!(
        message
            .iter()
            .any(|m| m == "unset’s maximum password age in days is none, where 1 to 365 is asked"),
        "{message:?}"
    );
}

#[test]
fn a_missing_shadow_line_fails_and_a_shell_less_account_must_be_locked() {
    let entry = |shell: bool, password: &str| json!({"uid": 1, "password": password, "login-shell": shell, "shadowed": []});
    let document = accounts(
        json!({"root": entry(false, "shadow"), "mail": entry(false, "shadow"), "nobody": entry(false, "shadow"),
               "alice": entry(true, "shadow"), "inline": entry(false, "hash"), "ghost": entry(false, "shadow")}),
        json!({}),
        json!({"root": {"password": "hash"}, "mail": {"password": "hash"}, "nobody": {"password": "locked"},
               "alice": {"password": "hash"}, "inline": {"password": "hash"}, "ghost": {"password": "missing"}}),
    );
    assert_eq!(
        account_rule("accounts/shadow-missing", &document),
        [
            ("alice".into(), Outcome::Pass),
            ("ghost".into(), Outcome::Fail),
            ("inline".into(), Outcome::Pass),
            ("mail".into(), Outcome::Pass),
            ("nobody".into(), Outcome::Pass),
            ("root".into(), Outcome::Pass),
        ]
    );
    assert_eq!(
        account_rule("accounts/no-shell-unlocked", &document),
        [
            ("alice".into(), Outcome::Skip),
            ("ghost".into(), Outcome::Pass),
            ("inline".into(), Outcome::Skip),
            ("mail".into(), Outcome::Fail),
            ("nobody".into(), Outcome::Pass),
        ],
        "root is CIS’s exception, and an inline passwd hash never reads shadow"
    );
}

// A facts document holding the given mount tables, `active` skipped as under --root unless given.
// The facts formats words makes of an fstab text, as the shipped mounts-fstab collector asks.
fn fstab_facts(text: &str) -> Value {
    let yaml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../collectors/mounts-fstab.yaml"),
    )
    .unwrap();
    let collector = systemlint::collector::Collector::parse(&yaml).unwrap();
    let file = serde_json::from_value(json!({"path": "/etc/fstab", "content": text})).unwrap();
    let reply = systemlint_formats::words(
        &[systemlint_protocol::Input::File(file)],
        &collector.parse.with,
    )
    .unwrap();
    json!(reply.facts)
}

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
fn a_world_writable_mount_without_nosuid_nodev_or_noexec_fails() {
    let at = |options: &[&str]| json!({"/tmp": {"options": options}, "/dev/shm": {"options": ["rw", "nosuid", "nodev"]}, "/home": {"options": ["rw"]}});
    let row = |rule: &str, subject: &str, outcome| (rule.to_owned(), subject.to_owned(), outcome);
    assert_eq!(
        mounts(Some(at(&["rw", "nodev"])), at(&["rw"])),
        [
            row("mounts/fstab-nodev", "/dev/shm", Outcome::Skip),
            row("mounts/fstab-nodev", "/tmp", Outcome::Skip),
            row("mounts/fstab-noexec", "/dev/shm", Outcome::Skip),
            row("mounts/fstab-noexec", "/tmp", Outcome::Skip),
            row("mounts/fstab-nosuid", "/dev/shm", Outcome::Skip),
            row("mounts/fstab-nosuid", "/tmp", Outcome::Skip),
            row("mounts/nodev", "/dev/shm", Outcome::Pass),
            row("mounts/nodev", "/tmp", Outcome::Pass),
            row("mounts/noexec", "/dev/shm", Outcome::Fail),
            row("mounts/noexec", "/tmp", Outcome::Fail),
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
            row("mounts/fstab-noexec", "/dev/shm", Outcome::Fail),
            row("mounts/fstab-noexec", "/tmp", Outcome::Pass),
            row("mounts/fstab-nosuid", "/dev/shm", Outcome::Pass),
            row("mounts/fstab-nosuid", "/tmp", Outcome::Pass),
            row("mounts/nodev", "", Outcome::Skip),
            row("mounts/noexec", "", Outcome::Skip),
            row("mounts/nosuid", "", Outcome::Skip),
        ],
        "a root run judges the declared table and skips the live one"
    );
    let declared = |options: &[&str]| {
        mounts(
            None,
            fstab_facts(&format!("tmpfs /tmp tmpfs {}\n", options.join(","))),
        )
        .into_iter()
        .filter(|(rule, _, _)| rule.starts_with("mounts/fstab-"))
        .map(|(rule, _, outcome)| (rule, outcome))
        .collect::<Vec<_>>()
    };
    let fstab = |nodev, noexec, nosuid| {
        vec![
            ("mounts/fstab-nodev".to_owned(), nodev),
            ("mounts/fstab-noexec".to_owned(), noexec),
            ("mounts/fstab-nosuid".to_owned(), nosuid),
        ]
    };
    use Outcome::{Fail, Pass};
    assert_eq!(
        declared(&["users"]),
        fstab(Pass, Pass, Pass),
        "users implies all three"
    );
    assert_eq!(
        declared(&["owner"]),
        fstab(Pass, Fail, Pass),
        "owner implies nosuid and nodev"
    );
    assert_eq!(
        declared(&["users", "exec", "suid", "dev"]),
        fstab(Fail, Fail, Fail),
        "a later option undoes what users implies"
    );
    assert_eq!(
        declared(&["exec", "suid", "dev", "user"]),
        fstab(Pass, Pass, Pass),
        "user undoes an earlier suid, dev and exec"
    );
    assert_eq!(
        declared(&["nosuid", "nodev", "noexec", "suid"]),
        fstab(Pass, Pass, Fail),
        "a later suid undoes nosuid"
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

// A local, enabled, simple service running as root with no sandbox, then `unit` and `state` changes applied, a null state dropping it.
fn service(unit: Value, state: Value) -> Value {
    let mut document = json!({"systemd": {"units": {"x.service": {"path": "/etc/systemd/system/x.service", "file": "/etc/systemd/system/x.service", "alias-of": null, "drop-ins": [], "type": "simple", "sections": {"Service": {"ExecStart": ["/opt/x/run"]}}, "sandbox": {"user": "root", "dynamic-user": false, "no-new-privileges": false, "protect-system": "no", "capability-bounding-set": "all"}}}, "state": {"x.service": {"enabled": true, "masked": false}}}, "collectors": {"systemd-units": {"status": "ok", "into": "systemd.units"}, "systemd-state": {"status": "ok", "into": "systemd.state"}}});
    let at = &mut document["systemd"]["units"]["x.service"];
    for (key, value) in unit.as_object().unwrap() {
        match key.strip_prefix("sandbox.") {
            Some(setting) => at["sandbox"][setting] = value.clone(),
            None => at[key] = value.clone(),
        }
    }
    if state.is_null() {
        document["systemd"]["state"] = json!({});
    }
    for (key, value) in state.as_object().into_iter().flatten() {
        document["systemd"]["state"]["x.service"][key] = value.clone();
    }
    document
}

// The outcome of services/unconfined-root over one unit.
fn unconfined(unit: Value, state: Value) -> Outcome {
    judge("services", &service(unit, state))[0].2
}

#[test]
fn a_local_root_service_fails_until_any_one_confinement_is_set() {
    let sandbox =
        |key: &str, value: Value| unconfined(json!({format!("sandbox.{key}"): value}), json!({}));
    assert_eq!(unconfined(json!({}), json!({})), Outcome::Fail);
    assert_eq!(sandbox("user", json!("0")), Outcome::Fail, "uid 0 is root");
    assert_eq!(sandbox("user", json!("svc")), Outcome::Pass);
    assert_eq!(sandbox("no-new-privileges", json!(true)), Outcome::Pass);
    assert_eq!(sandbox("protect-system", json!("yes")), Outcome::Pass);
    assert_eq!(
        sandbox("capability-bounding-set", json!(["CAP_NET_BIND_SERVICE"])),
        Outcome::Pass
    );
    assert_eq!(sandbox("capability-bounding-set", json!([])), Outcome::Pass);
}

#[test]
fn only_enabled_unmasked_long_running_units_written_on_the_host_are_judged() {
    assert_eq!(
        unconfined(
            json!({"file": "/usr/local/lib/systemd/system/x.service"}),
            json!({})
        ),
        Outcome::Fail
    );
    assert_eq!(
        unconfined(json!({"file": "/opt/x/x.service"}), json!({})),
        Outcome::Fail,
        "a unit linked in from /opt is local"
    );
    for vendor in [
        "/usr/lib/systemd/system/x.service",
        "/lib/systemd/system/x.service",
        "/run/systemd/system/x.service",
    ] {
        assert_eq!(
            unconfined(json!({"file": vendor}), json!({})),
            Outcome::Skip,
            "{vendor} is not written by hand"
        );
    }
    assert_eq!(
        unconfined(json!({"alias-of": "y.service"}), json!({})),
        Outcome::Skip,
        "an alias is judged under its unit"
    );
    assert_eq!(
        unconfined(json!({"type": "oneshot"}), json!({})),
        Outcome::Skip
    );
    assert_eq!(
        unconfined(json!({"type": "notify"}), json!({})),
        Outcome::Fail
    );
    assert_eq!(
        unconfined(
            json!({"sections": {"Unit": {"X-Snappy": ["yes"]}}}),
            json!({})
        ),
        Outcome::Skip,
        "snap run confines it"
    );
    assert_eq!(
        unconfined(
            json!({"sections": {"Unit": {"Description": ["x"]}}}),
            json!({})
        ),
        Outcome::Fail
    );
    assert_eq!(
        unconfined(json!({}), json!({"enabled": false})),
        Outcome::Skip
    );
    assert_eq!(
        unconfined(json!({}), json!({"masked": true})),
        Outcome::Skip
    );
    assert_eq!(
        unconfined(json!({}), Value::Null),
        Outcome::Unknown,
        "no state, no verdict"
    );
    let empty = json!({"systemd": {"units": {}}, "collectors": {"systemd-units": {"status": "ok", "into": "systemd.units"}}});
    assert_eq!(
        judge("services", &empty)[0].2,
        Outcome::NotApplicable,
        "no unit file, no systemd"
    );
}

// The setuid rule outcomes for one entry of the inventory, or with no setuid facts at all on None.
fn setuid(stat: Option<Value>) -> Vec<(String, Outcome)> {
    let mut document = json!({"collectors": {"setuid": {"status": "ok", "into": "setuid"}}});
    if let Some(stat) = stat {
        document["setuid"] = json!({"/opt/tool": stat});
    }
    judge("setuid", &document)
        .into_iter()
        .map(|(rule, _, o)| (rule, o))
        .collect()
}

#[test]
fn a_setuid_file_or_its_directory_fails_when_another_user_may_write_it() {
    let rules = |world, group| {
        vec![
            ("setuid/group-writable".to_owned(), group),
            ("setuid/world-writable".to_owned(), world),
        ]
    };
    let entry = |kind: &str, mode: &str| {
        let bits = u32::from_str_radix(mode, 8).unwrap();
        json!({"exists": true, "kind": kind, "mode": mode, "world-writable": bits & 0o002 != 0, "group-writable": bits & 0o020 != 0})
    };
    use Outcome::{Fail, Pass, Unknown};
    for (kind, mode, world, group) in [
        ("directory", "0755", Pass, Pass),
        ("directory", "0757", Fail, Pass),
        ("directory", "0775", Pass, Fail),
        ("directory", "1777", Pass, Pass),
        ("directory", "2777", Fail, Fail),
        ("directory", "3777", Pass, Pass),
        ("file", "4755", Pass, Pass),
        ("file", "4757", Fail, Pass),
        ("file", "2775", Pass, Fail),
        ("file", "5777", Fail, Fail),
    ] {
        assert_eq!(
            setuid(Some(entry(kind, mode))),
            rules(world, group),
            "{kind} {mode}"
        );
    }
    assert_eq!(setuid(None), rules(Unknown, Unknown));
}

// The tls checks of one probed URL, its collector `web` into `probes.web`, sorted by rule.
fn tls(url: &str, probe: Value) -> Vec<(String, Outcome, Option<f64>)> {
    let document = json!({"probes": {"web": {"http": {url: probe}}}, "collectors": {"web": {"status": "ok", "into": "probes.web"}}});
    let mut checks: Vec<_> = scored("tls", &document)
        .into_iter()
        .map(|(rule, _, outcome, score)| (rule, outcome, score.map(|s| (s * 10.0).round() / 10.0)))
        .collect();
    checks.sort_by(|a, b| a.0.cmp(&b.0));
    checks
}

#[test]
fn a_certificate_fails_expired_or_nearly_so_and_untrusted_only_while_valid() {
    let url = "https://kiota.test/";
    let cert = |percent: i64, days: i64, verified: bool| {
        tls(
            url,
            json!({"tls": {"verified": verified, "percent-left": percent, "days-left": days, "not-after": "2030-01-01T00:00:00Z"}}),
        )
    };
    let row = |rule: &str, outcome, score: Option<f64>| (rule.to_owned(), outcome, score);
    assert_eq!(
        cert(10, 9, true),
        [
            row("tls/expired", Outcome::Pass, None),
            row("tls/expiring", Outcome::Pass, None),
            row("tls/untrusted", Outcome::Pass, None)
        ]
    );
    assert_eq!(
        cert(9, 8, true)[1],
        row("tls/expiring", Outcome::Fail, Some(3.3))
    );
    assert_eq!(
        cert(0, 0, true)[..2],
        [
            row("tls/expired", Outcome::Pass, None),
            row("tls/expiring", Outcome::Fail, Some(6.6))
        ],
        "a certificate on its last day is not yet expired"
    );
    assert_eq!(
        cert(-1, -1, false),
        [
            row("tls/expired", Outcome::Fail, Some(8.5)),
            row("tls/expiring", Outcome::Skip, None),
            row("tls/untrusted", Outcome::Skip, None)
        ],
        "an expired certificate is one finding, not three"
    );
    assert_eq!(
        cert(50, 0, false)[2],
        row("tls/untrusted", Outcome::Fail, Some(7.0))
    );
    assert_eq!(
        tls(url, json!({"error": "connection refused"})),
        [
            row("tls/expired", Outcome::Unknown, None),
            row("tls/expiring", Outcome::Unknown, None),
            row("tls/untrusted", Outcome::Unknown, None)
        ],
        "a probe with no answer never passes"
    );
    assert_eq!(
        tls("http://kiota.test/", json!({"status": 200})),
        [],
        "plain HTTP has no certificate to judge"
    );
}

#[test]
fn the_tls_rules_do_not_apply_without_a_probe_and_are_unknown_offline() {
    let outcomes = |document: Value| {
        judge("tls", &document)
            .into_iter()
            .map(|(_, _, outcome)| outcome)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        outcomes(json!({"collectors": {"sysctl": {"status": "ok", "into": "sysctl.settings"}}})),
        [Outcome::NotApplicable; 3],
        "a host with no network collector has nothing to judge"
    );
    assert_eq!(
        outcomes(
            json!({"collectors": {"web": {"status": "skipped", "reason": "network", "into": "probes.web"}}})
        ),
        [Outcome::Unknown; 3],
        "an offline run never passes"
    );
}

// The resolv checks of one probed nameserver, its collector into `resolv.probes`, sorted by rule.
fn resolv(probe: Value) -> Vec<(String, Outcome)> {
    let document = json!({"resolv": {"probes": {"nameserver": {"192.0.2.1": probe}}}, "collectors": {"resolv-nameservers": {"status": "ok", "into": "resolv.probes"}}});
    let mut checks: Vec<_> = judge("resolv", &document)
        .into_iter()
        .map(|(rule, _, outcome)| (rule, outcome))
        .collect();
    checks.sort();
    checks
}

#[test]
fn a_nameserver_fails_silent_or_refusing_and_never_passes_unasked() {
    let row = |rule: &str, outcome| (rule.to_owned(), outcome);
    assert_eq!(
        resolv(json!({"answered": true, "codes": ["NOERROR", "SERVFAIL"]})),
        [
            row("resolv/nameserver-refuses", Outcome::Pass),
            row("resolv/nameserver-silent", Outcome::Pass)
        ]
    );
    assert_eq!(
        resolv(json!({"answered": true, "codes": ["NOERROR", "REFUSED"]})),
        [
            row("resolv/nameserver-refuses", Outcome::Fail),
            row("resolv/nameserver-silent", Outcome::Pass)
        ]
    );
    assert_eq!(
        resolv(json!({"answered": false})),
        [
            row("resolv/nameserver-refuses", Outcome::Skip),
            row("resolv/nameserver-silent", Outcome::Fail)
        ],
        "a silent nameserver is one finding, not two"
    );
    assert_eq!(
        resolv(json!({"error": "answered 1 of 2 queries"})),
        [
            row("resolv/nameserver-refuses", Outcome::Unknown),
            row("resolv/nameserver-silent", Outcome::Unknown)
        ],
        "a nameserver answering some queries is never judged"
    );
}

#[test]
fn the_resolv_rules_do_not_apply_without_their_collector_and_are_unknown_offline() {
    let outcomes = |document: Value| {
        judge("resolv", &document)
            .into_iter()
            .map(|(_, _, outcome)| outcome)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        outcomes(json!({"collectors": {"sysctl": {"status": "ok", "into": "sysctl.settings"}}})),
        [Outcome::NotApplicable; 2]
    );
    assert_eq!(
        outcomes(
            json!({"collectors": {"resolv-nameservers": {"status": "skipped", "reason": "network", "into": "resolv.probes"}}})
        ),
        [Outcome::Unknown; 2],
        "an offline run never passes"
    );
    assert_eq!(
        outcomes(
            json!({"resolv": {"probes": {}}, "collectors": {"resolv-nameservers": {"status": "ok", "into": "resolv.probes"}}})
        ),
        [Outcome::NotApplicable; 2],
        "a resolv.conf naming no nameserver leaves nothing to judge"
    );
}

// A document with the auth collectors’ facts: login.defs keys, pam_limits entries of limits.conf and PAM files by path.
fn auth(defs: Value, limits: Value, pam: Value) -> Value {
    json!({"auth": {"login-defs": defs, "limits": {"/etc/security/limits.conf": limits}, "pam": pam}, "collectors": {
        "auth-login-defs": {"status": "ok", "into": "auth.login-defs"},
        "auth-limits": {"status": "ok", "into": "auth.limits"},
        "auth-pam": {"status": "ok", "into": "auth.pam"}}})
}

// The outcomes one rule of one ruleset gives over a document.
fn outcomes(ruleset: &str, rule: &str, document: &Value) -> Vec<Outcome> {
    judge(ruleset, document)
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, _, outcome)| outcome)
        .collect()
}

#[test]
fn the_login_umask_passes_from_027_and_fails_at_022_or_unset() {
    let umask = |defs: Value| {
        outcomes(
            "login-defs",
            "login-defs/umask",
            &auth(defs, json!([]), json!({})),
        )
    };
    for strict in ["027", "0027", "077", "037"] {
        assert_eq!(umask(json!({"UMASK": strict})), [Outcome::Pass], "{strict}");
    }
    for loose in ["022", "026", "007", "27"] {
        assert_eq!(umask(json!({"UMASK": loose})), [Outcome::Fail], "{loose}");
    }
    assert_eq!(
        umask(json!({"UMASK": 27})),
        [Outcome::Fail],
        "a bare 27 is typed a number"
    );
    assert_eq!(
        umask(json!({"PASS_MAX_DAYS": 99999})),
        [Outcome::Fail],
        "unset is 022"
    );
    assert_eq!(umask(json!({})), [Outcome::NotApplicable], "no login.defs");
}

// A PAM entry as the auth-pam collector’s words columns write it.
fn entry(kind: &str, control: &str, module: &str, arguments: &[&str]) -> Value {
    json!({"line": 1, "type": kind, "control": control, "module": module, "arguments": arguments})
}

#[test]
fn pam_permit_fails_only_where_it_settles_the_auth_stack() {
    let permit = |control: &str, kind: &str| {
        let pam = json!({"/etc/pam.d/x": [entry(kind, control, "pam_permit.so", &[])]});
        outcomes(
            "pam",
            "pam/permit-sufficient",
            &auth(json!({}), json!([]), pam),
        )
    };
    assert_eq!(permit("sufficient", "auth"), [Outcome::Fail]);
    assert_eq!(
        permit("Sufficient", "-Auth"),
        [Outcome::Fail],
        "Linux-PAM ignores case"
    );
    assert_eq!(
        permit("success=done  default=ignore", "auth"),
        [Outcome::Fail]
    );
    assert_eq!(
        permit("default=ignore success=done", "auth"),
        [Outcome::Fail]
    );
    assert_eq!(permit("success=done1", "auth"), [Outcome::Pass]);
    assert_eq!(permit("insufficient", "auth"), [Outcome::Pass]);
    assert_eq!(
        permit("required", "auth"),
        [Outcome::Pass],
        "Debian’s common-auth tail"
    );
    assert_eq!(permit("success=1 default=ignore", "auth"), [Outcome::Pass]);
    assert_eq!(permit("sufficient", "session"), [Outcome::Pass]);
}

#[test]
fn pam_unix_nullok_fails_on_its_auth_line_only() {
    let nullok = |kind: &str, arguments: &[&str]| {
        let pam =
            json!({"/etc/pam.d/common-auth": [entry(kind, "required", "pam_unix.so", arguments)]});
        outcomes("pam", "pam/nullok", &auth(json!({}), json!([]), pam))
    };
    assert_eq!(nullok("auth", &["nullok"]), [Outcome::Fail]);
    assert_eq!(nullok("-auth", &["nullok"]), [Outcome::Fail]);
    assert_eq!(nullok("auth", &["nullok_secure"]), [Outcome::Fail]);
    assert_eq!(nullok("auth", &["try_first_pass"]), [Outcome::Pass]);
    assert_eq!(nullok("password", &["nullok"]), [Outcome::Pass]);
}

#[test]
fn a_password_stack_without_faillock_fails_and_one_without_pam_unix_is_not_judged() {
    let lockout = |entries: Value| {
        outcomes(
            "pam",
            "pam/no-lockout",
            &auth(
                json!({}),
                json!([]),
                json!({"/etc/pam.d/common-auth": entries}),
            ),
        )
    };
    let unix = entry("auth", "required", "pam_unix.so", &[]);
    let faillock = entry("auth", "required", "pam_faillock.so", &["preauth"]);
    assert_eq!(lockout(json!([unix])), [Outcome::Fail]);
    assert_eq!(lockout(json!([faillock, unix])), [Outcome::Pass]);
    let pathed = entry("auth", "required", "/usr/lib/security/pam_unix.so", &[]);
    assert_eq!(
        lockout(json!([pathed])),
        [Outcome::Fail],
        "a module named by path"
    );
    let lookalike = entry("auth", "required", "pam_unix.so.bak", &[]);
    assert_eq!(lockout(json!([lookalike])), [Outcome::Pass]);
    assert_eq!(
        lockout(json!([entry("auth", "required", "pam_sss.so", &[])])),
        [Outcome::Pass]
    );
    assert_eq!(
        outcomes(
            "pam",
            "pam/no-lockout",
            &auth(json!({}), json!([]), json!({}))
        ),
        [Outcome::NotApplicable],
        "no /etc/pam.d"
    );
}

// A pam_limits core entry.
fn core(domain: &str, kind: &str, value: Value) -> Value {
    json!({"domain": domain, "type": kind, "item": "core", "value": value, "line": 1})
}

#[test]
fn core_dumps_pass_only_with_a_hard_zero_for_everyone_and_none_raised() {
    let pam = json!({"/etc/pam.d/login": []});
    let limit = |entries: Value| {
        outcomes(
            "coredump",
            "coredump/no-hard-limit",
            &auth(json!({}), entries, pam.clone()),
        )
    };
    assert_eq!(limit(json!([core("*", "hard", json!(0))])), [Outcome::Pass]);
    assert_eq!(limit(json!([core("*", "-", json!(0))])), [Outcome::Pass]);
    assert_eq!(
        limit(json!([core("*", "Hard", json!(0))])),
        [Outcome::Pass],
        "pam_limits compares without case"
    );
    assert_eq!(
        limit(json!([core("*", "soft", json!(0))])),
        [Outcome::Fail],
        "soft is raised at will"
    );
    assert_eq!(
        limit(json!([core("root", "hard", json!(0))])),
        [Outcome::Fail],
        "not every user"
    );
    assert_eq!(
        limit(json!([core("*", "hard", json!(1))])),
        [Outcome::Fail],
        "1 is the edge above 0"
    );
    assert_eq!(
        limit(json!([
            core("*", "hard", json!(0)),
            core("@dev", "hard", json!("unlimited"))
        ])),
        [Outcome::Fail]
    );
    assert_eq!(limit(json!([])), [Outcome::Fail]);
    let mut split = auth(json!({}), json!([core("*", "hard", json!(0))]), pam.clone());
    split["auth"]["limits"]["/etc/security/limits.d/dev.conf"] =
        json!([core("@dev", "-", json!("unlimited"))]);
    assert_eq!(
        outcomes("coredump", "coredump/no-hard-limit", &split),
        [Outcome::Fail],
        "a drop-in raising it"
    );
    let mut dropin = auth(json!({}), json!([]), pam.clone());
    dropin["auth"]["limits"]["/etc/security/limits.d/core.conf"] =
        json!([core("*", "hard", json!(0))]);
    assert_eq!(
        outcomes("coredump", "coredump/no-hard-limit", &dropin),
        [Outcome::Pass],
        "the zero in a drop-in"
    );
    assert_eq!(
        outcomes(
            "coredump",
            "coredump/no-hard-limit",
            &auth(json!({}), json!([]), json!({}))
        ),
        [Outcome::Skip],
        "no PAM, so no pam_limits"
    );
}

// The cron/world-readable outcomes per path for the given stats, or with no cron facts at all on None.
fn cron(stats: Option<Value>) -> Vec<(String, Outcome)> {
    let mut document =
        json!({"collectors": {"files-cron": {"status": "ok", "into": "files.cron"}}});
    if let Some(stats) = stats {
        document["files"] = json!({"cron": stats});
    }
    judge("cron", &document)
        .into_iter()
        .map(|(_, subject, o)| (subject, o))
        .collect()
}

#[test]
fn a_system_crontab_or_cron_directory_fails_once_others_may_read_it() {
    let stat = |kind: &str, mode: &str| json!({"exists": true, "kind": kind, "mode": mode});
    use Outcome::{Fail, Pass, Unknown};
    for (path, kind, mode, outcome) in [
        ("/etc/crontab", "file", "0640", Pass),
        ("/etc/crontab", "file", "0644", Fail),
        ("/etc/crontab", "file", "0601", Fail),
        ("/etc/cron.d", "directory", "0750", Pass),
        ("/etc/cron.d", "directory", "0751", Fail),
        ("/etc/cron.yearly", "directory", "0755", Fail),
        ("/etc/cron.daily", "symlink", "0777", Outcome::Skip),
    ] {
        assert_eq!(
            cron(Some(json!({path: stat(kind, mode)}))),
            [(path.to_owned(), outcome)],
            "{path} {kind} {mode}"
        );
    }
    let unjudged = json!({
        "/etc/cron.d/backup": stat("file", "0644"),
        "/etc/cron.allow": stat("file", "0644"),
    });
    assert_eq!(
        cron(Some(unjudged)),
        [],
        "files in a directory and the allow lists"
    );
    assert_eq!(cron(None), [(String::new(), Unknown)]);
}

// The module names the kernel-modules ruleset defines, in the file’s spelling.
fn modules() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/kernel-modules.yaml");
    let ruleset: Value =
        systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    ruleset["rules"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|id| id.strip_prefix("kernel-modules/"))
        .filter(|m| *m != "builtin" && !m.ends_with("-loaded") && !m.ends_with("-blacklist"))
        .map(str::to_owned)
        .collect()
}

// The outcome of each kernel-modules rule on module m, keyed by the rule’s suffix.
fn module(m: &str, kernel: Value) -> BTreeMap<String, Outcome> {
    judge("kernel-modules", &json!({"kernel": kernel}))
        .into_iter()
        .filter_map(|(rule, _, outcome)| {
            let tail = rule.strip_prefix(&format!("kernel-modules/{m}"))?;
            (tail.is_empty() || tail.starts_with('-')).then(|| (tail.to_owned(), outcome))
        })
        .collect()
}

#[test]
fn every_kernel_module_rule_passes_when_turned_away_and_fails_when_loadable() {
    use Outcome::{Fail, Pass, Skip, Unknown};
    let names = modules();
    assert_eq!(names.len(), 16, "{names:?}");
    for m in &names {
        let k = m.replace('-', "_");
        let host = |command: Value, blacklist: Value, loaded: Value| json!({"shipped": {m.as_str(): {}}, "install": {k.as_str(): {"command": command}}, "blacklist": blacklist, "loaded": loaded});
        let outcomes = |a, b, c| {
            BTreeMap::from([
                (String::new(), a),
                ("-blacklist".to_owned(), b),
                ("-loaded".to_owned(), c),
            ])
        };
        assert_eq!(
            module(
                m,
                host(json!(["/bin/false"]), json!({k.as_str(): {}}), json!({}))
            ),
            outcomes(Pass, Pass, Pass),
            "{m}: turned away, blacklisted, not loaded"
        );
        assert_eq!(
            module(
                m,
                host(json!(["/usr/bin/true"]), json!({}), json!({k.as_str(): {}}))
            ),
            outcomes(Pass, Fail, Fail),
            "{m}: /usr/bin/true passes as CIS accepts it"
        );
        for command in [
            json!(["/sbin/modprobe", "--ignore-install", k]),
            json!(["/bin/falsey"]),
            json!([]),
        ] {
            assert_eq!(
                module(m, host(command.clone(), json!({}), json!({})))[""],
                Fail,
                "{m}: {command}"
            );
        }
        let unshipped = json!({"shipped": {}, "install": {}, "blacklist": {}});
        assert_eq!(
            module(m, unshipped),
            outcomes(Skip, Skip, Skip),
            "{m}: not shipped, under --root"
        );
        assert_eq!(
            module(m, json!({"shipped": {m.as_str(): {}}, "loaded": {}})),
            outcomes(Unknown, Unknown, Pass),
            "{m}: a failed modprobe collector is unknown, never a finding"
        );
    }
}

#[test]
fn only_the_listed_kernel_modules_run_by_default() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/kernel-modules.yaml");
    let parsed = systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([("kernel-modules".to_owned(), parsed)])).unwrap();
    let picked = library.select_for(&[]).unwrap().rules;
    let default: Vec<&str> = picked
        .keys()
        .map(|id| id.trim_start_matches("kernel-modules/"))
        .collect();
    let mut expected: Vec<String> = [
        "cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf", "dccp", "rds", "sctp", "tipc",
    ]
    .iter()
    .flat_map(|m| [m.to_string(), format!("{m}-loaded")])
    .chain(
        [
            "firewire-core-loaded",
            "atm-loaded",
            "can-loaded",
            "builtin",
        ]
        .map(str::to_owned),
    )
    .collect();
    expected.sort();
    assert_eq!(default, expected);
    assert!(
        library.definitions.values().all(|spec| spec
            .tags
            .iter()
            .any(|t| t.starts_with("cis-ubuntu-26.04:"))
            || spec.tags == ["default", "kernel"]),
        "every module rule but builtin carries its CIS control"
    );
}

#[test]
fn a_builtin_module_from_the_default_list_is_a_finding() {
    let checks = judge(
        "kernel-modules",
        &json!({"kernel": {"builtin": {"sctp": {}, "unix": {}, "squashfs": {}}}}),
    );
    let builtin: Vec<_> = checks
        .into_iter()
        .filter(|(rule, _, _)| rule == "kernel-modules/builtin")
        .collect();
    assert_eq!(
        builtin,
        [(
            "kernel-modules/builtin".to_owned(),
            "sctp".to_owned(),
            Outcome::Fail
        )]
    );
}

// A Debian-like facts document whose apt-config dump printed `config`, or failed with None.
fn apt_config(config: Option<Value>) -> Value {
    let status = if config.is_some() { "ok" } else { "error" };
    let mut document = json!({"os": {"release": {"ID": "ubuntu"}}, "unattended-upgrades": {"binary": {"/usr/bin/unattended-upgrade": {"kind": "file"}}}, "collectors": {"os-release": {"status": "ok", "into": "os.release"}, "apt-config": {"status": status, "into": "apt.config"}, "unattended-upgrades-binary": {"status": "ok", "into": "unattended-upgrades.binary"}}});
    if let Some(config) = config {
        document["apt"] = json!({"config": config});
    }
    document
}

// The outcome of one rule of a ruleset over apt-config's keys.
fn apt_rule(ruleset: &str, rule: &str, config: Option<Value>) -> Outcome {
    judge(ruleset, &apt_config(config))
        .into_iter()
        .find(|(r, _, _)| r == rule)
        .unwrap_or_else(|| panic!("{rule} gave no check"))
        .2
}

#[test]
fn an_apt_switch_fails_only_on_a_value_apt_reads_as_the_unsafe_one() {
    let on = [
        "1", "01", "0x1", "+1", "yes", "TRUE", "with", "On", "enable",
    ];
    let off = [
        "0", "", "-0", "0x0", "no", "False", "without", "OFF", "disable",
    ];
    let ignored = ["2", "-1", "maybe", "0x"];
    let unsafe_when_on = [
        (
            "apt/allow-unauthenticated",
            "APT::Get::AllowUnauthenticated",
        ),
        (
            "apt/allow-insecure-repositories",
            "Acquire::AllowInsecureRepositories",
        ),
        (
            "apt/allow-weak-repositories",
            "Acquire::AllowWeakRepositories",
        ),
        (
            "apt/allow-downgrade-to-insecure",
            "Acquire::AllowDowngradeToInsecureRepositories",
        ),
    ];
    for (rule, key) in unsafe_when_on {
        let one = |value: &str| apt_rule("apt", rule, Some(json!({key: value})));
        assert_eq!(
            apt_rule("apt", rule, Some(json!({}))),
            Outcome::Pass,
            "{rule} unset"
        );
        on.iter()
            .for_each(|v| assert_eq!(one(v), Outcome::Fail, "{rule} {v:?}"));
        off.iter()
            .chain(&ignored)
            .for_each(|v| assert_eq!(one(v), Outcome::Pass, "{rule} {v:?}"));
        let lower = key.to_lowercase();
        assert_eq!(
            apt_rule("apt", rule, Some(json!({lower: "1"}))),
            Outcome::Fail,
            "{rule} lowercase"
        );
        assert_eq!(
            apt_rule("apt", rule, None),
            Outcome::Unknown,
            "{rule} with apt-config failed"
        );
    }
    let check_date = |value: &str| {
        apt_rule(
            "apt",
            "apt/check-date-off",
            Some(json!({"Acquire::Check-Date": value})),
        )
    };
    assert_eq!(
        apt_rule("apt", "apt/check-date-off", Some(json!({}))),
        Outcome::Pass
    );
    off.iter()
        .for_each(|v| assert_eq!(check_date(v), Outcome::Fail, "check-date {v:?}"));
    on.iter()
        .chain(&ignored)
        .for_each(|v| assert_eq!(check_date(v), Outcome::Pass, "check-date {v:?}"));
    let mut debian_only = apt_config(Some(json!({"APT::Get::AllowUnauthenticated": "1"})));
    debian_only["os"]["release"] = json!({"ID": "fedora"});
    assert!(
        judge("apt", &debian_only)
            .iter()
            .all(|(_, _, o)| *o == Outcome::NotApplicable)
    );
}

#[test]
fn weak_dependencies_fail_until_recommends_is_off_and_suggests_stays_off() {
    let weak = |config: Value| apt_rule("apt", "apt/weak-dependencies", Some(config));
    assert_eq!(weak(json!({})), Outcome::Fail, "apt recommends by default");
    assert_eq!(weak(json!({"APT::Install-Recommends": "0"})), Outcome::Pass);
    assert_eq!(
        weak(json!({"APT::Install-Recommends": "2"})),
        Outcome::Fail,
        "apt ignores 2 and recommends"
    );
    assert_eq!(
        weak(json!({"APT::Install-Recommends": "0", "APT::Install-Suggests": "0"})),
        Outcome::Pass
    );
    assert_eq!(
        weak(json!({"APT::Install-Recommends": "false", "APT::Install-Suggests": "1"})),
        Outcome::Fail
    );
}

#[test]
fn unattended_upgrades_fail_off_or_on_stale_lists_and_only_where_installed() {
    let run = |rule: &str, config: Value| apt_rule("unattended-upgrades", rule, Some(config));
    let on = json!({"APT::Periodic::Unattended-Upgrade": "1", "APT::Periodic::Update-Package-Lists": "1"});
    assert_eq!(run("unattended-upgrades/off", on.clone()), Outcome::Pass);
    assert_eq!(run("unattended-upgrades/stale-lists", on), Outcome::Pass);
    assert_eq!(
        run("unattended-upgrades/off", json!({})),
        Outcome::Fail,
        "unset is 0"
    );
    assert_eq!(
        run(
            "unattended-upgrades/off",
            json!({"APT::Periodic::Unattended-Upgrade": "0"})
        ),
        Outcome::Fail
    );
    for interval in ["always", "1d", "00", "12h"] {
        assert_eq!(
            run(
                "unattended-upgrades/off",
                json!({"APT::Periodic::Unattended-Upgrade": interval})
            ),
            Outcome::Pass,
            "{interval}"
        );
    }
    let stale = json!({"APT::Periodic::Unattended-Upgrade": "1", "APT::Periodic::Update-Package-Lists": "0"});
    assert_eq!(run("unattended-upgrades/stale-lists", stale), Outcome::Fail);
    assert_eq!(
        run(
            "unattended-upgrades/stale-lists",
            json!({"APT::Periodic::Unattended-Upgrade": "1"})
        ),
        Outcome::Fail,
        "unset lists"
    );
    assert_eq!(
        run("unattended-upgrades/stale-lists", json!({})),
        Outcome::Skip,
        "off is the other rule’s finding"
    );
    let mut absent = apt_config(Some(json!({})));
    absent["unattended-upgrades"]["binary"] = json!({});
    assert!(
        judge("unattended-upgrades", &absent)
            .iter()
            .all(|(_, _, o)| *o == Outcome::NotApplicable)
    );
}

#[test]
fn unattended_upgrades_keep_replaced_packages_until_both_removals_are_on() {
    let keeps = |config: Value| {
        apt_rule(
            "unattended-upgrades",
            "unattended-upgrades/keeps-replaced",
            Some(config),
        )
    };
    assert_eq!(
        keeps(json!({})),
        Outcome::Fail,
        "unused dependencies stay by default"
    );
    assert_eq!(
        keeps(json!({"Unattended-Upgrade::Remove-Unused-Dependencies": "true"})),
        Outcome::Pass,
        "kernels go by default"
    );
    assert_eq!(
        keeps(
            json!({"Unattended-Upgrade::Remove-Unused-Dependencies": "true", "Unattended-Upgrade::Remove-Unused-Kernel-Packages": "false"})
        ),
        Outcome::Fail
    );
    assert_eq!(
        keeps(json!({"Unattended-Upgrade::Remove-Unused-Dependencies": "maybe"})),
        Outcome::Fail,
        "an unread value keeps the default"
    );
}

// The outcomes of restart/replaced-code for one service’s replaced paths and its systemd state.
fn restart(replaced: Option<Value>, state: Value) -> Vec<(String, Outcome)> {
    let mut document = json!({"systemd": {"state": state}});
    if let Some(replaced) = replaced {
        document["processes"] =
            json!({"services": {"app.service": {"pids": [10], "replaced": replaced}}});
    }
    judge("restart", &document)
        .into_iter()
        .map(|(_, subject, o)| (subject, o))
        .collect()
}

#[test]
fn a_running_service_fails_from_its_first_replaced_file_and_a_stopping_one_never() {
    let running = |active: &str| json!({"app.service": {"enabled": true, "masked": false, "active": active, "sub": "x"}});
    let app = |o| vec![("app.service".to_owned(), o)];
    assert_eq!(
        restart(Some(json!([])), running("active")),
        app(Outcome::Pass)
    );
    assert_eq!(
        restart(Some(json!(["/usr/lib/libssl.so.3"])), running("active")),
        app(Outcome::Fail)
    );
    assert_eq!(
        restart(Some(json!(["/usr/lib/libssl.so.3"])), running("activating")),
        app(Outcome::Skip),
        "a oneshot still running, as apt upgrading itself, is about to exit"
    );
    assert_eq!(
        restart(
            Some(json!(["/usr/lib/libssl.so.3"])),
            running("deactivating")
        ),
        app(Outcome::Skip)
    );
    let mut root = json!({"systemd": {"state": running("active")}});
    root["collectors"]["processes-services"] =
        json!({"status": "skipped", "into": "processes.services", "reason": "live only"});
    let skipped = checks("restart", &root);
    assert_eq!(
        (skipped[0].outcome, skipped[0].collector.as_deref()),
        (Outcome::Unknown, Some("processes-services")),
        "--root or an unprivileged run reads no process, which the report prints as not run"
    );
    assert_eq!(
        restart(
            Some(json!(["/usr/lib/libssl.so.3"])),
            json!({"app.service": {"enabled": true, "masked": false}})
        ),
        app(Outcome::Unknown),
        "no active state from the manager is unknown, never a finding"
    );
}
