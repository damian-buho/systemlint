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
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../rulesets/{ruleset}.yaml"));
    let parsed = systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([(ruleset.to_owned(), parsed)])).unwrap();
    let rules: Vec<_> = library.select(&[ruleset.to_owned()]).unwrap().into_iter().map(|(id, spec)| compile(&id, spec).unwrap()).collect();
    lint(document, &rules, &[], "2026-11-12").into_iter().map(|c| (c.rule.clone(), c.subject_label(), c.outcome)).collect()
}

// A facts document holding the given sysctl settings, nested by their dots.
fn sysctl(settings: Value) -> Value {
    json!({"sysctl": {"source": "effective", "settings": settings}, "collectors": {"sysctl": {"status": "ok", "into": "sysctl"}}})
}

// The settings object for one dotted key.
fn key(dotted: &str, value: Value) -> Value {
    dotted.rsplit('.').fold(value, |inner, part| json!({part: inner}))
}

// The outcome of one rule when only its key is set, or unset with None.
fn one(ruleset: &str, rule: &str, dotted: &str, value: Option<Value>) -> Outcome {
    let document = sysctl(value.map_or(json!({}), |v| key(dotted, v)));
    let checks = judge(ruleset, &document);
    checks.into_iter().find(|(r, _, _)| r == rule).unwrap_or_else(|| panic!("{rule} gave no check")).2
}

#[test]
fn every_sysctl_rule_passes_at_its_edge_fails_beyond_it_and_is_unknown_unset() {
    let edges = [
        ("kernel", "kernel/aslr", "kernel.randomize_va_space", 2, 1),
        ("kernel", "kernel/kptr-restrict", "kernel.kptr_restrict", 1, 0),
        ("kernel", "kernel/dmesg-restrict", "kernel.dmesg_restrict", 1, 0),
        ("kernel", "kernel/ptrace-scope", "kernel.yama.ptrace_scope", 1, 0),
        ("kernel", "kernel/unprivileged-bpf", "kernel.unprivileged_bpf_disabled", 1, 0),
        ("kernel", "kernel/perf-events", "kernel.perf_event_paranoid", 2, 1),
        ("kernel", "kernel/tty-ldisc-autoload", "dev.tty.ldisc_autoload", 0, 1),
        ("coredump", "coredump/suid-dumpable", "fs.suid_dumpable", 0, 1),
        ("fs-protected", "fs-protected/symlinks", "fs.protected_symlinks", 1, 0),
        ("fs-protected", "fs-protected/hardlinks", "fs.protected_hardlinks", 1, 0),
        ("fs-protected", "fs-protected/fifos", "fs.protected_fifos", 1, 0),
        ("fs-protected", "fs-protected/regular", "fs.protected_regular", 1, 0),
        ("ip-flood", "ip-flood/syncookies", "net.ipv4.tcp_syncookies", 1, 0),
        ("ip-flood", "ip-flood/broadcast-echo", "net.ipv4.icmp_echo_ignore_broadcasts", 1, 0),
    ];
    for (ruleset, rule, dotted, pass, fail) in edges {
        assert_eq!(one(ruleset, rule, dotted, Some(json!(pass))), Outcome::Pass, "{rule} at {pass}");
        assert_eq!(one(ruleset, rule, dotted, Some(json!(fail))), Outcome::Fail, "{rule} at {fail}");
        assert_eq!(one(ruleset, rule, dotted, None), Outcome::Unknown, "{rule} unset");
    }
}

#[test]
fn suid_dumpable_accepts_a_root_only_crash_handler_and_rejects_anything_above() {
    assert_eq!(one("coredump", "coredump/suid-dumpable", "fs.suid_dumpable", Some(json!(2))), Outcome::Pass);
    assert_eq!(one("coredump", "coredump/suid-dumpable", "fs.suid_dumpable", Some(json!(3))), Outcome::Fail);
}

#[test]
fn ipv4_redirects_are_judged_per_interface_but_loopback_and_skipped_where_it_forwards() {
    let conf = json!({"all": {"accept_redirects": 0, "forwarding": 0}, "eth0": {"accept_redirects": 1, "forwarding": 0}, "docker0": {"accept_redirects": 1, "forwarding": 1}, "lo": {"accept_redirects": 1, "forwarding": 0}});
    let checks = judge("ip-routing", &sysctl(json!({"net": {"ipv4": {"conf": conf}}})));
    let redirects: Vec<_> = checks.iter().filter(|(r, _, _)| r == "ip-routing/ipv4-redirects").map(|(_, s, o)| (s.as_str(), *o)).collect();
    assert_eq!(redirects, [("all", Outcome::Pass), ("docker0", Outcome::Skip), ("eth0", Outcome::Fail)]);
}

#[test]
fn ipv6_redirects_leave_all_and_loopback_out_and_skip_a_forwarding_interface() {
    let conf = json!({"all": {"accept_redirects": 1, "forwarding": 0}, "default": {"accept_redirects": 0, "forwarding": 0}, "eth0": {"accept_redirects": 1, "forwarding": 1}, "wlan0": {"accept_redirects": 1, "forwarding": 0}, "lo": {"accept_redirects": 1, "forwarding": 0}});
    let checks = judge("ip-routing", &sysctl(json!({"net": {"ipv6": {"conf": conf}}})));
    let redirects: Vec<_> = checks.iter().filter(|(r, _, _)| r == "ip-routing/ipv6-redirects").map(|(_, s, o)| (s.as_str(), *o)).collect();
    assert_eq!(redirects, [("default", Outcome::Pass), ("eth0", Outcome::Skip), ("wlan0", Outcome::Fail)]);
}

#[test]
fn ipv4_source_routing_fails_an_interface_only_when_all_allows_it_too() {
    let route = |all: u8, eth0: u8| {
        let conf = json!({"all": {"accept_source_route": all}, "eth0": {"accept_source_route": eth0}});
        let checks = judge("ip-routing", &sysctl(json!({"net": {"ipv4": {"conf": conf}}})));
        checks.into_iter().filter(|(r, _, _)| r == "ip-routing/ipv4-source-route").map(|(_, s, o)| (s, o)).collect::<Vec<_>>()
    };
    assert_eq!(route(0, 1), [("eth0".to_owned(), Outcome::Pass)], "all off overrides the interface");
    assert_eq!(route(1, 0), [("eth0".to_owned(), Outcome::Pass)]);
    assert_eq!(route(1, 1), [("eth0".to_owned(), Outcome::Fail)]);
}

// A document with the ufw collectors' facts: the binary paths found and ufw.conf, absent with None.
fn ufw(binaries: &[&str], conf: Option<Value>) -> Value {
    let binary: serde_json::Map<String, Value> = binaries.iter().map(|p| ((*p).to_owned(), json!({"exists": true, "type": "file"}))).collect();
    let mut document = json!({"ufw": {"binary": binary}, "collectors": {"ufw-binary": {"status": "ok", "into": "ufw.binary"}, "ufw": {"status": "ok", "into": "ufw.conf"}}});
    if let Some(conf) = conf {
        document["ufw"]["conf"] = conf;
    }
    document
}

#[test]
fn ufw_switched_off_fails_only_where_its_program_exists() {
    let outcome = |document: &Value| judge("ufw", document).into_iter().map(|(_, _, o)| o).collect::<Vec<_>>();
    assert_eq!(outcome(&ufw(&[], Some(json!({"ENABLED": "no"})))), [Outcome::NotApplicable], "a leftover ufw.conf without the program");
    assert_eq!(outcome(&ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": "yes"})))), [Outcome::Pass]);
    assert_eq!(outcome(&ufw(&["/usr/sbin/ufw"], Some(json!({"ENABLED": "no"})))), [Outcome::Fail]);
    assert_eq!(outcome(&ufw(&["/usr/sbin/ufw"], None)), [Outcome::Unknown], "the program without its configuration");
}

// The outcome of tmp/sticky on one directory's stat, or with no tmp.dirs at all on None.
fn tmp(stat: Option<Value>) -> Vec<Outcome> {
    let mut document = json!({"collectors": {"tmp-dirs": {"status": "ok", "into": "tmp.dirs"}}});
    if let Some(stat) = stat {
        document["tmp"] = json!({"dirs": {"/tmp": stat}});
    }
    judge("tmp", &document).into_iter().map(|(_, _, o)| o).collect()
}

#[test]
fn a_world_writable_temporary_directory_fails_only_without_the_sticky_bit() {
    assert_eq!(tmp(Some(json!({"exists": true, "mode": "1777", "world-writable": true}))), [Outcome::Pass]);
    assert_eq!(tmp(Some(json!({"exists": true, "mode": "0777", "world-writable": true}))), [Outcome::Fail]);
    assert_eq!(tmp(Some(json!({"exists": true, "mode": "3777", "world-writable": true}))), [Outcome::Pass], "setgid beside sticky");
    assert_eq!(tmp(Some(json!({"exists": true, "mode": "2777", "world-writable": true}))), [Outcome::Fail], "setgid alone");
    assert_eq!(tmp(Some(json!({"exists": true, "mode": "0775", "world-writable": false}))), [Outcome::Pass], "no other user writes it");
    assert_eq!(tmp(Some(json!({"exists": false}))), [Outcome::Pass]);
    assert_eq!(tmp(None), [Outcome::Unknown]);
}

#[test]
fn every_rule_carrying_a_lynis_reference_is_tagged_lynis_and_back() {
    for entry in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets")).unwrap() {
        let path = entry.unwrap().path();
        let ruleset: Value = systemlint::yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for (id, rule) in ruleset["rules"].as_object().unwrap() {
            let tagged = rule["tags"].as_array().is_some_and(|t| t.contains(&json!("lynis")));
            let cited = rule["references"].as_array().is_some_and(|r| r.iter().any(|r| r["url"].as_str().unwrap().starts_with("https://cisofy.com/lynis/controls/")));
            assert_eq!(tagged, cited, "{id} in {}", path.display());
        }
    }
}
