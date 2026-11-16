// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::vars::{Supplied, apply};
use systemlint_protocol::{ExecInput, Input};

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

// Every check of one shipped ruleset over a document.
fn checks(ruleset: &str, document: &Value) -> Vec<systemlint::judge::Check> {
    checks_with(ruleset, document, json!({}))
}

// Like checks, its vars filled from `config` as `check.vars` gives them, else their defaults.
fn checks_with(ruleset: &str, document: &Value, config: Value) -> Vec<systemlint::judge::Check> {
    selected(ruleset, &[ruleset.to_owned()], document, config)
}

// One shipped ruleset, parsed.
fn ruleset_yaml<T: serde::de::DeserializeOwned>(ruleset: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../rulesets/{ruleset}.yaml"));
    systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

// The selectors a user keeping `rule` passes: its ruleset, less every rule it declares `conflicts` with.
fn keeping(ruleset: &str, rule: &str) -> Vec<String> {
    let conflicts = ruleset_yaml::<Value>(ruleset)["rules"][rule]["conflicts"].clone();
    let others = conflicts
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    std::iter::once(ruleset.to_owned())
        .chain(others.map(|o| format!("!{o}")))
        .collect()
}

// The checks of the rules `selectors` pick from one shipped ruleset, its vars filled from `config`.
fn selected(
    ruleset: &str,
    selectors: &[String],
    document: &Value,
    config: Value,
) -> Vec<systemlint::judge::Check> {
    let parsed = ruleset_yaml(ruleset);
    let mut rulesets = BTreeMap::from([(ruleset.to_owned(), parsed)]);
    let supplied = Supplied {
        config: config.as_object().unwrap().clone(),
        env: |_| None,
        ..Supplied::default()
    };
    apply(&mut rulesets, &supplied).unwrap();
    let library = Library::new(rulesets).unwrap();
    let rules: Vec<_> = library
        .select(selectors)
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
        (
            "ip-flood",
            "ip-flood/bogus-icmp-errors",
            "net.ipv4.icmp_ignore_bogus_error_responses",
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

// Every check of one ip-routing rule over the given net.ipv4.conf map, as (subject, outcome).
fn ipv4_conf(rule: &str, conf: Value) -> Vec<(String, Outcome)> {
    judge(
        "ip-routing",
        &sysctl(json!({"net": {"ipv4": {"conf": conf}}})),
    )
    .into_iter()
    .filter(|(r, _, _)| r == rule)
    .map(|(_, s, o)| (s, o))
    .collect()
}

#[test]
fn route_localnet_fails_any_interface_but_loopback_that_sets_it() {
    let conf = json!({"all": {"route_localnet": 0}, "eth0": {"route_localnet": 1}, "lo": {"route_localnet": 1}, "wlan0": {}});
    assert_eq!(
        ipv4_conf("ip-routing/route-localnet", conf),
        [
            ("all".to_owned(), Outcome::Pass),
            ("eth0".to_owned(), Outcome::Fail),
            ("wlan0".to_owned(), Outcome::Unknown)
        ]
    );
}

#[test]
fn secure_redirects_judge_only_all_and_default() {
    let conf = json!({"all": {"secure_redirects": 0}, "default": {"secure_redirects": 1}, "eth0": {"secure_redirects": 1}});
    assert_eq!(
        ipv4_conf("ip-routing/ipv4-secure-redirects", conf),
        [
            ("all".to_owned(), Outcome::Pass),
            ("default".to_owned(), Outcome::Fail)
        ]
    );
}

// The outcome of kernel/apparmor-unconfined over the sysctl-apparmor facts.
fn apparmor_unconfined(facts: Value) -> Vec<Outcome> {
    let document = json!({"sysctl": {"settings": {}, "apparmor": facts}, "collectors": {"sysctl": {"status": "ok", "into": "sysctl.settings"}, "sysctl-apparmor": {"status": "ok", "into": "sysctl.apparmor"}}});
    judge("kernel", &document)
        .into_iter()
        .filter(|(r, _, _)| r == "kernel/apparmor-unconfined")
        .map(|(_, _, o)| o)
        .collect()
}

#[test]
fn apparmor_unconfined_is_judged_only_where_user_namespaces_are_restricted() {
    let both = |userns: u8, unconfined: u8| json!({"kernel": {"apparmor_restrict_unprivileged_userns": userns, "apparmor_restrict_unprivileged_unconfined": unconfined}});
    assert_eq!(apparmor_unconfined(both(1, 1)), [Outcome::Pass]);
    assert_eq!(apparmor_unconfined(both(1, 0)), [Outcome::Fail]);
    assert_eq!(
        apparmor_unconfined(both(0, 0)),
        [Outcome::Skip],
        "user namespaces open anyway"
    );
    assert_eq!(
        apparmor_unconfined(json!({"kernel": {"apparmor_restrict_unprivileged_unconfined": 0}})),
        [Outcome::Skip],
        "a kernel without the restriction"
    );
    assert_eq!(
        apparmor_unconfined(json!({})),
        [Outcome::Skip],
        "a kernel without AppArmor"
    );
    assert_eq!(
        apparmor_unconfined(json!({"kernel": {"apparmor_restrict_unprivileged_userns": 1}})),
        [Outcome::Unknown]
    );
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

// The (subject, outcome) pairs of one rule over `facts` nested at `into`, its collector ok, or with no facts on None.
fn collected(rule: &str, id: &str, into: &str, facts: Option<Value>) -> Vec<(String, Outcome)> {
    let ruleset = rule.split('/').next().unwrap();
    let mut document = json!({"collectors": {id: {"status": "ok", "into": into}}});
    if let Some(facts) = facts {
        let (top, rest) = into.split_once('.').unwrap();
        document[top] = json!({rest: facts});
    }
    judge(ruleset, &document)
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, s, o)| (s, o))
        .collect()
}

#[test]
fn a_cpu_flaw_fails_only_when_the_kernel_reports_it_vulnerable() {
    let flaw = |line: &str| {
        collected(
            "cpu/vulnerable",
            "cpu-vulnerabilities",
            "cpu.vulnerabilities",
            Some(json!({"/sys/devices/system/cpu/vulnerabilities/mds": [line]})),
        )[0]
        .1
    };
    assert_eq!(flaw("Not affected"), Outcome::Pass);
    assert_eq!(
        flaw("Mitigation: Clear CPU buffers; SMT vulnerable"),
        Outcome::Pass,
        "mitigated, SMT aside"
    );
    assert_eq!(
        flaw("Unknown: Dependent on hypervisor status"),
        Outcome::Pass
    );
    assert_eq!(
        flaw("Vulnerable: Clear CPU buffers attempted, no microcode"),
        Outcome::Fail
    );
    assert_eq!(flaw("Vulnerable"), Outcome::Fail);
    assert_eq!(
        collected(
            "cpu/vulnerable",
            "cpu-vulnerabilities",
            "cpu.vulnerabilities",
            None
        ),
        [(String::new(), Outcome::Unknown)]
    );
}

#[test]
fn a_netrc_fails_once_every_user_can_read_it() {
    let netrc = |mode: &str, kind: &str| {
        collected(
            "netrc/readable",
            "netrc-files",
            "netrc.files",
            Some(json!({"/home/bob/.netrc": {"exists": true, "kind": kind, "mode": mode}})),
        )[0]
        .1
    };
    assert_eq!(netrc("0600", "file"), Outcome::Pass);
    assert_eq!(
        netrc("0673", "file"),
        Outcome::Pass,
        "a user’s own group holds that user alone, and write without read leaks nothing"
    );
    assert_eq!(netrc("0604", "file"), Outcome::Fail);
    assert_eq!(
        netrc("0777", "symlink"),
        Outcome::Skip,
        "a link’s own mode means nothing"
    );
    assert_eq!(
        collected(
            "netrc/readable",
            "netrc-files",
            "netrc.files",
            Some(json!({}))
        ),
        [],
        "no home holds a .netrc"
    );
}

// The auditd rules’ outcomes, by rule then subject, with auditd on disk and `facts` merged in.
fn auditd(facts: Value) -> Vec<(String, String, Outcome)> {
    let mut document = json!({"auditd": {"binary": {"/usr/sbin/auditd": {"exists": true}}}, "collectors": {
        "auditd-binary": {"status": "ok", "into": "auditd.binary"},
        "auditd-conf": {"status": "ok", "into": "auditd.conf"},
        "auditd-logs": {"status": "ok", "into": "auditd.logs"},
        "audit-rules-loaded": {"status": "ok", "into": "audit.loaded"},
        "systemd-state": {"status": "ok", "into": "systemd.state"}}});
    for (top, value) in facts.as_object().unwrap() {
        match document.get_mut(top).and_then(Value::as_object_mut) {
            Some(map) => map.extend(value.as_object().unwrap().clone()),
            None => document[top] = value.clone(),
        }
    }
    judge("auditd", &document)
}

// One auditd rule’s outcome over auditd.conf as the kv op reads `text`.
fn auditd_conf(rule: &str, text: &str) -> Outcome {
    let file =
        serde_json::from_value(json!({"path": "/etc/audit/auditd.conf", "content": text})).unwrap();
    let with = json!({"repeat": "last"});
    let conf = systemlint_formats::kv(&[Input::File(file)], with.as_object().unwrap())
        .unwrap()
        .facts;
    let checks: Vec<_> = auditd(json!({"auditd": {"conf": conf}}))
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .collect();
    assert_eq!(checks.len(), 1, "{rule} over {text:?}");
    checks[0].2
}

#[test]
fn auditd_conf_fails_ubuntus_stock_actions_and_reads_keys_and_values_without_case() {
    let stock = "max_log_file_action = ROTATE\nspace_left_action = SYSLOG\nadmin_space_left_action = SUSPEND\ndisk_full_action = SUSPEND\ndisk_error_action = SUSPEND\n";
    for rule in [
        "auditd/deletes-logs",
        "auditd/full-disk",
        "auditd/low-space",
    ] {
        assert_eq!(
            auditd_conf(rule, stock),
            Outcome::Fail,
            "{rule} on Ubuntu’s stock auditd.conf"
        );
        assert_eq!(
            auditd_conf(rule, ""),
            Outcome::Fail,
            "{rule} unset takes auditd’s default"
        );
    }
    assert_eq!(
        auditd_conf("auditd/deletes-logs", "max_log_file_action = keep_logs\n"),
        Outcome::Pass
    );
    assert_eq!(
        auditd_conf("auditd/deletes-logs", "MAX_LOG_FILE_ACTION = KEEP_LOGS\n"),
        Outcome::Pass
    );
    assert_eq!(
        auditd_conf(
            "auditd/deletes-logs",
            "max_log_file_action = keep_logs\nmax_log_file_action = rotate\n"
        ),
        Outcome::Fail,
        "the last line wins"
    );
    let full = |full: &str, error: &str| {
        auditd_conf(
            "auditd/full-disk",
            &format!("disk_full_action = {full}\ndisk_error_action = {error}\n"),
        )
    };
    assert_eq!(full("halt", "syslog"), Outcome::Pass);
    assert_eq!(full("SINGLE", "single"), Outcome::Pass);
    assert_eq!(full("rotate", "halt"), Outcome::Fail);
    assert_eq!(full("halt", "suspend"), Outcome::Fail);
    let low = |space: &str, admin: &str| {
        auditd_conf(
            "auditd/low-space",
            &format!("space_left_action = {space}\nadmin_space_left_action = {admin}\n"),
        )
    };
    assert_eq!(low("email", "single"), Outcome::Pass);
    assert_eq!(low("exec", "halt"), Outcome::Pass);
    assert_eq!(low("syslog", "single"), Outcome::Fail);
    assert_eq!(low("email", "suspend"), Outcome::Fail);
}

#[test]
fn auditd_fails_disabled_or_stopped_and_an_empty_rule_list_only_while_it_runs() {
    let unit = |state: Value| {
        auditd(json!({"systemd": {"state": {"auditd.service": state, "ssh.service": {"enabled": false, "active": "inactive"}}}}))
            .into_iter()
            .filter(|(r, _, _)| r == "auditd/disabled" || r == "auditd/inactive")
            .map(|(r, _, o)| (r, o))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        unit(json!({"enabled": true, "active": "active"})),
        [
            ("auditd/disabled".to_owned(), Outcome::Pass),
            ("auditd/inactive".to_owned(), Outcome::Pass)
        ]
    );
    assert_eq!(
        unit(json!({"enabled": false, "active": "failed"})),
        [
            ("auditd/disabled".to_owned(), Outcome::Fail),
            ("auditd/inactive".to_owned(), Outcome::Fail)
        ]
    );
    assert_eq!(
        unit(json!({"enabled": true})),
        [
            ("auditd/disabled".to_owned(), Outcome::Pass),
            ("auditd/inactive".to_owned(), Outcome::Skip)
        ],
        "under --root no unit has an active state"
    );
    let listed = |stdout: &str, active: &str| {
        let run = ExecInput {
            argv: vec!["/usr/sbin/auditctl".into(), "-l".into()],
            stdout: stdout.into(),
            stderr: String::new(),
            exit: 0,
        };
        let with = json!({"split": ["-a", "-S"]});
        let loaded = systemlint_formats::flags(&[Input::Exec(run)], with.as_object().unwrap())
            .unwrap()
            .facts;
        auditd(json!({"audit": {"loaded": loaded}, "systemd": {"state": {"auditd.service": {"enabled": true, "active": active}}}}))
            .into_iter()
            .find(|(r, _, _)| r == "auditd/no-rules")
            .unwrap()
            .2
    };
    assert_eq!(listed("No rules\n", "active"), Outcome::Fail);
    assert_eq!(listed("", "active"), Outcome::Fail);
    assert_eq!(
        listed("-w /etc/sudoers -p wa -k scope\n", "active"),
        Outcome::Pass
    );
    assert_eq!(
        listed("-a always,exit -F arch=b64 -S execve -F key=x\n", "active"),
        Outcome::Pass
    );
    assert_eq!(
        listed("No rules\n", "inactive"),
        Outcome::Skip,
        "a stopped auditd is auditd/inactive"
    );
    let rooted = auditd(json!({"systemd": {"state": {"auditd.service": {"enabled": true}}}}));
    assert_eq!(
        rooted
            .iter()
            .find(|(r, _, _)| r == "auditd/no-rules")
            .map(|c| c.2),
        Some(Outcome::Skip),
        "under --root no unit has an active state"
    );
    let unitless = auditd(json!({"systemd": {"state": {}}}));
    assert_eq!(
        unitless
            .iter()
            .find(|(r, _, _)| r == "auditd/no-rules")
            .map(|c| c.2),
        Some(Outcome::Skip),
        "auditd on disk with no unit"
    );
}

#[test]
fn audit_logs_fail_once_other_users_read_them_or_the_group_writes_the_directory() {
    let mode = |kind: &str, mode: &str| {
        auditd(json!({"auditd": {"logs": {"/var/log/audit/x": {"exists": true, "kind": kind, "mode": mode}}}}))
            .into_iter()
            .filter(|(r, _, o)| r.starts_with("auditd/log-") && r.ends_with("-mode") && *o != Outcome::Skip)
            .map(|(r, _, o)| (r, o))
            .collect::<Vec<_>>()
    };
    let file = |m| mode("file", m);
    let directory = |m| mode("directory", m);
    assert_eq!(
        file("0640"),
        [("auditd/log-mode".to_owned(), Outcome::Pass)]
    );
    assert_eq!(
        file("0600"),
        [("auditd/log-mode".to_owned(), Outcome::Pass)]
    );
    assert_eq!(
        file("0644"),
        [("auditd/log-mode".to_owned(), Outcome::Fail)]
    );
    assert_eq!(
        file("0660"),
        [("auditd/log-mode".to_owned(), Outcome::Fail)]
    );
    assert_eq!(
        file("0740"),
        [("auditd/log-mode".to_owned(), Outcome::Fail)]
    );
    assert_eq!(
        directory("0750"),
        [("auditd/log-directory-mode".to_owned(), Outcome::Pass)]
    );
    assert_eq!(
        directory("2750"),
        [("auditd/log-directory-mode".to_owned(), Outcome::Pass)]
    );
    assert_eq!(
        directory("0700"),
        [("auditd/log-directory-mode".to_owned(), Outcome::Pass)]
    );
    assert_eq!(
        directory("0770"),
        [("auditd/log-directory-mode".to_owned(), Outcome::Fail)]
    );
    assert_eq!(
        directory("0751"),
        [("auditd/log-directory-mode".to_owned(), Outcome::Fail)]
    );
    assert_eq!(
        mode("symlink", "0777"),
        [],
        "a link’s own mode means nothing"
    );
    assert!(
        judge("auditd", &json!({"auditd": {"binary": {}, "logs": {"/var/log/audit/x": {"kind": "file", "mode": "0666"}}}, "collectors": {}}))
            .iter()
            .all(|(r, _, o)| *o == if r == "auditd/not-installed" { Outcome::Fail } else { Outcome::Skip }),
        "a host without auditd fails auditd/not-installed alone"
    );
}

#[test]
fn an_audit_log_owned_by_anyone_but_root_fails_and_its_directory_is_left_to_the_mode_rule() {
    let owner = |kind: &str, uid: Option<u32>| {
        let mut stat = json!({"exists": true, "kind": kind, "mode": "0600"});
        if let Some(uid) = uid {
            stat["uid"] = json!(uid);
        }
        auditd(json!({"auditd": {"logs": {"/var/log/audit/x": stat}}}))
            .into_iter()
            .find(|(r, _, _)| r == "auditd/log-owner")
            .map(|c| c.2)
    };
    assert_eq!(owner("file", Some(0)), Some(Outcome::Pass));
    assert_eq!(owner("file", Some(1)), Some(Outcome::Fail));
    assert_eq!(owner("file", None), Some(Outcome::Unknown));
    assert_eq!(owner("directory", Some(1)), Some(Outcome::Skip));
}

// The banner stat rules’ outcomes over the given banner.files stats.
fn banner(stats: Value) -> Vec<(String, String, Outcome)> {
    judge(
        "banner",
        &json!({"banner": {"files": stats}, "collectors": {"banner-files": {"status": "ok", "into": "banner.files"}}}),
    )
    .into_iter()
    .filter(|(r, _, _)| r == "banner/owner" || r == "banner/writable")
    .collect()
}

#[test]
fn a_banner_fails_once_its_group_or_others_may_write_it_or_root_does_not_own_it() {
    let stat = |uid: u32, group: bool, world: bool| json!({"uid": uid, "group-writable": group, "world-writable": world});
    let outcomes = |s: Value| -> Vec<(String, Outcome)> {
        banner(json!({"/etc/issue": s}))
            .into_iter()
            .map(|(r, _, o)| (r, o))
            .collect()
    };
    assert_eq!(
        outcomes(stat(0, false, false)),
        [
            ("banner/owner".to_owned(), Outcome::Pass),
            ("banner/writable".to_owned(), Outcome::Pass)
        ]
    );
    assert_eq!(
        outcomes(stat(0, true, false)),
        [
            ("banner/owner".to_owned(), Outcome::Pass),
            ("banner/writable".to_owned(), Outcome::Fail)
        ]
    );
    assert_eq!(
        outcomes(stat(0, false, true)),
        [
            ("banner/owner".to_owned(), Outcome::Pass),
            ("banner/writable".to_owned(), Outcome::Fail)
        ]
    );
    assert_eq!(
        outcomes(stat(1000, false, false)),
        [
            ("banner/owner".to_owned(), Outcome::Fail),
            ("banner/writable".to_owned(), Outcome::Pass)
        ]
    );
    assert_eq!(
        outcomes(json!({})),
        [
            ("banner/owner".to_owned(), Outcome::Unknown),
            ("banner/writable".to_owned(), Outcome::Unknown)
        ]
    );
}

#[test]
fn a_pending_reboot_fails_only_while_its_flag_file_exists() {
    let reboot = |facts| {
        collected(
            "reboot/required",
            "reboot-required",
            "reboot.required",
            facts,
        )
    };
    assert_eq!(
        reboot(Some(
            json!({"/run/reboot-required": {"exists": true, "kind": "file"}})
        )),
        [("/run/reboot-required".to_owned(), Outcome::Fail)]
    );
    assert_eq!(reboot(Some(json!({}))), [], "no update asked for a reboot");
}

#[test]
fn a_home_fails_once_others_reach_it_and_a_user_owns_it() {
    let home = |mode: &str, kind: &str, uid: u64| {
        collected(
            "home/open-to-others",
            "home-directories",
            "home.directories",
            Some(json!({"/home/bob": {"exists": true, "kind": kind, "mode": mode, "uid": uid}})),
        )[0]
        .1
    };
    assert_eq!(home("0750", "directory", 1000), Outcome::Pass);
    assert_eq!(home("0751", "directory", 1000), Outcome::Fail);
    assert_eq!(home("0755", "directory", 60000), Outcome::Fail);
    assert_eq!(
        home("0755", "directory", 999),
        Outcome::Skip,
        "a service account’s home"
    );
    assert_eq!(
        home("0755", "directory", 60001),
        Outcome::Skip,
        "nobody and the dynamic uids"
    );
    assert_eq!(
        home("0755", "directory", 0),
        Outcome::Skip,
        "a root-owned /usr/sbin or /var/www"
    );
    assert_eq!(
        home("0777", "symlink", 1000),
        Outcome::Skip,
        "a link’s own mode means nothing"
    );
}

// The home/not-owned checks for bob at `uid` whose home stat is `home`, or no stat at all.
fn home_owner(uid: u64, home: Option<Value>) -> Vec<systemlint::judge::Check> {
    let mut document = json!({
        "accounts": {"passwd": {"bob": {"uid": uid, "home": "/home/bob"}}},
        "home": {"directories": {}},
        "collectors": {
            "accounts-passwd": {"status": "ok", "into": "accounts.passwd"},
            "home-directories": {"status": "ok", "into": "home.directories"},
        },
    });
    if let Some(home) = home {
        document["home"]["directories"]["/home/bob"] = home;
    }
    checks("home", &document)
        .into_iter()
        .filter(|c| c.rule == "home/not-owned")
        .collect()
}

#[test]
fn a_home_fails_when_its_account_does_not_own_it() {
    let dir = |owner: u64| json!({"exists": true, "kind": "directory", "uid": owner});
    let outcome = |uid, home| home_owner(uid, home)[0].outcome;
    assert_eq!(outcome(1000, Some(dir(1000))), Outcome::Pass);
    assert_eq!(outcome(1000, Some(dir(1001))), Outcome::Fail);
    assert_eq!(outcome(60000, Some(dir(0))), Outcome::Fail);
    assert_eq!(
        outcome(999, Some(dir(0))),
        Outcome::Skip,
        "a service account"
    );
    assert_eq!(
        outcome(60001, Some(dir(0))),
        Outcome::Skip,
        "nobody and the dynamic uids"
    );
    assert_eq!(
        outcome(1000, Some(json!({"exists": false}))),
        Outcome::Skip,
        "an account whose home was never made"
    );
    assert_eq!(
        outcome(
            1000,
            Some(json!({"exists": true, "kind": "symlink", "uid": 0}))
        ),
        Outcome::Skip,
        "a link’s own owner means nothing"
    );
    assert_eq!(
        outcome(1000, None),
        Outcome::Unknown,
        "a home the collector should have stated"
    );
    let failed = &home_owner(1000, Some(dir(1001)))[0];
    assert_eq!(failed.subject_label(), "bob");
    assert!(
        failed
            .message
            .as_deref()
            .unwrap()
            .contains("uid 1001, not by its own uid 1000"),
        "{:?}",
        failed.message
    );
}

// The outcomes of the rhosts rules, by rule, for the server binaries found and the trust files' stats.
fn rhosts(readers: &[&str], system: Value, users: Value) -> Vec<(String, Outcome)> {
    let readers: serde_json::Map<String, Value> = readers
        .iter()
        .map(|p| ((*p).to_owned(), json!({"exists": true, "kind": "file"})))
        .collect();
    let document = json!({"rhosts": {"readers": readers, "system": system, "users": users}, "collectors": {
        "rhosts-readers": {"status": "ok", "into": "rhosts.readers"},
        "rhosts-system": {"status": "ok", "into": "rhosts.system"},
        "rhosts-users": {"status": "ok", "into": "rhosts.users"}}});
    judge("rhosts", &document)
        .into_iter()
        .map(|(r, _, o)| (r, o))
        .collect()
}

#[test]
fn a_trust_file_fails_only_when_it_names_a_host_and_an_r_server_reads_it() {
    let stat = |path: &str, size: u64, kind: &str| json!({path: {"exists": true, "kind": kind, "size": size}});
    let hosts = |size| stat("/etc/hosts.equiv", size, "file");
    let user = |size, kind| stat("/home/bob/.rhosts", size, kind);
    assert_eq!(
        rhosts(&[], hosts(10), user(10, "file")),
        [
            ("rhosts/hosts-equiv".into(), Outcome::NotApplicable),
            ("rhosts/user-file".into(), Outcome::NotApplicable)
        ],
        "nothing reads them without an rsh or rlogin server"
    );
    assert_eq!(
        rhosts(&["/usr/sbin/in.rshd"], hosts(0), user(0, "file")),
        [
            ("rhosts/hosts-equiv".into(), Outcome::Pass),
            ("rhosts/user-file".into(), Outcome::Pass)
        ],
        "an empty file trusts nobody"
    );
    assert_eq!(
        rhosts(&["/usr/sbin/in.rlogind"], hosts(1), user(1, "file")),
        [
            ("rhosts/hosts-equiv".into(), Outcome::Fail),
            ("rhosts/user-file".into(), Outcome::Fail)
        ]
    );
    assert_eq!(
        rhosts(&["/usr/sbin/in.rshd"], json!({}), user(9, "symlink")),
        [("rhosts/user-file".into(), Outcome::Skip)],
        "a link to /dev/null disables it, and ruserok refuses any link that is no regular file"
    );
}

// The (rule, subject, outcome) checks of the plaintext-servers ruleset over units, inetd services, xinetd files and xinetd.conf.
fn plaintext(
    state: Value,
    inetd: Value,
    xinetd: Value,
    conf: Value,
) -> Vec<(String, String, Outcome)> {
    let document = json!({"systemd": {"state": state}, "inetd": {"services": inetd}, "xinetd": {"services": xinetd, "conf": conf}, "collectors": {
        "systemd-state": {"status": "ok", "into": "systemd.state"},
        "inetd-services": {"status": "ok", "into": "inetd.services"},
        "xinetd-services": {"status": "ok", "into": "xinetd.services"},
        "xinetd-conf": {"status": "ok", "into": "xinetd.conf"}}});
    judge("plaintext-servers", &document)
}

#[test]
fn a_plaintext_server_unit_fails_once_enabled_or_running_and_never_masked() {
    let unit = |enabled: bool, masked: bool, active: Option<&str>| {
        let mut state = json!({"enabled": enabled, "masked": masked});
        if let Some(active) = active {
            state["active"] = json!(active);
        }
        state
    };
    let state = json!({
        "ypserv.service": unit(false, false, Some("inactive")),
        "yppasswdd.service": unit(true, false, Some("inactive")),
        "ypxfrd.service": unit(false, false, Some("activating")),
        "tftpd-hpa.service": unit(true, true, Some("inactive")),
        "atftpd.socket": unit(false, false, None),
        "telnet.socket": unit(false, false, Some("active")),
        "ssh.service": unit(true, false, Some("active"))});
    assert_eq!(
        plaintext(state, json!({}), json!({}), json!({})),
        [
            (
                "plaintext-servers/login-unit".into(),
                "telnet.socket".into(),
                Outcome::Fail
            ),
            (
                "plaintext-servers/nis-unit".into(),
                "yppasswdd.service".into(),
                Outcome::Fail
            ),
            (
                "plaintext-servers/nis-unit".into(),
                "ypserv.service".into(),
                Outcome::Pass
            ),
            (
                "plaintext-servers/nis-unit".into(),
                "ypxfrd.service".into(),
                Outcome::Fail
            ),
            (
                "plaintext-servers/tftp-unit".into(),
                "atftpd.socket".into(),
                Outcome::Pass
            ),
            (
                "plaintext-servers/tftp-unit".into(),
                "tftpd-hpa.service".into(),
                Outcome::Pass
            ),
        ],
        "a masked unit cannot start, and with no manager only the links count"
    );
}

#[test]
fn an_inetd_line_fails_only_for_a_plaintext_service_while_an_inetd_runs() {
    let line = json!({"path": "/etc/inetd.conf", "line": 1});
    let inetd = json!({"shell": line, "127.0.0.1:telnet": line, "ftp": line, "telnets": line});
    let checks = |state: Value| plaintext(state, inetd.clone(), json!({}), json!({}));
    assert_eq!(
        checks(json!({"inetutils-inetd.service": {"enabled": true, "masked": false}})),
        [
            (
                "plaintext-servers/inetd".into(),
                "127.0.0.1:telnet".into(),
                Outcome::Fail
            ),
            (
                "plaintext-servers/inetd".into(),
                "shell".into(),
                Outcome::Fail
            ),
        ],
        "ftp and telnets are no service on the list, and a host prefix still names telnet"
    );
    assert_eq!(
        checks(json!({"inetd.service": {"enabled": false, "masked": false, "active": "active"}}))
            .len(),
        2,
        "running though not enabled"
    );
    assert_eq!(
        checks(json!({"inetd.service": {"enabled": false, "masked": false, "active": "inactive"}})),
        [
            (
                "plaintext-servers/inetd".into(),
                "127.0.0.1:telnet".into(),
                Outcome::Skip
            ),
            (
                "plaintext-servers/inetd".into(),
                "shell".into(),
                Outcome::Skip
            ),
        ],
        "a line no inetd reads exposes nothing"
    );
    assert_eq!(
        checks(json!({})).len(),
        2,
        "no inetd unit at all is no inetd running, never unknown"
    );
    assert!(
        checks(json!({}))
            .iter()
            .all(|(_, _, o)| *o == Outcome::Skip)
    );
}

#[test]
fn an_xinetd_file_fails_without_disable_yes_unless_xinetd_is_off_or_lists_its_own() {
    let on = json!({"xinetd.service": {"enabled": true, "masked": false}});
    let files = json!({
        "/etc/xinetd.d/echo": {"service": ["echo"], "disable": ["=", "yes"]},
        "/etc/xinetd.d/telnet": {"service": ["telnet"]},
        "/etc/xinetd.d/tftp": {"service": ["tftp"], "disable": ["=", "no"]},
        "/etc/xinetd.d/rsync": {"service": ["rsync"]}});
    let conf = json!({"/etc/xinetd.conf": {}});
    let outcomes = |state: Value, conf: Value| {
        plaintext(state, json!({}), files.clone(), conf)
            .into_iter()
            .map(|(_, s, o)| (s, o))
            .collect::<Vec<_>>()
    };
    let all = |o: Outcome| {
        vec![
            (
                "/etc/xinetd.d/echo".to_owned(),
                if o == Outcome::Fail { Outcome::Pass } else { o },
            ),
            ("/etc/xinetd.d/rsync".to_owned(), Outcome::Skip),
            ("/etc/xinetd.d/telnet".to_owned(), o),
            ("/etc/xinetd.d/tftp".to_owned(), o),
        ]
    };
    assert_eq!(outcomes(on.clone(), conf.clone()), all(Outcome::Fail));
    assert_eq!(
        outcomes(
            json!({"xinetd.service": {"enabled": false, "masked": false}}),
            conf
        ),
        all(Outcome::Skip),
        "xinetd off"
    );
    assert_eq!(
        outcomes(
            on,
            json!({"/etc/xinetd.conf": {"disabled": ["=", "telnet"]}})
        ),
        all(Outcome::Skip),
        "a defaults list decides instead of disable"
    );
    assert_eq!(
        outcomes(json!({}), json!({"/etc/xinetd.conf": {}})),
        all(Outcome::Skip),
        "no xinetd unit"
    );
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
    account_rule_with(rule, document, json!({}))
}

// Like account_rule, its vars filled from `config`, the rules `rule` conflicts with left out.
fn account_rule_with(rule: &str, document: &Value, config: Value) -> Vec<(String, Outcome)> {
    selected("accounts", &keeping("accounts", rule), document, config)
        .into_iter()
        .filter(|c| c.rule == rule)
        .map(|c| (c.subject_label(), c.outcome))
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
        account_rule("accounts/passwd-hash", &document),
        [
            ("inline".into(), Outcome::Fail),
            ("locked".into(), Outcome::Pass),
            ("open".into(), Outcome::Pass),
            ("viashadow".into(), Outcome::Pass),
        ],
        "only a hash fails: empty is passwd-empty-password’s finding"
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
    assert_eq!(
        account_rule_with(
            "accounts/password-max-days",
            &document,
            json!({"password-max-days": 1})
        ),
        [
            ("daemon".into(), Outcome::Skip),
            ("edge".into(), Outcome::Fail),
            ("low".into(), Outcome::Fail),
            ("past".into(), Outcome::Fail),
            ("unset".into(), Outcome::Fail),
        ],
        "a site asking for daily rotation sets the bound to 1"
    );
    let message: Vec<String> = selected(
        "accounts",
        &keeping("accounts", "accounts/password-max-days"),
        &document,
        json!({}),
    )
    .into_iter()
    .filter(|c| c.rule == "accounts/password-max-days")
    .filter_map(|c| c.message)
    .collect();
    assert!(
        message
            .iter()
            .any(|m| m == "unset’s maximum password age in days is none, where 1 to 365 is asked"),
        "{message:?}"
    );
}

#[test]
fn nist_rotation_fails_any_scheduled_expiry_and_contradicts_the_cis_maximum() {
    let max = |password: &str, days: Value| json!({"password": password, "max-days": days});
    let document = accounts(
        json!({}),
        json!({}),
        json!({"never": max("hash", json!(99999)), "unset": max("hash", Value::Null),
               "below": max("hash", json!(99998)), "cis": max("hash", json!(365)),
               "zero": max("hash", json!(0)), "daemon": max("locked", json!(90))}),
    );
    assert_eq!(
        account_rule("accounts/password-rotation", &document),
        [
            ("below".into(), Outcome::Fail),
            ("cis".into(), Outcome::Fail),
            ("daemon".into(), Outcome::Skip),
            ("never".into(), Outcome::Pass),
            ("unset".into(), Outcome::Pass),
            ("zero".into(), Outcome::Fail),
        ],
        "only no maximum, or shadow’s 99999, sets no schedule"
    );
    let both = checks("accounts", &document);
    let judged: Vec<(&str, String, Outcome)> = both
        .iter()
        .filter(|c| {
            c.rule.starts_with("accounts/password-r") || c.rule == "accounts/password-max-days"
        })
        .filter(|c| c.subject_label() != "daemon")
        .map(|c| (c.rule.as_str(), c.subject_label(), c.outcome))
        .collect();
    assert_eq!(judged.len(), 10, "{judged:?}");
    assert!(
        judged.iter().all(|(_, _, o)| *o == Outcome::Conflict),
        "{judged:?}"
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

#[test]
fn group_root_and_group_shadow_belong_to_no_account_but_their_own() {
    let entry = |gid: u32| json!({"uid": 1000, "gid": gid, "password": "shadow", "shadowed": []});
    let passwd = json!({"root": entry(0), "sync": entry(0), "wheel": entry(0), "one": entry(1),
                        "reader": entry(42), "below": entry(41), "above": entry(43)});
    let group = |members: Value| json!({"shadow": {"gid": 42, "members": members, "shadowed": []}});
    let document = accounts(passwd.clone(), group(json!(["reader"])), json!({}));
    assert_eq!(
        account_rule("accounts/gid-zero", &document),
        [
            ("above".into(), Outcome::Pass),
            ("below".into(), Outcome::Pass),
            ("one".into(), Outcome::Pass),
            ("reader".into(), Outcome::Pass),
            ("wheel".into(), Outcome::Fail),
        ],
        "gid 1 is the edge; root, sync, shutdown, halt and operator are CIS’s exceptions"
    );
    assert_eq!(
        account_rule("accounts/shadow-group-members", &document),
        [("shadow".into(), Outcome::Fail)]
    );
    let empty = accounts(passwd.clone(), group(json!([])), json!({}));
    assert_eq!(
        account_rule("accounts/shadow-group-members", &empty),
        [("shadow".into(), Outcome::Pass)]
    );
    let primary: Vec<_> = account_rule("accounts/shadow-group-primary", &document)
        .into_iter()
        .filter(|(_, o)| *o != Outcome::Pass)
        .collect();
    assert_eq!(
        primary,
        [("reader".into(), Outcome::Fail)],
        "41 and 43 are the edges"
    );
    let other = accounts(
        passwd,
        json!({"shadow": {"gid": 43, "members": [], "shadowed": []}}),
        json!({}),
    );
    assert!(
        account_rule("accounts/shadow-group-primary", &other)
            .iter()
            .all(|(_, o)| *o == Outcome::Skip),
        "a shadow group off Debian’s fixed gid 42 is never guessed"
    );
}

#[test]
fn a_system_account_below_uid_min_or_nobody_has_no_login_shell() {
    let entry = |uid: u32, shell: bool| json!({"uid": uid, "login-shell": shell, "password": "shadow", "shadowed": []});
    let document = accounts(
        json!({"root": entry(0, true), "sync": entry(4, true), "postgres": entry(999, true), "daemon": entry(1, false),
               "alice": entry(1000, true), "nobody": entry(65534, true), "high": entry(65533, true)}),
        json!({}),
        json!({}),
    );
    assert_eq!(
        account_rule("accounts/system-login-shell", &document),
        [
            ("alice".into(), Outcome::Skip),
            ("daemon".into(), Outcome::Pass),
            ("high".into(), Outcome::Skip),
            ("nobody".into(), Outcome::Fail),
            ("postgres".into(), Outcome::Fail),
        ],
        "999 and 65534 are judged, 1000 and 65533 are not; root and sync are CIS’s exceptions"
    );
    let raised = account_rule_with(
        "accounts/system-login-shell",
        &document,
        json!({"uid-min": 500}),
    );
    assert!(
        raised.contains(&("postgres".into(), Outcome::Skip)),
        "{raised:?}"
    );
}

#[test]
fn nologin_in_etc_shells_fails_unless_commented_out() {
    let shells = |lines: Value| {
        json!({"accounts": {"shells": {"/etc/shells": lines}},
               "collectors": {"accounts-shells": {"status": "ok", "into": "accounts.shells"}}})
    };
    let rule = |document: &Value| account_rule("accounts/nologin-shell", document);
    let stock = shells(json!([
        "# /etc/shells: valid login shells",
        "/bin/sh",
        "# /usr/sbin/nologin",
        "/usr/bin/nologinx"
    ]));
    assert_eq!(
        rule(&stock),
        [("/etc/shells".into(), Outcome::Pass)],
        "a comment and a longer name pass"
    );
    let listed = shells(json!(["/bin/sh", "/usr/sbin/nologin"]));
    assert_eq!(rule(&listed), [("/etc/shells".into(), Outcome::Fail)]);
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
    checks.retain(|(rule, _, _)| {
        !rule.starts_with("mounts/separate-") && !rule.starts_with("mounts/partition-")
    });
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

// The outcomes one login-defs rule gives over the given keys, its vars from `config`, the rules it conflicts with left out.
fn login_defs(rule: &str, defs: Value, config: Value) -> Vec<Outcome> {
    let document = auth(defs, json!([]), json!({}));
    selected(
        "login-defs",
        &keeping("login-defs", rule),
        &document,
        config,
    )
    .into_iter()
    .filter(|c| c.rule == rule)
    .map(|c| c.outcome)
    .collect()
}

#[test]
fn the_stig_umask_passes_only_077() {
    let umask = |defs: Value| login_defs("login-defs/umask-077", defs, json!({}));
    for strict in ["077", "0077"] {
        assert_eq!(umask(json!({"UMASK": strict})), [Outcome::Pass], "{strict}");
    }
    for loose in ["027", "067"] {
        assert_eq!(umask(json!({"UMASK": loose})), [Outcome::Fail], "{loose}");
    }
    assert_eq!(
        umask(json!({"PASS_MAX_DAYS": 99999})),
        [Outcome::Fail],
        "unset is 022"
    );
}

#[test]
fn the_hash_scheme_passes_sha512_or_yescrypt_in_capitals_and_the_stig_only_sha512() {
    let method = |rule: &str, value: Option<&str>| {
        let defs = value.map_or(json!({"UMASK": "027"}), |v| json!({"ENCRYPT_METHOD": v}));
        login_defs(rule, defs, json!({}))
    };
    for strong in ["SHA512", "YESCRYPT"] {
        assert_eq!(
            method("login-defs/encrypt-method", Some(strong)),
            [Outcome::Pass],
            "{strong}"
        );
    }
    for weak in ["SHA256", "MD5", "DES", "sha512", "yescrypt"] {
        assert_eq!(
            method("login-defs/encrypt-method", Some(weak)),
            [Outcome::Fail],
            "{weak}"
        );
    }
    assert_eq!(
        method("login-defs/encrypt-method", None),
        [Outcome::Fail],
        "unset is DES"
    );
    assert_eq!(
        method("login-defs/encrypt-method-sha512", Some("SHA512")),
        [Outcome::Pass]
    );
    assert_eq!(
        method("login-defs/encrypt-method-sha512", Some("YESCRYPT")),
        [Outcome::Fail]
    );
    assert_eq!(
        method("login-defs/encrypt-method-sha512", None),
        [Outcome::Fail]
    );
}

#[test]
fn sha_rounds_fail_below_5000_on_the_lower_key_set_and_skip_other_schemes() {
    let rounds = |defs: Value| login_defs("login-defs/sha-rounds", defs, json!({}));
    let sha = |extra: Value| {
        let mut defs = json!({"ENCRYPT_METHOD": "SHA512"});
        defs.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        rounds(defs)
    };
    assert_eq!(sha(json!({})), [Outcome::Pass], "unset is the default 5000");
    assert_eq!(sha(json!({"SHA_CRYPT_MIN_ROUNDS": 5000})), [Outcome::Pass]);
    assert_eq!(sha(json!({"SHA_CRYPT_MIN_ROUNDS": 4999})), [Outcome::Fail]);
    assert_eq!(sha(json!({"SHA_CRYPT_MAX_ROUNDS": 5000})), [Outcome::Pass]);
    assert_eq!(
        sha(json!({"SHA_CRYPT_MAX_ROUNDS": 4999})),
        [Outcome::Fail],
        "a lone maximum is the count"
    );
    assert_eq!(
        sha(json!({"SHA_CRYPT_MIN_ROUNDS": 5000, "SHA_CRYPT_MAX_ROUNDS": 1000})),
        [Outcome::Pass],
        "shadow raises a maximum below the minimum to it"
    );
    assert_eq!(
        sha(json!({"SHA_CRYPT_MIN_ROUNDS": 4999, "SHA_CRYPT_MAX_ROUNDS": 9000})),
        [Outcome::Fail]
    );
    assert_eq!(
        rounds(json!({"ENCRYPT_METHOD": "SHA256", "SHA_CRYPT_MIN_ROUNDS": 4999})),
        [Outcome::Fail]
    );
    for other in [
        json!({"ENCRYPT_METHOD": "YESCRYPT", "SHA_CRYPT_MIN_ROUNDS": 1000}),
        json!({"SHA_CRYPT_MIN_ROUNDS": 1000}),
    ] {
        assert_eq!(rounds(other.clone()), [Outcome::Skip], "{other}");
    }
}

#[test]
fn new_account_ageing_fails_past_each_bound_and_unset() {
    let age = |rule: &str, key: &str, value: Option<i64>| {
        let defs = value.map_or(json!({"UMASK": "027"}), |v| json!({key: v}));
        login_defs(rule, defs, json!({}))
    };
    let edges = [
        ("login-defs/pass-min-days", "PASS_MIN_DAYS", 1, 0),
        ("login-defs/pass-warn-age", "PASS_WARN_AGE", 7, 6),
        ("login-defs/pass-max-days", "PASS_MAX_DAYS", 365, 366),
        ("login-defs/pass-max-days", "PASS_MAX_DAYS", 1, 0),
    ];
    for (rule, key, pass, fail) in edges {
        assert_eq!(age(rule, key, Some(pass)), [Outcome::Pass], "{rule} {pass}");
        assert_eq!(age(rule, key, Some(fail)), [Outcome::Fail], "{rule} {fail}");
        assert_eq!(age(rule, key, None), [Outcome::Fail], "{rule} unset");
    }
    let stig = |days: i64| {
        login_defs(
            "login-defs/pass-max-days",
            json!({"PASS_MAX_DAYS": days}),
            json!({"password-max-days": 60}),
        )
    };
    assert_eq!(stig(60), [Outcome::Pass]);
    assert_eq!(stig(61), [Outcome::Fail], "the STIG’s 60 is a var");
}

#[test]
fn nist_rotation_fails_any_new_account_expiry_and_contradicts_the_cis_maximum() {
    let rotation = |defs: Value| login_defs("login-defs/pass-rotation", defs, json!({}));
    for never in [
        json!({"UMASK": "027"}),
        json!({"PASS_MAX_DAYS": 99999}),
        json!({"PASS_MAX_DAYS": -1}),
        json!({"PASS_MAX_DAYS": "-1"}),
    ] {
        assert_eq!(rotation(never.clone()), [Outcome::Pass], "{never}");
    }
    for scheduled in [99998, 365, 0] {
        assert_eq!(
            rotation(json!({"PASS_MAX_DAYS": scheduled})),
            [Outcome::Fail],
            "{scheduled}"
        );
    }
    let both: Vec<Outcome> = checks(
        "login-defs",
        &auth(json!({"PASS_MAX_DAYS": 365}), json!([]), json!({})),
    )
    .into_iter()
    .filter(|c| c.rule.starts_with("login-defs/pass-r") || c.rule == "login-defs/pass-max-days")
    .map(|c| c.outcome)
    .collect();
    assert_eq!(both, [Outcome::Conflict; 2]);
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

#[test]
fn pam_unix_keeps_no_history_and_hashes_strongly_and_the_common_stacks_call_their_modules() {
    let judged = |rule: &str, path: &str, entries: Value| {
        outcomes(
            "pam",
            rule,
            &auth(json!({}), json!([]), json!({path: entries})),
        )
    };
    let common = "/etc/pam.d/common-password";
    let unix = |arguments: &[&str]| {
        json!([entry(
            "password",
            "[success=1 default=ignore]",
            "pam_unix.so",
            arguments
        )])
    };
    assert_eq!(
        judged("pam/unix-remember", common, unix(&["remember=5"])),
        [Outcome::Fail]
    );
    assert_eq!(
        judged(
            "pam/unix-remember",
            "/etc/pam.d/sshd",
            unix(&["remember=0"])
        ),
        [Outcome::Fail],
        "any file, any count"
    );
    assert_eq!(
        judged("pam/unix-remember", common, unix(&["remembered"])),
        [Outcome::Pass]
    );
    assert_eq!(
        judged("pam/unix-hash", common, unix(&["obscure", "yescrypt"])),
        [Outcome::Pass]
    );
    assert_eq!(
        judged("pam/unix-hash", common, unix(&["sha512"])),
        [Outcome::Pass]
    );
    assert_eq!(
        judged("pam/unix-hash", common, unix(&["sha256"])),
        [Outcome::Fail]
    );
    assert_eq!(judged("pam/unix-hash", common, unix(&[])), [Outcome::Fail]);
    assert_eq!(
        judged("pam/unix-hash", "/etc/pam.d/passwd", unix(&[])),
        Vec::<Outcome>::new(),
        "only common-password"
    );
    assert_eq!(
        judged("pam/unix-enabled", "/etc/pam.d/common-session", unix(&[])),
        [Outcome::Pass]
    );
    let sss = json!([entry("session", "required", "pam_sss.so", &[])]);
    assert_eq!(
        judged("pam/unix-enabled", "/etc/pam.d/common-session", sss.clone()),
        [Outcome::Fail]
    );
    assert_eq!(
        judged("pam/unix-enabled", "/etc/pam.d/login", sss),
        Vec::<Outcome>::new()
    );
    for (rule, module) in [
        ("pam/pwquality-enabled", "pam_pwquality.so"),
        ("pam/pwhistory-enabled", "pam_pwhistory.so"),
    ] {
        let with = json!([
            entry("password", "requisite", module, &[]),
            entry("password", "required", "pam_unix.so", &[])
        ]);
        assert_eq!(judged(rule, common, with), [Outcome::Pass], "{rule}");
        let session = json!([entry("session", "requisite", module, &[])]);
        assert_eq!(
            judged(rule, common, session),
            [Outcome::Fail],
            "{rule}: only a password line counts"
        );
    }
}

// The pam rules over faillock.conf, pwhistory.conf and the two common stacks that use them.
fn lockout_rule(
    rule: &str,
    conf: (&str, Value),
    auth_args: &[&str],
    password_args: &[&str],
) -> Vec<Outcome> {
    let pam = json!({
        "/etc/pam.d/common-auth": [entry("auth", "requisite", "pam_faillock.so", &[&["preauth"], auth_args].concat())],
        "/etc/pam.d/common-password": [entry("password", "requisite", "pam_pwhistory.so", password_args),
                                       entry("password", "[success=1 default=ignore]", "pam_unix.so", &["use_authtok"])]});
    let mut document = auth(json!({}), json!([]), pam);
    document["auth"][conf.0] = conf.1;
    document["collectors"][format!("auth-{}", conf.0)] =
        json!({"status": "ok", "into": format!("auth.{}", conf.0)});
    outcomes("pam", rule, &document)
}

#[test]
fn faillock_conf_locks_after_at_most_five_failures_for_fifteen_minutes_root_included() {
    let deny = |conf: Value, args: &[&str]| {
        lockout_rule("pam/faillock-deny", ("faillock", conf), args, &[])
    };
    assert_eq!(deny(json!({"deny": 5}), &[]), [Outcome::Pass]);
    assert_eq!(deny(json!({}), &[]), [Outcome::Pass], "unset is 3");
    assert_eq!(deny(json!({"deny": 6}), &[]), [Outcome::Fail]);
    assert_eq!(
        deny(json!({"deny": 0}), &[]),
        [Outcome::Fail],
        "0 never locks"
    );
    assert_eq!(
        deny(json!({"deny": 6}), &["deny=3"]),
        [Outcome::Skip],
        "the argument overrides the file"
    );
    let unlock =
        |conf: Value| lockout_rule("pam/faillock-unlock-time", ("faillock", conf), &[], &[]);
    assert_eq!(unlock(json!({"unlock_time": 900})), [Outcome::Pass]);
    assert_eq!(
        unlock(json!({"unlock_time": 0})),
        [Outcome::Pass],
        "0 waits for an administrator"
    );
    assert_eq!(unlock(json!({"unlock_time": 899})), [Outcome::Fail]);
    assert_eq!(unlock(json!({})), [Outcome::Fail], "unset is 600");
    let root = |conf: Value| lockout_rule("pam/faillock-root", ("faillock", conf), &[], &[]);
    assert_eq!(root(json!({"even_deny_root": true})), [Outcome::Pass]);
    assert_eq!(root(json!({"root_unlock_time": 60})), [Outcome::Pass]);
    assert_eq!(
        root(json!({"even_deny_root": true, "root_unlock_time": 59})),
        [Outcome::Fail]
    );
    assert_eq!(root(json!({})), [Outcome::Fail]);
}

#[test]
fn pwhistory_remembers_24_passwords_for_root_too_and_takes_the_checked_password() {
    let remember =
        |conf: Value| lockout_rule("pam/pwhistory-remember", ("pwhistory", conf), &[], &[]);
    assert_eq!(remember(json!({"remember": 24})), [Outcome::Pass]);
    assert_eq!(remember(json!({"remember": 23})), [Outcome::Fail]);
    assert_eq!(remember(json!({})), [Outcome::Fail], "unset is 10");
    let root = |conf: Value, args: &[&str]| {
        lockout_rule("pam/pwhistory-root", ("pwhistory", conf), &[], args)
    };
    assert_eq!(
        root(json!({"enforce_for_root": true}), &[]),
        [Outcome::Pass]
    );
    assert_eq!(root(json!({}), &["enforce_for_root"]), [Outcome::Pass]);
    assert_eq!(root(json!({}), &[]), [Outcome::Fail]);
    let authtok = |args: &[&str]| {
        lockout_rule(
            "pam/pwhistory-use-authtok",
            ("pwhistory", json!({})),
            &[],
            args,
        )
    };
    assert_eq!(authtok(&["use_authtok"]), [Outcome::Pass]);
    assert_eq!(authtok(&["remember=24"]), [Outcome::Fail]);
    assert_eq!(
        lockout_rule("pam/unix-use-authtok", ("pwhistory", json!({})), &[], &[]),
        [Outcome::Pass]
    );
    let unix = json!({"/etc/pam.d/common-password": [entry("password", "required", "pam_unix.so", &["obscure", "yescrypt"])]});
    assert_eq!(
        outcomes(
            "pam",
            "pam/unix-use-authtok",
            &auth(json!({}), json!([]), unix)
        ),
        [Outcome::Fail]
    );
}

#[test]
fn su_is_restricted_only_by_a_required_pam_wheel_with_use_uid_and_a_group() {
    let su = |control: &str, arguments: &[&str]| {
        let pam = json!({"/etc/pam.d/su": [entry("auth", control, "pam_wheel.so", arguments)]});
        outcomes(
            "pam",
            "pam/su-unrestricted",
            &auth(json!({}), json!([]), pam),
        )
    };
    assert_eq!(
        su("required", &["use_uid", "group=sugroup"]),
        [Outcome::Pass]
    );
    assert_eq!(
        su("requisite", &["group=sugroup", "use_uid"]),
        [Outcome::Pass],
        "either order"
    );
    assert_eq!(
        su("required", &["use_uid"]),
        [Outcome::Fail],
        "no group= falls back to wheel or root’s gid"
    );
    assert_eq!(su("required", &["use_uid", "group="]), [Outcome::Fail]);
    assert_eq!(su("required", &["group=sugroup"]), [Outcome::Fail]);
    assert_eq!(
        su("sufficient", &["use_uid", "group=sugroup"]),
        [Outcome::Fail]
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

// The outcomes of the ports rules for one port’s listening addresses.
fn ports(port: &str, addresses: Value) -> Vec<(String, Outcome)> {
    judge("ports", &json!({"ports": {port: {"addresses": addresses}}}))
        .into_iter()
        .map(|(rule, _, o)| (rule, o))
        .collect()
}

#[test]
fn a_plain_listener_fails_from_its_first_address_beyond_the_loopback() {
    for (port, rule) in [
        ("tcp:2375", "ports/docker-api-plain"),
        ("udp:631", "ports/cups-browsed"),
        ("udp:11211", "ports/memcached-udp"),
        ("tcp:25", "ports/mta-public"),
        ("tcp:465", "ports/mta-public"),
        ("tcp:587", "ports/mta-public"),
    ] {
        let one = |o| vec![(rule.to_owned(), o)];
        assert_eq!(
            ports(port, json!(["127.0.0.1", "127.255.255.255", "::1"])),
            one(Outcome::Pass),
            "{port}"
        );
        assert_eq!(
            ports(port, json!(["127.0.0.1", "128.0.0.1"])),
            one(Outcome::Fail),
            "{port}"
        );
        assert_eq!(
            ports(port, json!(["0.0.0.0"])),
            one(Outcome::Fail),
            "{port}"
        );
        assert_eq!(ports(port, json!(["::"])), one(Outcome::Fail), "{port}");
        assert_eq!(ports(port, json!(["::10"])), one(Outcome::Fail), "{port}");
        assert_eq!(
            ports(port, json!(["10.0.0.127"])),
            one(Outcome::Fail),
            "{port}"
        );
    }
    assert_eq!(ports("tcp:2376", json!(["0.0.0.0"])), vec![], "TLS port");
    for port in ["tcp:24", "tcp:26", "tcp:586", "udp:25"] {
        assert_eq!(
            ports(port, json!(["0.0.0.0"])),
            vec![],
            "{port} is no mail port"
        );
    }
    assert_eq!(
        ports("tcp:631", json!(["0.0.0.0"])),
        vec![],
        "cupsd, not cups-browsed"
    );
    assert_eq!(
        ports("tcp:11211", json!(["0.0.0.0"])),
        vec![],
        "memcached over TCP"
    );
}

// The outcome of one sudo-defaults rule for one account’s Defaults, with the ruleset vars in `config`.
fn sudo_defaults(rule: &str, defaults: Value, config: Value) -> Option<Outcome> {
    let document = json!({"sudo": {"binary": {"/usr/bin/sudo": {}}, "version": {"1.9.17p2": {}}, "defaults": {"bob": defaults}}});
    checks_with("sudo-defaults", &document, config)
        .into_iter()
        .find(|c| c.rule == format!("sudo-defaults/{rule}"))
        .map(|c| c.outcome)
}

#[test]
fn sudo_defaults_fail_from_their_edge_and_an_unset_key_keeps_the_safe_default() {
    let at = |rule: &str, defaults: Value| sudo_defaults(rule, defaults, json!({})).unwrap();
    let on = json!({"env_reset": true});
    assert_eq!(at("no-authenticate", on.clone()), Outcome::Pass);
    assert_eq!(
        at("no-authenticate", json!({"authenticate": true})),
        Outcome::Pass
    );
    assert_eq!(
        at("no-authenticate", json!({"authenticate": false})),
        Outcome::Fail
    );
    assert_eq!(
        at("no-pty", on.clone()),
        Outcome::Pass,
        "use_pty is on by default since sudo 1.9.14"
    );
    assert_eq!(at("no-pty", json!({"use_pty": false})), Outcome::Fail);
    assert_eq!(
        at("use-pty", on.clone()),
        Outcome::Fail,
        "CIS asks for it spelled out"
    );
    assert_eq!(at("use-pty", json!({"use_pty": true})), Outcome::Pass);
    assert_eq!(at("logfile", on.clone()), Outcome::Fail);
    assert_eq!(at("logfile", json!({"logfile": false})), Outcome::Fail);
    assert_eq!(
        at("logfile", json!({"logfile": "/var/log/sudo.log"})),
        Outcome::Pass
    );
    assert_eq!(
        at("timestamp-timeout", on.clone()),
        Outcome::Pass,
        "unset is the build default, 15 or less"
    );
    for (minutes, outcome) in [
        (json!(0), Outcome::Pass),
        (json!(15), Outcome::Pass),
        (json!(16), Outcome::Fail),
        (json!(-1), Outcome::Fail),
        (json!("2.5"), Outcome::Pass),
    ] {
        assert_eq!(
            at("timestamp-timeout", json!({"timestamp_timeout": minutes})),
            outcome,
            "{minutes}"
        );
    }
    let strict = |minutes: i64| {
        sudo_defaults(
            "timestamp-timeout",
            json!({"timestamp_timeout": minutes}),
            json!({"sudo-timestamp-timeout": 5}),
        )
        .unwrap()
    };
    assert_eq!((strict(5), strict(6)), (Outcome::Pass, Outcome::Fail));
    assert_eq!(
        sudo_defaults("use-pty", json!({}), json!({})),
        Some(Outcome::Skip),
        "an account sudo does not allow"
    );
}

#[test]
fn a_host_without_sudo_finds_sudo_defaults_not_applicable() {
    let document = json!({"sudo": {"binary": {}}, "collectors": {"sudo-binary": {"status": "ok", "into": "sudo.binary"}, "sudo-version": {"status": "skipped", "into": "sudo.version"}, "sudo-defaults": {"status": "skipped", "into": "sudo.defaults"}}});
    let outcomes: Vec<_> = checks("sudo-defaults", &document)
        .into_iter()
        .map(|c| c.outcome)
        .collect();
    assert_eq!(outcomes.len(), 5);
    assert!(
        outcomes.iter().all(|o| *o == Outcome::NotApplicable),
        "{outcomes:?}"
    );
}

// The outcomes of rescue/no-sulogin, by unit, for each unit's merged ExecStart list.
fn rescue(units: &[(&str, Value)]) -> Vec<(String, Outcome)> {
    let units: serde_json::Map<_, _> = units
        .iter()
        .map(|(name, exec)| {
            (
                (*name).to_owned(),
                json!({"sections": {"Service": {"ExecStart": exec}}}),
            )
        })
        .collect();
    judge("rescue", &json!({"systemd": {"units": units}}))
        .into_iter()
        .map(|(_, subject, o)| (subject, o))
        .collect()
}

#[test]
fn a_rescue_shell_fails_only_once_its_effective_command_skips_sulogin() {
    let one = |exec: Value| rescue(&[("rescue.service", exec)]);
    let rescue_is = |o| vec![("rescue.service".to_owned(), o)];
    assert_eq!(
        one(json!(["-/usr/lib/systemd/systemd-sulogin-shell rescue"])),
        rescue_is(Outcome::Pass)
    );
    assert_eq!(
        one(json!([
            "",
            "-/usr/lib/systemd/systemd-sulogin-shell rescue"
        ])),
        rescue_is(Outcome::Pass)
    );
    assert_eq!(
        one(json!([""])),
        rescue_is(Outcome::Pass),
        "a reset with no command leaves a unit systemd refuses to start"
    );
    assert_eq!(one(json!(["", "/bin/bash"])), rescue_is(Outcome::Fail));
    assert_eq!(
        rescue(&[
            ("emergency.service", json!(["/bin/sh"])),
            ("ssh.service", json!(["/usr/sbin/sshd -D"]))
        ]),
        [("emergency.service".to_owned(), Outcome::Fail)],
        "only the rescue and emergency units are judged"
    );
    assert!(rescue(&[("ssh.service", json!(["/usr/sbin/sshd -D"]))]).is_empty());
}

#[test]
fn xdmcp_fails_only_where_a_gdm_file_enables_it() {
    let gdm = |text: Value| {
        let document = json!({"gdm": {"config": {"/etc/gdm3/custom.conf": text}},
                              "collectors": {"gdm-config": {"status": "ok", "into": "gdm.config"}}});
        outcomes("gdm", "gdm/xdmcp", &document)
    };
    assert_eq!(gdm(json!({"xdmcp": {"Enable": ["true"]}})), [Outcome::Fail]);
    assert_eq!(
        gdm(json!({"xdmcp": {"Enable": ["False", " TRUE "]}})),
        [Outcome::Fail],
        "any value, any case"
    );
    assert_eq!(gdm(json!({"xdmcp": {"Enable": ["1"]}})), [Outcome::Fail]);
    assert_eq!(
        gdm(json!({"xdmcp": {"Enable": ["false"]}})),
        [Outcome::Pass]
    );
    assert_eq!(gdm(json!({"xdmcp": {}})), [Outcome::Pass]);
    assert_eq!(
        gdm(json!({"daemon": {"AutomaticLoginEnable": ["true"]}})),
        [Outcome::Pass]
    );
    assert_eq!(
        outcomes("gdm", "gdm/xdmcp", &json!({"gdm": {"config": {}}})),
        [Outcome::NotApplicable],
        "no GDM"
    );
}

#[test]
fn wayland_passes_only_where_a_gdm_file_turns_it_off_and_never_back_on() {
    let gdm = |text: Value| {
        let document = json!({"gdm": {"config": {"/etc/gdm3/custom.conf": text}},
                              "collectors": {"gdm-config": {"status": "ok", "into": "gdm.config"}}});
        outcomes("gdm", "gdm/wayland-enabled", &document)
    };
    assert_eq!(
        gdm(json!({"daemon": {"WaylandEnable": ["false"]}})),
        [Outcome::Pass]
    );
    assert_eq!(
        gdm(json!({"daemon": {"WaylandEnable": ["0"]}})),
        [Outcome::Pass]
    );
    assert_eq!(
        gdm(json!({"daemon": {"WaylandEnable": ["true"]}})),
        [Outcome::Fail]
    );
    assert_eq!(
        gdm(json!({"daemon": {"WaylandEnable": ["false", "true"]}})),
        [Outcome::Fail],
        "turned back on"
    );
    assert_eq!(gdm(json!({"daemon": {}})), [Outcome::Fail], "unset is on");
    assert_eq!(gdm(json!({"xdmcp": {}})), [Outcome::Fail], "no [daemon]");
}

#[test]
fn systemd_journal_remote_fails_once_enabled_or_running_and_never_masked() {
    let remote = |state: Value| {
        outcomes(
            "journald",
            "journald/remote-listening",
            &json!({"systemd": {"state": state}}),
        )
    };
    let socket = |enabled: bool, masked: bool, active: &str| {
        json!({"systemd-journal-remote.socket": {"enabled": enabled, "masked": masked, "active": active},
               "systemd-journald.service": {"enabled": true, "masked": false, "active": "active"}})
    };
    assert_eq!(remote(socket(false, false, "inactive")), [Outcome::Pass]);
    assert_eq!(remote(socket(true, false, "inactive")), [Outcome::Fail]);
    assert_eq!(remote(socket(false, false, "active")), [Outcome::Fail]);
    assert_eq!(
        remote(socket(true, true, "inactive")),
        [Outcome::Pass],
        "masked"
    );
    assert_eq!(remote(json!({})), Vec::<Outcome>::new(), "not installed");
}

#[test]
fn sshd_offers_a_post_quantum_key_exchange() {
    let kex = |algorithms: Value| {
        let document =
            json!({"sshd": {"global": {"/etc/ssh/sshd_config": {"kexalgorithms": algorithms}}}});
        outcomes("ssh", "ssh/kex-post-quantum", &document)
    };
    assert_eq!(
        kex(json!(["mlkem768x25519-sha256", "curve25519-sha256"])),
        [Outcome::Pass]
    );
    assert_eq!(
        kex(json!([
            "curve25519-sha256",
            "sntrup761x25519-sha512@openssh.com"
        ])),
        [Outcome::Pass],
        "anywhere in the list"
    );
    assert_eq!(
        kex(json!(["curve25519-sha256", "curve25519-sha256@libssh.org"])),
        [Outcome::Fail]
    );
}

#[test]
fn every_unused_service_fails_enabled_or_running_and_passes_masked_or_off() {
    let rules: Value = ruleset_yaml("unused-services");
    for (rule, spec) in rules["rules"].as_object().unwrap() {
        for unit in spec["keys"]["enum"].as_array().unwrap() {
            let unit = unit.as_str().unwrap();
            let one = |enabled: bool, masked: bool, active: &str| {
                let state = json!({unit: {"enabled": enabled, "masked": masked, "active": active},
                                   "ssh.service": {"enabled": true, "masked": false, "active": "active"}});
                outcomes(
                    "unused-services",
                    rule,
                    &json!({"systemd": {"state": state}}),
                )
            };
            assert_eq!(
                one(true, false, "inactive"),
                [Outcome::Fail],
                "{rule} {unit} enabled"
            );
            assert_eq!(
                one(false, false, "activating"),
                [Outcome::Fail],
                "{rule} {unit} starting"
            );
            assert_eq!(
                one(false, false, "inactive"),
                [Outcome::Pass],
                "{rule} {unit} off"
            );
            assert_eq!(
                one(true, true, "inactive"),
                [Outcome::Pass],
                "{rule} {unit} masked"
            );
        }
        let absent = outcomes(
            "unused-services",
            rule,
            &json!({"systemd": {"state": {"ssh.service": {"enabled": true}}}}),
        );
        assert!(absent.is_empty(), "{rule}: no unit, no check");
    }
}

#[test]
fn the_benchmark_sysctl_keys_pass_only_at_their_value_on_all_and_default() {
    let rules = [
        ("ipv4-ip-forward", "ipv4", "", 0),
        ("ipv4-forwarding", "ipv4", "forwarding", 0),
        ("ipv6-forwarding", "ipv6", "forwarding", 0),
        ("ipv4-send-redirects", "ipv4", "send_redirects", 0),
        ("ipv4-rp-filter-strict", "ipv4", "rp_filter", 1),
        ("ipv4-log-martians", "ipv4", "log_martians", 1),
        ("ipv6-source-route", "ipv6", "accept_source_route", 0),
        ("ipv6-accept-ra", "ipv6", "accept_ra", 0),
    ];
    for (name, family, key, good) in rules {
        let rule = format!("ip-routing/{name}");
        let judged = |value: i64| {
            let settings = if key.is_empty() {
                json!({"net": {"ipv4": {"ip_forward": value}}})
            } else {
                let interfaces =
                    json!({"all": {key: value}, "default": {key: value}, "eth0": {key: value}});
                json!({"net": {family: {"conf": interfaces}}})
            };
            let outcomes = outcomes(
                "ip-routing",
                &rule,
                &json!({"sysctl": {"settings": settings}}),
            );
            assert_eq!(
                outcomes.len(),
                if key.is_empty() { 1 } else { 2 },
                "{rule}: all and default only"
            );
            outcomes
        };
        assert!(
            judged(good).iter().all(|o| *o == Outcome::Pass),
            "{rule} at {good}"
        );
        for bad in [good - 1, good + 1] {
            assert!(
                judged(bad).iter().all(|o| *o == Outcome::Fail),
                "{rule} at {bad}"
            );
        }
    }
}

#[test]
fn the_dev_sec_sysctl_keys_pass_only_at_their_value() {
    let cases = [
        (
            "ip-flood",
            "icmp-ratemask",
            "net.ipv4.icmp_ratemask",
            vec![88089],
            vec![88088, 88090],
        ),
        (
            "ip-flood",
            "tcp-rfc1337",
            "net.ipv4.tcp_rfc1337",
            vec![1],
            vec![0, 2],
        ),
        (
            "ip-routing",
            "arp-ignore",
            "net.ipv4.conf.all.arp_ignore",
            vec![1, 2],
            vec![0, 3],
        ),
        (
            "ip-routing",
            "arp-announce",
            "net.ipv4.conf.all.arp_announce",
            vec![2],
            vec![1, 3],
        ),
        (
            "ip-routing",
            "shared-media",
            "net.ipv4.conf.default.shared_media",
            vec![1],
            vec![0, 2],
        ),
        (
            "ip-routing",
            "ipv6-router-solicitations",
            "net.ipv6.conf.all.router_solicitations",
            vec![0],
            vec![-1, 1],
        ),
        (
            "ip-routing",
            "ipv6-ra-router-preference",
            "net.ipv6.conf.default.accept_ra_rtr_pref",
            vec![0],
            vec![1],
        ),
        (
            "ip-routing",
            "ipv6-ra-prefix-info",
            "net.ipv6.conf.default.accept_ra_pinfo",
            vec![0],
            vec![1],
        ),
        (
            "ip-routing",
            "ipv6-ra-default-router",
            "net.ipv6.conf.default.accept_ra_defrtr",
            vec![0],
            vec![1],
        ),
        (
            "ip-routing",
            "ipv6-autoconf",
            "net.ipv6.conf.default.autoconf",
            vec![0],
            vec![1],
        ),
        (
            "ip-routing",
            "ipv6-max-addresses",
            "net.ipv6.conf.default.max_addresses",
            vec![1],
            vec![0, 2],
        ),
        ("kernel", "sysrq", "kernel.sysrq", vec![0], vec![1, 176]),
    ];
    for (ruleset, name, key, good, bad) in cases {
        let rule = format!("{ruleset}/{name}");
        let judged = |value: i64| {
            let mut settings = json!({});
            let mut at = &mut settings;
            for part in key.split('.') {
                at = &mut at[part];
            }
            *at = json!(value);
            outcomes(ruleset, &rule, &json!({"sysctl": {"settings": settings}}))
        };
        for value in good {
            assert_eq!(judged(value), [Outcome::Pass], "{rule} at {value}");
        }
        for value in bad {
            assert_eq!(judged(value), [Outcome::Fail], "{rule} at {value}");
        }
    }
    let core = |dumpable: i64, pattern: &str| {
        let settings =
            json!({"fs": {"suid_dumpable": dumpable}, "kernel": {"core_pattern": pattern}});
        outcomes(
            "coredump",
            "coredump/core-pattern-absolute",
            &json!({"sysctl": {"settings": settings}}),
        )
    };
    assert_eq!(core(2, "|/usr/share/apport/apport -p%p"), [Outcome::Pass]);
    assert_eq!(core(2, "/var/crash/core.%p"), [Outcome::Pass]);
    assert_eq!(core(2, "core"), [Outcome::Fail]);
    assert_eq!(core(2, "| relative"), [Outcome::Fail]);
    assert_eq!(
        core(1, "core"),
        [Outcome::Skip],
        "only suid_dumpable 2 dumps setuid programs as root"
    );
}

#[test]
fn the_account_databases_belong_to_group_root_and_the_hashes_to_root_or_shadow() {
    let stat = |gid: i64| json!({"kind": "file", "uid": 0, "gid": gid, "mode": "0640"});
    let document = json!({
        "files": {"accounts": {"/etc/passwd": stat(0), "/etc/group": stat(1), "/etc/shells": {"kind": "symlink", "gid": 5}},
                  "shadow": {"/etc/shadow": stat(42), "/etc/gshadow": stat(0), "/etc/shadow-": stat(41),
                             "/etc/gshadow-": stat(43), "/etc/security/opasswd": stat(4)}},
        "accounts": {"group": {"shadow": {"gid": 42, "members": [], "shadowed": []}}}});
    let rule = |name: &str, document: &Value| -> Vec<(String, Outcome)> {
        judge("files", document)
            .into_iter()
            .filter(|(r, _, _)| r == name)
            .map(|(_, s, o)| (s, o))
            .collect()
    };
    assert_eq!(
        rule("files/accounts-group", &document),
        [
            ("/etc/group".into(), Outcome::Fail),
            ("/etc/passwd".into(), Outcome::Pass),
            ("/etc/shells".into(), Outcome::Skip),
        ],
        "gid 1 is the edge; a symlink is not judged"
    );
    assert_eq!(
        rule("files/shadow-group", &document),
        [
            ("/etc/gshadow".into(), Outcome::Pass),
            ("/etc/gshadow-".into(), Outcome::Fail),
            ("/etc/shadow".into(), Outcome::Pass),
            ("/etc/shadow-".into(), Outcome::Fail),
        ],
        "41 and 43 are the edges; opasswd is not CIS’s"
    );
    let mut moved = document.clone();
    moved["accounts"]["group"]["shadow"]["gid"] = json!(43);
    assert!(
        rule("files/shadow-group", &moved)
            .iter()
            .all(|(_, o)| *o == Outcome::Skip)
    );
}

#[test]
fn the_benchmark_mounts_are_separate_and_its_data_mounts_carry_their_options() {
    let judged = |active: Option<Value>| {
        let mut document = json!({"mounts": {"fstab": {}}, "collectors": {"mounts-active": {"status": "skipped", "reason": "live", "into": "mounts.active"}}});
        if let Some(active) = active {
            document["mounts"]["active"] = active;
            document["collectors"]["mounts-active"] =
                json!({"status": "ok", "into": "mounts.active"});
        }
        let mut checks: Vec<_> = judge("mounts", &document)
            .into_iter()
            .filter(|(rule, _, _)| {
                rule.starts_with("mounts/separate-") || rule.starts_with("mounts/partition-")
            })
            .collect();
        checks.sort();
        checks
    };
    let active = json!({"/": {"options": ["rw"]}, "/home": {"options": ["rw", "nodev"]}, "/var/log": {"options": ["nodev", "nosuid", "noexec"]}, "/tmp": {"options": []}});
    let failing: Vec<_> = judged(Some(active))
        .into_iter()
        .filter(|(_, _, o)| *o != Outcome::Pass)
        .collect();
    let row = |rule: &str, subject: &str| (rule.to_owned(), subject.to_owned(), Outcome::Fail);
    assert_eq!(
        failing,
        [
            row("mounts/partition-nosuid", "/home"),
            row("mounts/separate-dev-shm", ""),
            row("mounts/separate-var", ""),
            row("mounts/separate-var-log-audit", ""),
            row("mounts/separate-var-tmp", ""),
        ],
        "/home needs no noexec, and a mount that is absent has no options to judge"
    );
    assert!(
        judged(None).iter().all(|(_, _, o)| *o == Outcome::Skip),
        "under --root"
    );
}

#[test]
fn the_benchmark_sshd_keywords_pass_at_their_edge() {
    let main = "/etc/ssh/sshd_config";
    let setting = |rule: &str, keyword: &str, value: Value| {
        let document =
            json!({"sshd": {"settings": {keyword: {main: value}}, "global": {main: {}}}});
        outcomes("ssh", rule, &document)
    };
    let global = |rule: &str, values: Value| {
        outcomes("ssh", rule, &json!({"sshd": {"global": {main: values}}}))
    };
    assert_eq!(
        setting("ssh/banner-none", "banner", json!("none")),
        [Outcome::Fail]
    );
    assert_eq!(
        setting("ssh/banner-none", "banner", json!("/etc/issue.net")),
        [Outcome::Pass]
    );
    for (rule, keyword) in [
        ("ssh/client-alive-interval", "clientaliveinterval"),
        ("ssh/client-alive-count-max", "clientalivecountmax"),
    ] {
        assert_eq!(setting(rule, keyword, json!(0)), [Outcome::Fail], "{rule}");
        assert_eq!(setting(rule, keyword, json!(1)), [Outcome::Pass], "{rule}");
    }
    assert_eq!(
        setting(
            "ssh/gssapi-authentication",
            "gssapiauthentication",
            json!("yes")
        ),
        [Outcome::Fail]
    );
    assert_eq!(
        setting(
            "ssh/gssapi-authentication",
            "gssapiauthentication",
            json!("no")
        ),
        [Outcome::Pass]
    );
    assert_eq!(
        setting("ssh/max-sessions", "maxsessions", json!(10)),
        [Outcome::Pass]
    );
    assert_eq!(
        setting("ssh/max-sessions", "maxsessions", json!(11)),
        [Outcome::Fail]
    );
    for (value, outcome) in [
        ("10:30:60", Outcome::Pass),
        ("10", Outcome::Pass),
        ("1:100:1", Outcome::Pass),
        ("10:30:100", Outcome::Fail),
        ("11:30:60", Outcome::Fail),
        ("10:29:60", Outcome::Fail),
        ("10:30:61", Outcome::Fail),
    ] {
        assert_eq!(
            global("ssh/max-startups", json!({"maxstartups": value})),
            [outcome],
            "{value}"
        );
    }
    assert_eq!(
        global("ssh/use-pam", json!({"usepam": "yes"})),
        [Outcome::Pass]
    );
    assert_eq!(
        global("ssh/use-pam", json!({"usepam": "no"})),
        [Outcome::Fail]
    );
    assert_eq!(
        global("ssh/access-unlisted", json!({"usepam": "yes"})),
        [Outcome::Fail]
    );
    assert_eq!(
        global("ssh/access-unlisted", json!({"allowgroups": ["ssh-users"]})),
        [Outcome::Pass]
    );
    assert_eq!(
        global("ssh/access-unlisted", json!({"denyusers": ["guest"]})),
        [Outcome::Pass]
    );
}

// One auditd rule’s outcome, `auditd` on disk or not, over the kernel command line as kernel-cmdline reads `text`.
fn boot(rule: &str, installed: bool, text: &str) -> Outcome {
    let file = serde_json::from_value(json!({"path": "/proc/cmdline", "content": text})).unwrap();
    let with = json!({"records": " ", "negate": "!", "repeat": "last", "comments": []});
    let cmdline = systemlint_formats::kv(&[Input::File(file)], with.as_object().unwrap())
        .unwrap()
        .facts;
    let binary = if installed {
        json!({"/usr/sbin/auditd": {"exists": true}})
    } else {
        json!({})
    };
    let mut document = json!({"auditd": {"binary": binary}, "kernel": {"cmdline": cmdline}, "collectors": {
        "auditd-binary": {"status": "ok", "into": "auditd.binary"},
        "kernel-cmdline": {"status": "ok", "into": "kernel.cmdline"}}});
    if text.is_empty() {
        document["kernel"] = json!({});
    }
    judge("auditd", &document)
        .into_iter()
        .find(|(r, _, _)| r == rule)
        .unwrap()
        .2
}

#[test]
fn auditd_fails_off_disk_and_a_boot_without_audit_or_a_backlog_of_8192() {
    let stock = "BOOT_IMAGE=/vmlinuz-7.3.1 root=UUID=1234 ro quiet splash vt.handoff=7\n";
    assert_eq!(boot("auditd/not-installed", true, stock), Outcome::Pass);
    assert_eq!(boot("auditd/not-installed", false, stock), Outcome::Fail);
    assert_eq!(
        boot("auditd/disabled", false, stock),
        Outcome::Skip,
        "every other rule waits for auditd on disk"
    );
    assert_eq!(
        collected(
            "auditd/not-installed",
            "auditd-binary",
            "auditd.binary",
            None
        ),
        [(String::new(), Outcome::Unknown)]
    );
    let audit = |text: &str| boot("auditd/boot-unaudited", true, text);
    assert_eq!(audit(stock), Outcome::Fail);
    assert_eq!(audit("ro audit=1\n"), Outcome::Pass);
    assert_eq!(audit("ro audit=On\n"), Outcome::Pass);
    assert_eq!(audit("ro audit=0\n"), Outcome::Fail);
    assert_eq!(
        audit("audit=1 audit=off\n"),
        Outcome::Fail,
        "the last one wins"
    );
    assert_eq!(
        audit(""),
        Outcome::Unknown,
        "under --root the running kernel is not the root’s"
    );
    assert_eq!(boot("auditd/boot-unaudited", false, stock), Outcome::Skip);
    let backlog = |text: &str| boot("auditd/boot-backlog", true, text);
    assert_eq!(backlog(stock), Outcome::Fail, "unset means 64");
    assert_eq!(backlog("audit=1 audit_backlog_limit=8192\n"), Outcome::Pass);
    assert_eq!(backlog("audit_backlog_limit=8191\n"), Outcome::Fail);
    assert_eq!(
        backlog("audit-backlog-limit=8192\n"),
        Outcome::Pass,
        "the kernel reads - and _ alike in a parameter name"
    );
    assert_eq!(boot("auditd/boot-backlog", false, stock), Outcome::Skip);
}

#[test]
fn aide_fails_off_disk_and_without_an_enabled_running_daily_check() {
    let aide = |rule: &str, installed: bool, units: Value| {
        let binary = if installed {
            json!({"/usr/bin/aide": {"exists": true}})
        } else {
            json!({})
        };
        let document = json!({"aide": {"binary": binary}, "systemd": {"state": units}, "collectors": {
            "aide-binary": {"status": "ok", "into": "aide.binary"},
            "systemd-state": {"status": "ok", "into": "systemd.state"}}});
        judge("aide", &document)
            .into_iter()
            .find(|(r, _, _)| r == rule)
            .unwrap()
            .2
    };
    let units = |timer: Value, masked: bool| json!({"dailyaidecheck.timer": timer, "dailyaidecheck.service": {"enabled": false, "masked": masked}});
    let on = json!({"enabled": true, "masked": false, "active": "active"});
    assert_eq!(aide("aide/not-installed", true, json!({})), Outcome::Pass);
    assert_eq!(aide("aide/not-installed", false, json!({})), Outcome::Fail);
    assert_eq!(
        collected("aide/not-installed", "aide-binary", "aide.binary", None),
        [(String::new(), Outcome::Unknown)]
    );
    let scheduled = |units: Value| aide("aide/unscheduled", true, units);
    assert_eq!(scheduled(units(on.clone(), false)), Outcome::Pass);
    assert_eq!(
        scheduled(units(on.clone(), true)),
        Outcome::Fail,
        "a masked service never runs"
    );
    assert_eq!(
        scheduled(units(
            json!({"enabled": false, "masked": false, "active": "inactive"}),
            false
        )),
        Outcome::Fail
    );
    assert_eq!(
        scheduled(units(
            json!({"enabled": true, "masked": false, "active": "inactive"}),
            false
        )),
        Outcome::Fail
    );
    assert_eq!(
        scheduled(units(json!({"enabled": true, "masked": false}), false)),
        Outcome::Pass,
        "under --root no unit has an active state"
    );
    assert_eq!(scheduled(json!({})), Outcome::Fail, "no timer at all");
    assert_eq!(aide("aide/unscheduled", false, json!({})), Outcome::Skip);
}

// One apparmor rule’s outcomes, parser on disk or not, over securityfs `profiles` as apparmor-profiles reads it.
fn apparmor(rule: &str, installed: bool, profiles: &str, units: Value) -> Vec<(String, Outcome)> {
    let file = serde_json::from_value(
        json!({"path": "/sys/kernel/security/apparmor/profiles", "content": profiles}),
    )
    .unwrap();
    let with = json!({"pattern": "^(?P<key>.+) \\((?P<mode>[a-z]+)\\)$"});
    let loaded = systemlint_formats::r#match(&[Input::File(file)], with.as_object().unwrap())
        .unwrap()
        .facts;
    let binary = if installed {
        json!({"/usr/sbin/apparmor_parser": {"exists": true}})
    } else {
        json!({})
    };
    let document = json!({"apparmor": {"binary": binary, "profiles": loaded}, "systemd": {"state": units}, "collectors": {
        "apparmor-binary": {"status": "ok", "into": "apparmor.binary"},
        "apparmor-profiles": {"status": "ok", "into": "apparmor.profiles"},
        "systemd-state": {"status": "ok", "into": "systemd.state"}}});
    judge("apparmor", &document)
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, s, o)| (s, o))
        .collect()
}

#[test]
fn apparmor_fails_off_disk_unloaded_unstarted_and_each_profile_short_of_enforce() {
    let loaded = "/usr/bin/man (enforce)\nsnap.firefox.firefox (complain)\nbusybox (unconfined)\n/usr/sbin/cupsd//third_party (enforce)\n";
    let on = json!({"apparmor.service": {"enabled": true, "masked": false, "active": "active"}});
    let one = |rule: &str, installed: bool, profiles: &str, units: Value| {
        apparmor(rule, installed, profiles, units)[0].1
    };
    assert_eq!(
        one("apparmor/not-installed", true, loaded, on.clone()),
        Outcome::Pass
    );
    assert_eq!(
        one("apparmor/not-installed", false, loaded, on.clone()),
        Outcome::Fail
    );
    assert_eq!(
        one("apparmor/no-profiles", true, loaded, on.clone()),
        Outcome::Pass
    );
    assert_eq!(
        one("apparmor/no-profiles", true, "", on.clone()),
        Outcome::Fail,
        "apparmor=0 leaves no profiles file"
    );
    assert_eq!(
        one("apparmor/no-profiles", false, "", on.clone()),
        Outcome::Skip
    );
    assert_eq!(
        one("apparmor/service-off", true, loaded, on.clone()),
        Outcome::Pass
    );
    assert_eq!(
        one(
            "apparmor/service-off",
            true,
            loaded,
            json!({"apparmor.service": {"enabled": false, "masked": true}})
        ),
        Outcome::Fail
    );
    assert_eq!(
        one(
            "apparmor/service-off",
            true,
            loaded,
            json!({"apparmor.service": {"enabled": true, "active": "failed"}})
        ),
        Outcome::Fail
    );
    assert_eq!(
        one(
            "apparmor/service-off",
            true,
            loaded,
            json!({"apparmor.service": {"enabled": true}})
        ),
        Outcome::Pass,
        "under --root no unit has an active state"
    );
    assert_eq!(
        one("apparmor/service-off", true, loaded, json!({})),
        Outcome::Fail,
        "no unit at all"
    );
    assert_eq!(
        one("apparmor/service-off", false, loaded, json!({})),
        Outcome::Skip
    );
    assert_eq!(
        apparmor("apparmor/not-enforcing", true, loaded, on),
        [
            ("/usr/bin/man".to_owned(), Outcome::Pass),
            ("/usr/sbin/cupsd//third_party".to_owned(), Outcome::Pass),
            ("busybox".to_owned(), Outcome::Fail),
            ("snap.firefox.firefox".to_owned(), Outcome::Fail)
        ]
    );
}

#[test]
fn a_banner_fails_on_an_agetty_escape_naming_the_system_but_not_on_an_escaped_backslash() {
    let banner = |text: &str| {
        let file = serde_json::from_value(json!({"path": "/etc/issue", "content": text})).unwrap();
        let lines = systemlint_formats::lines(&[Input::File(file)]).facts;
        let document = json!({"banner-text": {"sshd": lines}, "collectors": {"banner-sshd-text": {"status": "ok", "into": "banner-text.sshd"}}});
        judge("banner", &document)
            .into_iter()
            .filter(|(r, _, _)| r == "banner/discloses-system")
            .map(|(_, _, o)| o)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        banner("Ubuntu 26.04 LTS \\n \\l\n"),
        [Outcome::Pass],
        "hostname and tty are left out"
    );
    assert_eq!(banner("Authorised use only.\n"), [Outcome::Pass]);
    assert_eq!(banner("Kernel \\r on \\m\n"), [Outcome::Fail]);
    assert_eq!(
        banner("\\S{PRETTY_NAME}\n"),
        [Outcome::Fail],
        "agetty reads \\S too"
    );
    assert_eq!(banner("\\v\n"), [Outcome::Fail]);
    assert_eq!(
        banner("C:\\\\share\n"),
        [Outcome::Pass],
        "an escaped backslash shows a backslash"
    );
    assert_eq!(banner("C:\\\\\\share\n"), [Outcome::Fail]);
}

#[test]
fn the_update_notifier_motd_units_fail_enabled_or_running_and_pass_masked_or_off() {
    for (rule, unit) in [
        (
            "banner/update-notifier-service",
            "update-notifier-motd.service",
        ),
        ("banner/update-notifier-timer", "update-notifier-motd.timer"),
    ] {
        let one = |enabled: bool, masked: bool, active: &str| {
            let state = json!({unit: {"enabled": enabled, "masked": masked, "active": active}});
            outcomes("banner", rule, &json!({"systemd": {"state": state}}))
        };
        assert_eq!(
            one(true, false, "inactive"),
            [Outcome::Fail],
            "{unit} enabled"
        );
        assert_eq!(
            one(false, false, "active"),
            [Outcome::Fail],
            "{unit} running"
        );
        assert_eq!(one(false, false, "inactive"), [Outcome::Pass], "{unit} off");
        assert_eq!(one(true, true, "active"), [Outcome::Pass], "{unit} masked");
        let absent = outcomes(
            "banner",
            rule,
            &json!({"systemd": {"state": {"ssh.service": {"enabled": true}}}}),
        );
        assert!(absent.is_empty(), "{rule}: no unit, no check");
    }
}

#[test]
fn every_client_binary_the_collector_stats_fails_exactly_one_clients_rule() {
    let yaml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../collectors/clients-binaries.yaml"),
    )
    .unwrap();
    let collector: Value = systemlint::yaml::from_str(&yaml).unwrap();
    let rules: Value = ruleset_yaml("clients");
    for pattern in collector["read"]["stat"].as_array().unwrap() {
        let path = pattern.as_str().unwrap().replace("/usr/*bin/", "/usr/bin/");
        let document = json!({"clients": {"binaries": {&path: {"uid": 0},
                                                       "/usr/bin/telnet": {"uid": 0},
                                                       "/usr/bin/rsh": {"uid": 0},
                                                       "/usr/bin/ypdomainname": {"uid": 0}}},
                              "collectors": {"clients-binaries": {"status": "ok", "into": "clients.binaries"}}});
        let failed: Vec<_> = judge("clients", &document)
            .into_iter()
            .filter(|(_, _, o)| *o != Outcome::Pass)
            .collect();
        assert_eq!(failed.len(), 1, "{path}: {failed:?}");
        assert_eq!(failed[0].2, Outcome::Fail, "{path}");
        assert!(rules["rules"][&failed[0].0].is_object());
    }
    let none = json!({"clients": {"binaries": {"/usr/bin/telnet": {"uid": 0}, "/usr/bin/ssh": {"uid": 0}}},
                      "collectors": {"clients-binaries": {"status": "ok", "into": "clients.binaries"}}});
    assert!(
        judge("clients", &none)
            .iter()
            .all(|(_, _, o)| *o == Outcome::Pass),
        "an alternatives link names no client"
    );
}

#[test]
fn timesyncd_passes_only_on_a_last_assignment_naming_a_server_and_applies_only_without_chrony() {
    let unit = |chrony: Option<bool>| {
        let mut state = json!({"systemd-timesyncd.service": {"enabled": true, "masked": false, "active": "active"}});
        if let Some(masked) = chrony {
            state["chrony.service"] = json!({"enabled": !masked, "masked": masked});
        }
        state
    };
    let server = |timesyncd: Value, chrony: Option<bool>| {
        outcomes(
            "timesync",
            "timesync/timesyncd-no-server",
            &json!({"timesyncd": timesyncd, "systemd": {"state": unit(chrony)}}),
        )
    };
    let main = |m: Value| json!({"main": m, "drop-ins": {}});
    assert_eq!(
        server(main(json!({"NTP": "a.example"})), None),
        [Outcome::Pass]
    );
    assert_eq!(
        server(main(json!({"FallbackNTP": "b.example"})), None),
        [Outcome::Pass]
    );
    assert_eq!(
        server(main(json!({"NTP": ""})), None),
        [Outcome::Fail],
        "empty"
    );
    assert_eq!(server(main(json!({})), None), [Outcome::Fail], "unset");
    assert_eq!(
        server(
            json!({"main": {"NTP": "a.example"}, "drop-ins": {"NTP": ""}}),
            None
        ),
        [Outcome::Fail],
        "a drop-in resets the list"
    );
    assert_eq!(
        server(
            json!({"main": {"NTP": ""}, "drop-ins": {"NTP": "a.example"}}),
            None
        ),
        [Outcome::Pass],
        "a drop-in overrides the main file"
    );
    assert_eq!(
        server(main(json!({})), Some(false)),
        [Outcome::Skip],
        "chrony keeps the clock"
    );
    assert_eq!(
        server(main(json!({})), Some(true)),
        [Outcome::Fail],
        "chrony masked"
    );
    let known = json!({"active": "inactive", "sub": "dead"});
    let mut conflicts = unit(None);
    conflicts["ntpsec.service"] = known.clone();
    conflicts["chrony.service"] = known;
    assert_eq!(
        outcomes(
            "timesync",
            "timesync/timesyncd-no-server",
            &json!({"timesyncd": main(json!({})), "systemd": {"state": conflicts}}),
        ),
        [Outcome::Fail],
        "a unit only the manager knows is not installed"
    );
    let running = |enabled: bool, active: &str, chrony: Option<bool>| {
        let mut state = unit(chrony);
        state["systemd-timesyncd.service"] =
            json!({"enabled": enabled, "masked": false, "active": active});
        outcomes(
            "timesync",
            "timesync/timesyncd-off",
            &json!({"systemd": {"state": state}}),
        )
    };
    assert_eq!(running(true, "active", None), [Outcome::Pass]);
    assert_eq!(running(true, "inactive", None), [Outcome::Fail]);
    assert_eq!(running(false, "active", None), [Outcome::Fail]);
    assert_eq!(running(false, "inactive", Some(false)), [Outcome::Skip]);
}

#[test]
fn chrony_passes_on_a_server_or_pool_in_its_config_or_source_files_and_while_enabled_and_running() {
    let state = |masked: bool, enabled: bool, active: &str| json!({"chrony.service": {"enabled": enabled, "masked": masked, "active": active}});
    let server = |conf: Value, sources: Value, masked: bool| {
        outcomes(
            "timesync",
            "timesync/chrony-no-server",
            &json!({"chrony": {"conf": conf, "sources": sources},
                    "systemd": {"state": state(masked, true, "active")},
                    "collectors": {"chrony-conf": {"status": "ok", "into": "chrony.conf"},
                                   "chrony-sources": {"status": "ok", "into": "chrony.sources"}}}),
        )
    };
    let conf = json!({"/etc/chrony/chrony.conf": {"sourcedir": ["/etc/chrony/sources.d"]}});
    assert_eq!(server(conf.clone(), json!({}), false), [Outcome::Fail]);
    assert_eq!(
        server(
            conf.clone(),
            json!({"/etc/chrony/sources.d/a.sources": {"pool": ["1.ntp.ubuntu.com"]}}),
            false
        ),
        [Outcome::Pass]
    );
    assert_eq!(
        server(
            json!({"/etc/chrony/chrony.conf": {"server": ["10.0.0.1", "iburst"]}}),
            json!({}),
            false
        ),
        [Outcome::Pass]
    );
    assert_eq!(
        server(json!({}), json!({}), false),
        [Outcome::Fail],
        "no chrony.conf"
    );
    assert_eq!(
        server(conf, json!({}), true),
        [Outcome::Skip],
        "chrony masked"
    );
    assert_eq!(
        outcomes(
            "timesync",
            "timesync/chrony-off",
            &json!({"systemd": {"state": {"chrony.service": {"active": "inactive", "sub": "dead"}}}}),
        ),
        [Outcome::Skip],
        "a chrony.service only the manager knows is not installed"
    );
    let running = |enabled: bool, active: &str| {
        outcomes(
            "timesync",
            "timesync/chrony-off",
            &json!({"systemd": {"state": state(false, enabled, active)}}),
        )
    };
    assert_eq!(running(true, "active"), [Outcome::Pass]);
    assert_eq!(running(true, "failed"), [Outcome::Fail]);
    assert_eq!(running(false, "active"), [Outcome::Fail]);
    let under_root =
        json!({"systemd": {"state": {"chrony.service": {"enabled": true, "masked": false}}}});
    assert_eq!(
        outcomes("timesync", "timesync/chrony-off", &under_root),
        [Outcome::Pass],
        "--root reads no active state"
    );
}
