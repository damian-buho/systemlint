// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint_protocol::{ExecInput, Input};

// CIS 6.2.3.1, 6.2.3.2 and 6.2.3.20 as rule patterns over the lines of both sources, each a line some source must hold.
const RULESET: &str = r#"
description: CIS audits over audit rule lines
rules:
  audit/scope:
    title: sudoers changes unaudited
    fact: audit.*
    expect:
      not:
        additionalProperties:
          not:
            contains: {pattern: '^\s*-w\s+/etc/sudoers(?=\s)(?=.*\s-p\s*(?=\S*w)(?=\S*a))(?=.*\s(-k\s*|-F\s*key=)\S)'}
  audit/user-emulation:
    title: commands run as another user unaudited
    fact: audit.*
    expect:
      allOf:
        - not: {additionalProperties: {not: {contains: {pattern: '^\s*-a\s+always,exit(?=.*\s-F\s*arch=b64\b)(?=.*\s-F\s*auid!=(unset|-1|4294967295)\b)(?=.*\s-C\s*(euid!=uid|uid!=euid)\b)(?=.*\s-S\s*(\S*,)?execve\b)(?=.*\s(-k\s*|-F\s*key=)\S)'}}}}
        - not: {additionalProperties: {not: {contains: {pattern: '^\s*-a\s+always,exit(?=.*\s-F\s*arch=b32\b)(?=.*\s-F\s*auid!=(unset|-1|4294967295)\b)(?=.*\s-C\s*(euid!=uid|uid!=euid)\b)(?=.*\s-S\s*(\S*,)?execve\b)(?=.*\s(-k\s*|-F\s*key=)\S)'}}}}
  audit/immutable:
    title: audit rules left mutable
    fact: audit.rules
    expect:
      allOf:
        - not: {additionalProperties: {not: {contains: {pattern: '^\s*-e\s+2\b'}}}}
        - additionalProperties: {not: {contains: {pattern: '^\s*-e\s+[01]\b'}}}
"#;

// The rules.d file as CIS’s remediation writes it.
const ON_DISK: &str = "## stock\n-D\n-w /etc/sudoers -p aw -k scope\n-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation\n-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation\n-e 2\n";

// The same rules as auditctl -l prints them once loaded.
const LOADED: &str = "-w /etc/sudoers -p wa -k scope\n-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation\n-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation\n";

// The facts formats lines makes of one rules.d file and one auditctl -l run.
fn facts(on_disk: &str, loaded: &str) -> Value {
    let file = serde_json::from_value(
        json!({"path": "/etc/audit/rules.d/50-cis.rules", "content": on_disk}),
    )
    .unwrap();
    let run = ExecInput {
        argv: vec!["/usr/sbin/auditctl".into(), "-l".into()],
        stdout: loaded.into(),
        stderr: String::new(),
        exit: 0,
    };
    let rules = systemlint_formats::lines(&[Input::File(file)]).facts;
    let loaded = systemlint_formats::lines(&[Input::Exec(run)]).facts;
    json!({"audit": {"rules": rules, "loaded": loaded}})
}

// Every check of the ruleset above, as (rule, subject, outcome).
fn judge(document: &Value) -> Vec<(String, String, Outcome)> {
    let parsed = systemlint::yaml::from_str(RULESET).unwrap();
    let library = Library::new(BTreeMap::from([("audit".to_owned(), parsed)])).unwrap();
    let rules: Vec<_> = library
        .select(&["audit".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-14")
        .into_iter()
        .map(|c| (c.rule.clone(), c.subject_label(), c.outcome))
        .collect()
}

// The outcomes of one rule, by subject.
fn outcomes(document: &Value, rule: &str) -> Vec<(String, Outcome)> {
    judge(document)
        .into_iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, s, o)| (s, o))
        .collect()
}

#[test]
fn cis_audits_pass_on_the_remediated_files_and_on_what_auditctl_lists() {
    let failed: Vec<_> = judge(&facts(ON_DISK, LOADED))
        .into_iter()
        .filter(|(_, _, o)| *o != Outcome::Pass)
        .collect();
    assert_eq!(failed, []);
}

#[test]
fn a_watch_missing_an_access_or_its_key_fails() {
    for line in [
        "-w /etc/sudoers -p w -k scope",
        "-w /etc/sudoers -p wa",
        "# -w /etc/sudoers -p wa -k scope",
        "-w /etc/sudoers.d -p wa -k scope",
    ] {
        let document = facts(
            ON_DISK,
            &LOADED.replace("-w /etc/sudoers -p wa -k scope", line),
        );
        assert_eq!(
            outcomes(&document, "audit/scope"),
            [
                ("loaded".into(), Outcome::Fail),
                ("rules".into(), Outcome::Pass)
            ],
            "{line}"
        );
    }
}

#[test]
fn a_syscall_rule_missing_a_filter_or_an_arch_fails() {
    for (from, to) in [
        (" -F auid!=-1", ""),
        (" -C uid!=euid", ""),
        ("arch=b32", "arch=b64"),
        ("-S execve", "-S execveat"),
    ] {
        let document = facts(ON_DISK, &LOADED.replacen(from, to, 2));
        assert_eq!(
            outcomes(&document, "audit/user-emulation")[0],
            ("loaded".into(), Outcome::Fail),
            "{from}"
        );
    }
    let grouped = facts(ON_DISK, &LOADED.replace("-S execve", "-S execveat,execve"));
    assert_eq!(
        outcomes(&grouped, "audit/user-emulation")[0],
        ("loaded".into(), Outcome::Pass)
    );
}

#[test]
fn rules_left_mutable_fail_and_a_later_lock_alone_passes() {
    assert_eq!(
        outcomes(
            &facts(&ON_DISK.replace("-e 2", "-e 1"), LOADED),
            "audit/immutable"
        ),
        [("".into(), Outcome::Fail)]
    );
    assert_eq!(
        outcomes(
            &facts(&ON_DISK.replace("-e 2", ""), LOADED),
            "audit/immutable"
        ),
        [("".into(), Outcome::Fail)]
    );
    assert_eq!(
        outcomes(
            &facts(&ON_DISK.replace("-e 2", "-e 2 # locked"), LOADED),
            "audit/immutable"
        ),
        [("".into(), Outcome::Pass)]
    );
}
