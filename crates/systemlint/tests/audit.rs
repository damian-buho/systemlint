// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint_protocol::{ExecInput, Input};

// The shipped audit ruleset, parsed as the caller needs it.
fn ruleset<T: serde::de::DeserializeOwned>() -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/audit.yaml");
    systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

// Each rule’s fix as the audit lines it adds, by rule ID.
fn fixes() -> BTreeMap<String, Vec<String>> {
    let rules = ruleset::<Value>()["rules"].as_object().unwrap().clone();
    rules
        .into_iter()
        .filter_map(|(id, rule)| {
            let fix = rule["fix"].as_str()?.strip_prefix("add -a ")?;
            let (lines, _) = fix.split_once(" to a .rules file")?;
            Some((
                id,
                format!("-a {lines}")
                    .split(", ")
                    .map(str::to_owned)
                    .collect(),
            ))
        })
        .collect()
}

// Every fix but `without`, then -c and -e 2, as one rules.d file.
fn remediated(without: &str) -> String {
    let mut lines: Vec<String> = fixes()
        .into_iter()
        .filter(|(id, _)| id != without)
        .flat_map(|(_, lines)| lines)
        .collect();
    lines.extend(["-c".to_owned(), "-e 2".to_owned()]);
    lines.join("\n") + "\n"
}

// The same lines as auditctl -l prints them: no -c or -e, the key as -F key=.
fn listed(on_disk: &str) -> String {
    on_disk
        .lines()
        .filter(|l| l.starts_with("-a ") || l.starts_with("-w "))
        .map(|l| l.replace(" -k ", " -F key="))
        .collect::<Vec<_>>()
        .join("\n")
}

// The facts formats options makes of one rules.d file and one auditctl -l run, with auditd on disk.
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
    let with = json!({"split": ["-a", "-S"]});
    let with = with.as_object().unwrap();
    let rules = systemlint_formats::flags(&[Input::File(file)], with)
        .unwrap()
        .facts;
    let loaded = systemlint_formats::flags(&[Input::Exec(run)], with)
        .unwrap()
        .facts;
    json!({"audit": {"rules": rules, "loaded": loaded}, "auditd": {"binary": {"/usr/sbin/auditd": {"mode": "0755"}}}})
}

// Every check of the shipped ruleset, as (rule, subject, outcome).
fn judge(document: &Value) -> Vec<(String, String, Outcome)> {
    let library = Library::new(BTreeMap::from([("audit".to_owned(), ruleset())])).unwrap();
    let rules: Vec<_> = library
        .select(&["audit".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(document, &rules, &[], "2026-11-15")
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

// The outcome of one rule over a rules.d file holding `on_disk` alone.
fn on_disk(rule: &str, on_disk: &str) -> Outcome {
    outcomes(&facts(on_disk, ""), rule)
        .into_iter()
        .find(|(s, _)| s != "loaded")
        .unwrap()
        .1
}

#[test]
fn every_fix_passes_its_rule_on_disk_and_as_auditctl_lists_it() {
    let on_disk = remediated("");
    let checks = judge(&facts(&on_disk, &listed(&on_disk)));
    assert_eq!(checks.len(), fixes().len() * 2 + 2);
    let failed: Vec<_> = checks
        .into_iter()
        .filter(|(_, _, o)| *o != Outcome::Pass)
        .collect();
    assert_eq!(failed, []);
}

#[test]
fn leaving_out_one_rules_lines_fails_that_rule_alone() {
    for rule in fixes().keys() {
        let failed: Vec<_> = judge(&facts(&remediated(rule), ""))
            .into_iter()
            .filter(|(_, s, o)| s == "rules" && *o != Outcome::Pass)
            .map(|(r, _, _)| r)
            .collect();
        assert_eq!(failed, std::slice::from_ref(rule), "{rule}");
    }
}

#[test]
fn a_watch_passes_with_w_and_a_and_fails_on_a_lesser_access_or_another_path() {
    for (lines, outcome) in [
        (
            "-w /etc/sudoers -p wa\n-w /etc/sudoers.d/ -p rwa",
            Outcome::Pass,
        ),
        (
            "-a exit,always -F path=/etc/sudoers -F perm=aw\n-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa -F auid>=1000",
            Outcome::Pass,
        ),
        (
            "-w /etc/sudoers -p w\n-w /etc/sudoers.d -p wa",
            Outcome::Fail,
        ),
        (
            "-a always,exit -F path=/etc/sudoers -F perm=a\n-w /etc/sudoers.d -p wa",
            Outcome::Fail,
        ),
        (
            "-a never,exit -F path=/etc/sudoers -F perm=wa\n-w /etc/sudoers.d -p wa",
            Outcome::Fail,
        ),
        (
            "-w /etc/sudoers -p wa\n-a always,exit -F path=/etc/sudoers.d -F perm=wa",
            Outcome::Fail,
        ),
        (
            "-w /etc/sudoers -p wa\n# -w /etc/sudoers.d -p wa",
            Outcome::Fail,
        ),
        (
            "-w /etc/sudoers -p wa\n-w /etc/sudoers.dx -p wa",
            Outcome::Fail,
        ),
    ] {
        assert_eq!(on_disk("audit/sudoers", lines), outcome, "{lines}");
    }
}

#[test]
fn a_program_run_passes_on_x_and_fails_on_write_alone() {
    for (lines, outcome) in [
        (
            "-a always,exit -F path=/usr/bin/kmod -F perm=x",
            Outcome::Pass,
        ),
        ("-w /usr/bin/kmod -p rx", Outcome::Pass),
        (
            "-a always,exit -F path=/usr/bin/kmod -F perm=wa",
            Outcome::Fail,
        ),
        ("-w /usr/bin/kmod -p wa", Outcome::Fail),
    ] {
        assert_eq!(on_disk("audit/kmod", lines), outcome, "{lines}");
    }
}

#[test]
fn a_syscall_passes_grouped_or_split_and_fails_without_an_architecture() {
    for (lines, outcome) in [
        (
            "-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000\n-a always,exit -F arch=b32 -S mount",
            Outcome::Pass,
        ),
        (
            "-a always,exit -F arch=b64 -S mount\n-a always,exit -F arch=b64 -S mount",
            Outcome::Fail,
        ),
        (
            "-a always,exit -F arch=b64 -S mount\n-a always,exit -F arch=b32 -S umount2",
            Outcome::Fail,
        ),
    ] {
        assert_eq!(on_disk("audit/mount", lines), outcome, "{lines}");
    }
    let split = "-a always,exit -F arch=b64 -S unlink\n-a always,exit -F arch=b64 -S unlinkat\n-a always,exit -F arch=b32 -S unlinkat,unlink";
    assert_eq!(on_disk("audit/unlink", split), Outcome::Pass);
    assert_eq!(
        on_disk(
            "audit/time",
            "-a always,exit -S adjtimex,settimeofday,clock_settime\n-w /etc/localtime -p wa"
        ),
        Outcome::Pass
    );
}

#[test]
fn denied_access_passes_on_each_error_or_no_error_filter_and_fails_on_one_alone() {
    let calls = "creat,open,openat,truncate,ftruncate";
    let both = |filter: &str| {
        format!(
            "-a always,exit -F arch=b64 -S {calls}{filter}\n-a always,exit -F arch=b32 -S {calls}{filter}\n"
        )
    };
    assert_eq!(
        on_disk(
            "audit/access-denied",
            &(both(" -F exit=-EACCES") + &both(" -F exit=-EPERM"))
        ),
        Outcome::Pass
    );
    assert_eq!(on_disk("audit/access-denied", &both("")), Outcome::Pass);
    assert_eq!(
        on_disk("audit/access-denied", &both(" -F exit=-EPERM")),
        Outcome::Fail
    );
    assert_eq!(
        on_disk("audit/access-denied", &both(" -F exit=-ENOENT")),
        Outcome::Fail
    );
}

#[test]
fn rules_left_mutable_or_stopping_at_an_error_fail_and_a_later_lock_alone_passes() {
    let base = remediated("");
    for (from, to, rule, outcome) in [
        ("-e 2", "-e 1", "audit/immutable", Outcome::Fail),
        ("-e 2", "", "audit/immutable", Outcome::Fail),
        ("-e 2", "-e 2\n-e 0", "audit/immutable", Outcome::Fail),
        ("-e 2", "-e 2 # locked", "audit/immutable", Outcome::Pass),
        ("-c\n", "", "audit/continue-on-error", Outcome::Fail),
        (
            "-c\n",
            "-c # keep going\n",
            "audit/continue-on-error",
            Outcome::Pass,
        ),
    ] {
        assert_eq!(
            on_disk(rule, &base.replace(from, to)),
            outcome,
            "{from} -> {to}"
        );
    }
}

#[test]
fn no_rules_file_fails_and_no_auditd_is_not_applicable() {
    let mut document = facts("", "");
    document["audit"]["rules"] = json!({});
    assert_eq!(
        outcomes(&document, "audit/sudoers"),
        [
            ("loaded".into(), Outcome::Fail),
            ("rules".into(), Outcome::Fail)
        ]
    );
    document["auditd"]["binary"] = json!({});
    assert!(
        judge(&document)
            .iter()
            .all(|(_, _, o)| *o == Outcome::NotApplicable)
    );
}
