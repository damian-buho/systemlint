// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Check, Waiver, compile, lint};
use systemlint::report::{lint_sarif, lint_textfile};

fn facts(name: &str) -> Value {
    systemlint::document::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../fixtures/lint/facts/{name}.yaml"))).unwrap()
}

const HTTPS: &str = "fact: apt.sources.*.uri\nexpect: {pattern: '^https://'}\nmessage: '{subject} fetches over {got}'\nseverity: warning\ndocs: https://example.org/https\ntags: [apt, std:1.2]\n";

fn run(yaml: &str, document: &Value, waivers: &[Waiver]) -> Vec<Check> {
    lint(document, &[compile("apt/https", systemlint::yaml::from_str(yaml).unwrap()).unwrap()], waivers, "2026-11-11")
}

fn sarif(document: &Value, checks: &[Check]) -> Value {
    serde_json::from_str(&lint_sarif(document, checks)).unwrap()
}

#[test]
fn sarif_reports_a_failure_at_its_file_under_the_root() {
    let document = facts("root");
    let log = sarif(&document, &run(HTTPS, &document, &[]));
    let run = &log["runs"][0];
    assert_eq!(log["version"], "2.1.0");
    assert_eq!(run["originalUriBaseIds"]["ROOT"]["uri"], "file:///srv/image/");
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "the passing source gives no result: {results:?}");
    assert_eq!((&results[0]["kind"], &results[0]["level"]), (&json!("fail"), &json!("warning")));
    assert_eq!(results[0]["locations"][0]["physicalLocation"]["artifactLocation"], json!({"uri": "etc/apt/sources.list.d/old.sources", "uriBaseId": "ROOT"}));
    assert_eq!(results[0]["message"]["text"], "/etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”");
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!((&rule["id"], &rule["helpUri"], &rule["properties"]["security-severity"]), (&json!("apt/https"), &json!("https://example.org/https"), &json!("5.0")));
    assert_eq!(rule["properties"]["tags"], json!(["apt", "std:1.2"]));
}

#[test]
fn sarif_reads_a_line_only_from_a_positive_number_and_encodes_the_path() {
    let mut document = facts("root");
    document["apt"]["sources"] = json!({"/etc/apt/sources.list:1": {"uri": "http://a"}, "/etc/apt/a b.list:0": {"uri": "http://b"}, "/etc/apt/c.list:x": {"uri": "http://c"}});
    let log = sarif(&document, &run(HTTPS, &document, &[]));
    let found: Vec<(Value, Value)> = log["runs"][0]["results"].as_array().unwrap().iter().map(|r| (r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].clone(), r["locations"][0]["physicalLocation"]["region"]["startLine"].clone())).collect();
    assert_eq!(found, [(json!("etc/apt/a%20b.list:0"), Value::Null), (json!("etc/apt/c.list:x"), Value::Null), (json!("etc/apt/sources.list"), json!(1))]);
}

#[test]
fn sarif_keeps_unknowns_open_waivers_suppressed_and_collector_errors_as_notifications() {
    let document = facts("unprivileged");
    let unknown = lint(&document, &[compile("files/shadow", systemlint::yaml::from_str("fact: files./etc/shadow.world-readable\nexpect: {const: false}\n").unwrap()).unwrap()], &[], "2026-11-11");
    let mut failing = facts("root");
    failing["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    let waiver = Waiver { rule: "apt/*".into(), subject: None, reason: "mirror retired in December".into(), until: "2026-11-30".into() };
    let waived = run(HTTPS, &failing, &[waiver]);
    let log = sarif(&document, &[unknown, waived].concat());
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!((&results[0]["kind"], &results[0]["level"]), (&json!("open"), &json!("none")));
    assert!(results[0]["locations"][0].get("physicalLocation").is_none(), "a fact with no path subject has a logical location only");
    assert_eq!(results[1]["suppressions"][0]["justification"], "mirror retired in December (until 2026-11-30)");
    let notes = &log["runs"][0]["invocations"][0]["toolExecutionNotifications"];
    assert_eq!(notes[0]["message"]["text"], "collector shadow: can’t stat /etc/shadow: Permission denied (os error 13)");
}

#[test]
fn sarif_bases_a_host_at_slash_and_a_relative_root_on_no_uri() {
    let mut document = facts("root");
    document["meta"]["subject"] = json!({"kind": "host", "name": "kiota"});
    assert_eq!(sarif(&document, &[])["runs"][0]["originalUriBaseIds"]["ROOT"]["uri"], "file:///");
    document["meta"]["subject"] = json!({"kind": "root", "path": "fixtures/ubuntu"});
    assert!(sarif(&document, &[])["runs"][0]["originalUriBaseIds"]["ROOT"].get("uri").is_none());
}

#[test]
fn textfile_counts_outcomes_rules_and_collectors() {
    let mut document = facts("unprivileged");
    document["collectors"]["odd\"id\\\n"] = json!({"status": "skipped"});
    let text = lint_textfile(&document, &run(HTTPS, &document, &[]));
    for line in [
        "systemlint_checks{outcome=\"pass\"} 1",
        "systemlint_checks{outcome=\"fail\"} 0",
        "systemlint_rule_checks{rule=\"apt/https\",outcome=\"pass\"} 1",
        "systemlint_failures{severity=\"error\"} 0",
        "systemlint_failures{severity=\"hint\"} 0",
        "systemlint_collector_status{collector=\"shadow\",status=\"error\"} 1",
        "systemlint_collector_status{collector=\"shadow\",status=\"ok\"} 0",
        "systemlint_collector_status{collector=\"odd\\\"id\\\\\\n\",status=\"skipped\"} 1",
        "systemlint_privileged 0",
        "# TYPE systemlint_rule_checks gauge",
    ] {
        assert!(text.lines().any(|l| l == line), "missing {line:?} in:\n{text}");
    }
}

#[test]
fn write_replaces_a_file_atomically_with_its_mode() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("report-write");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("systemlint.prom");
    std::fs::write(&path, "old").unwrap();
    systemlint::document::write(&path, "new\n", 0o644).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o644 & !umask());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file is left");
}

fn umask() -> u32 {
    let mask = rustix::process::umask(rustix::fs::Mode::empty());
    rustix::process::umask(mask);
    mask.bits()
}
