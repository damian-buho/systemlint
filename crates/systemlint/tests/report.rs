// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{Check, Outcome, Waived, Waiver, compile, level_of, lint};
use systemlint::report::{
    Colour, Rating, colour, lint_human, lint_json, lint_plain, lint_sarif, lint_textfile, rate,
    weight,
};
use systemlint::rules::Library;

fn facts(name: &str) -> Value {
    systemlint::document::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../fixtures/lint/facts/{name}.yaml")),
    )
    .unwrap()
}

const HTTPS: &str = "fact: apt.sources.*.uri\nexpect: {pattern: '^https://'}\nmessage: '{subject} fetches over {got}'\nseverity: warning\ndocs: https://example.org/https\ntags: [apt, std:1.2]\n";

fn run(yaml: &str, document: &Value, waivers: &[Waiver]) -> Vec<Check> {
    lint(
        document,
        &[compile("apt/https", systemlint::yaml::from_str(yaml).unwrap()).unwrap()],
        waivers,
        "2026-11-11",
    )
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
    assert_eq!(
        run["originalUriBaseIds"]["ROOT"]["uri"],
        "file:///srv/image/"
    );
    let results = run["results"].as_array().unwrap();
    assert_eq!(
        results.len(),
        1,
        "the passing source gives no result: {results:?}"
    );
    assert_eq!(
        (&results[0]["kind"], &results[0]["level"]),
        (&json!("fail"), &json!("warning"))
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"],
        json!({"uri": "etc/apt/sources.list.d/old.sources", "uriBaseId": "ROOT"})
    );
    assert_eq!(
        results[0]["message"]["text"],
        "/etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”"
    );
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!(
        (
            &rule["id"],
            &rule["helpUri"],
            &rule["properties"]["security-severity"]
        ),
        (
            &json!("apt/https"),
            &json!("https://example.org/https"),
            &json!("5.0")
        )
    );
    assert_eq!(rule["properties"]["tags"], json!(["apt", "std:1.2"]));
}

#[test]
fn sarif_reads_a_line_only_from_a_positive_number_and_encodes_the_path() {
    let mut document = facts("root");
    document["apt"]["sources"] = json!({"/etc/apt/sources.list:1": {"uri": "http://a"}, "/etc/apt/a b.list:0": {"uri": "http://b"}, "/etc/apt/c.list:x": {"uri": "http://c"}});
    let log = sarif(&document, &run(HTTPS, &document, &[]));
    let found: Vec<(Value, Value)> = log["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].clone(),
                r["locations"][0]["physicalLocation"]["region"]["startLine"].clone(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (json!("etc/apt/a%20b.list:0"), Value::Null),
            (json!("etc/apt/c.list:x"), Value::Null),
            (json!("etc/apt/sources.list"), json!(1))
        ]
    );
}

#[test]
fn sarif_keeps_unknowns_open_waivers_suppressed_and_collector_errors_as_notifications() {
    let document = facts("unprivileged");
    let unknown = lint(
        &document,
        &[compile(
            "files/shadow",
            systemlint::yaml::from_str(
                "fact: files./etc/shadow.world-readable\nexpect: {const: false}\n",
            )
            .unwrap(),
        )
        .unwrap()],
        &[],
        "2026-11-11",
    );
    let mut failing = facts("root");
    failing["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    let waiver = Waiver {
        rule: "apt/*".into(),
        subject: None,
        reason: "mirror retired in December".into(),
        until: "2026-11-30".into(),
    };
    let waived = run(HTTPS, &failing, &[waiver]);
    let log = sarif(&document, &[unknown, waived].concat());
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(
        (&results[0]["kind"], &results[0]["level"]),
        (&json!("open"), &json!("none"))
    );
    assert!(
        results[0]["locations"][0].get("physicalLocation").is_none(),
        "a fact with no path subject has a logical location only"
    );
    assert_eq!(
        results[1]["suppressions"][0]["justification"],
        "mirror retired in December (until 2026-11-30)"
    );
    let notes = &log["runs"][0]["invocations"][0]["toolExecutionNotifications"];
    assert_eq!(
        notes[0]["message"]["text"],
        "collector shadow: can’t stat /etc/shadow: Permission denied (os error 13)"
    );
}

#[test]
fn sarif_bases_a_host_at_slash_and_a_relative_root_on_no_uri() {
    let mut document = facts("root");
    document["meta"]["subject"] = json!({"kind": "host", "name": "kiota"});
    assert_eq!(
        sarif(&document, &[])["runs"][0]["originalUriBaseIds"]["ROOT"]["uri"],
        "file:///"
    );
    document["meta"]["subject"] = json!({"kind": "root", "path": "fixtures/ubuntu"});
    assert!(
        sarif(&document, &[])["runs"][0]["originalUriBaseIds"]["ROOT"]
            .get("uri")
            .is_none()
    );
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
        "systemlint_failures{severity=\"advice\"} 0",
        "systemlint_collector_status{collector=\"shadow\",status=\"error\"} 1",
        "systemlint_collector_status{collector=\"shadow\",status=\"ok\"} 0",
        "systemlint_collector_status{collector=\"odd\\\"id\\\\\\n\",status=\"skipped\"} 1",
        "systemlint_privileged 0",
        "# TYPE systemlint_rule_checks gauge",
    ] {
        assert!(
            text.lines().any(|l| l == line),
            "missing {line:?} in:\n{text}"
        );
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
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o644 & !umask()
    );
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no temporary file is left"
    );
}

#[test]
fn write_to_a_dash_prints_and_creates_no_file() {
    systemlint::document::write(Path::new("-"), "", 0o644).unwrap();
    assert!(
        !Path::new("-").exists(),
        "- is stdout, never a file in the working directory"
    );
}

fn umask() -> u32 {
    let mask = rustix::process::umask(rustix::fs::Mode::empty());
    rustix::process::umask(mask);
    mask.bits()
}

#[test]
fn human_folds_unknowns_from_skipped_collectors_into_one_line_per_reason() {
    let mut document = facts("root");
    document["env"] = json!({"files": {"/etc/environment": {"vars": {}}}});
    let root = json!({"status": "skipped", "reason": "needs root, and this run is unprivileged", "into": "env.processes"});
    document["collectors"]["env-processes"] = root.clone();
    document["collectors"]["env-defaults"] =
        json!({"status": "skipped", "reason": root["reason"], "into": "env.defaults"});
    document["collectors"]["env-image"] =
        json!({"status": "error", "reason": "can’t read it", "into": "env.image"});
    let rules = ["a", "b"].map(|id| {
        compile(
            &format!("env/{id}"),
            systemlint::yaml::from_str("fact: env.*.*.vars\nexpect: {type: object}\n").unwrap(),
        )
        .unwrap()
    });
    let checks = lint(&document, &rules, &[], "2026-11-11");
    let text = lint_human(&document, &checks, 0, false, false, false);
    assert!(text.contains("Not run (env-defaults, env-processes): needs root, and this run is unprivileged\n  env/a, env/b\n\n"), "{text}");
    assert_eq!(text.matches("Not run (").count(), 1, "{text}");
    assert!(
        text.contains("Unknown: [env/a]\n- image: ") && !text.contains("- processes"),
        "an error stays its own line: {text}"
    );
    assert!(
        text.ends_with("Passed            2\nUnknown           2\nNot run           4, they need root, an opt-in flag or fresher facts\n"),
        "{text}"
    );
    assert!(
        lint_textfile(&document, &checks).contains("outcome=\"unknown\""),
        "machine formats keep the unknown"
    );
}

#[test]
fn an_opt_in_left_off_prints_no_block_and_still_counts() {
    let mut document = facts("root");
    document["collectors"]["env-image"] = json!({"status": "skipped", "opt-in": true, "reason": "reads an image config, and no --image-config was given", "into": "env.image"});
    document["collectors"]["env-processes"] = json!({"status": "skipped", "reason": "can’t read /proc/1/environ without root", "into": "env.processes"});
    let rules = ["image", "processes"].map(|source| {
        let yaml = format!("fact: env.{source}.*.vars\nexpect: {{type: object}}\n");
        compile(
            &format!("env/{source}"),
            systemlint::yaml::from_str(&yaml).unwrap(),
        )
        .unwrap()
    });
    let checks = lint(&document, &rules, &[], "2026-11-14");
    let text = lint_human(&document, &checks, 0, false, false, false);
    assert!(!text.contains("image-config"), "{text}");
    assert!(
        text.contains("Not run (env-processes): can’t read /proc/1/environ without root\n"),
        "{text}"
    );
    assert!(
        text.ends_with("Not run           2, they need root, an opt-in flag or fresher facts\n"),
        "{text}"
    );
    let plain = lint_plain(&document, &checks, true);
    assert!(
        !plain.contains("image-config") && plain.contains("without root"),
        "{plain}"
    );
}

#[test]
fn human_folds_an_unreadable_path_into_one_line_for_every_rule() {
    let document = json!({
        "env": {"defaults": {"/etc/default/locale": {"vars": {}}}},
        "collectors": {"env-defaults": {"status": "ok", "into": "env.defaults", "unreadable": {"/etc/default/cacerts": "permission denied"}}}
    });
    let rules = ["a", "b"].map(|id| {
        compile(
            &format!("env/{id}"),
            systemlint::yaml::from_str("fact: env.defaults.*.vars\nexpect: {type: object}\n")
                .unwrap(),
        )
        .unwrap()
    });
    let checks = lint(&document, &rules, &[], "2026-11-13");
    let text = lint_human(&document, &checks, 0, false, false, false);
    assert!(
        text.starts_with(
            "Not read (env-defaults): /etc/default/cacerts, permission denied\n  env/a, env/b\n\n"
        ),
        "{text}"
    );
    assert!(!text.contains("Unknown: ["), "{text}");
    assert!(
        text.ends_with("Passed            2\nUnknown           2\n"),
        "the summary keeps them unknown: {text}"
    );
}

fn judged(outcome: Outcome, score: f64) -> Check {
    Check {
        rule: "r".into(),
        title: None,
        outcome,
        subject: vec![],
        fact: "f".into(),
        severity: Some(level_of(score)),
        score: Some(score),
        message: None,
        text: None,
        variables: BTreeMap::new(),
        value: None,
        reason: None,
        collector: None,
        waiver: None,
        tags: vec![],
        fix: None,
        remedy: None,
        docs: None,
        rationale: None,
        references: vec![],
    }
}

fn grade(failures: &[f64], passes: usize) -> Option<char> {
    let checks: Vec<Check> = failures
        .iter()
        .map(|s| judged(Outcome::Fail, *s))
        .chain((0..passes).map(|_| judged(Outcome::Pass, 0.0)))
        .collect();
    rate(&checks).map(|r| r.grade)
}

#[test]
fn rating_meets_every_floor_at_its_edge() {
    for (failed, expected) in [
        (1, 'A'),
        (2, 'B'),
        (3, 'B'),
        (4, 'C'),
        (5, 'D'),
        (6, 'D'),
        (7, 'E'),
        (8, 'E'),
        (9, 'F'),
    ] {
        assert_eq!(
            grade(&vec![5.0; failed], 10 - failed),
            Some(expected),
            "{failed} warnings of 10"
        );
    }
    assert_eq!(
        grade(&[5.1], 9),
        Some('B'),
        "a cost just over 1 drops below the A floor"
    );
    assert_eq!(grade(&[6.6], 99), Some('B'), "an error caps the grade at B");
    assert_eq!(grade(&[6.5], 99), Some('A'), "a warning does not");
    assert_eq!(grade(&[], 3), Some('S'));
    assert_eq!(
        grade(&[9.9; 3], 0),
        Some('F'),
        "a cost above the total floors at zero"
    );
    assert_eq!((weight(5.0), weight(10.0)), (1.0, 4.0));
}

#[test]
fn rating_leaves_out_waivers_unknowns_and_skips() {
    let mut waived = judged(Outcome::Fail, 9.0);
    waived.waiver = Some(Waived {
        reason: "r".into(),
        until: "2026-12-31".into(),
        active: true,
    });
    assert_eq!(
        rate(&[
            waived.clone(),
            judged(Outcome::Unknown, 0.0),
            judged(Outcome::Skip, 0.0)
        ]),
        None,
        "nothing judged gives no grade"
    );
    assert_eq!(
        rate(&[waived, judged(Outcome::Pass, 0.0)]),
        Some(Rating {
            grade: 'S',
            score: 1.0
        })
    );
}

#[test]
fn colour_follows_the_flag_then_the_environment_then_the_terminal() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    };
    assert!(colour(Colour::Always, env(&[("NO_COLOR", "1")]), false));
    assert!(!colour(Colour::Never, env(&[("FORCE_COLOR", "1")]), true));
    assert!(colour(Colour::Auto, env(&[]), true) && !colour(Colour::Auto, env(&[]), false));
    assert!(!colour(Colour::Auto, env(&[("NO_COLOR", "1")]), true));
    assert!(!colour(
        Colour::Auto,
        env(&[("SYSTEMLINT_NO_COLOR", "1")]),
        true
    ));
    assert!(
        colour(Colour::Auto, env(&[("NO_COLOR", "")]), true),
        "an empty NO_COLOR is unset"
    );
    assert!(
        !colour(
            Colour::Auto,
            env(&[("NO_COLOR", "1"), ("FORCE_COLOR", "1")]),
            true
        ),
        "NO_COLOR wins"
    );
    assert!(colour(Colour::Auto, env(&[("FORCE_COLOR", "1")]), false));
    assert!(!colour(Colour::Auto, env(&[("FORCE_COLOR", "0")]), true));
    assert!(!colour(Colour::Auto, env(&[("TERM", "dumb")]), true));
}

fn shipped(ids: &[&str]) -> Vec<systemlint::judge::Rule> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/apt.yaml");
    let library = Library::new(BTreeMap::from([(
        "apt".to_owned(),
        systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
    )]))
    .unwrap();
    library
        .select(&ids.iter().map(|i| (*i).to_owned()).collect::<Vec<_>>())
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect()
}

fn sources() -> (Value, Vec<Check>) {
    let source = |overlaps: &[&str], stale: &[&str]| json!({"enabled": true, "overlaps": overlaps, "stale-suites": stale});
    let document = json!({"os": {"release": {"ID": "ubuntu"}}, "apt": {"sources": {"/a.list:1": source(&["/b.sources:1"], &["noble"]), "/b.sources:1": source(&["/a.list:1"], &[]), "/c.sources:1": source(&[], &["xenial"])}}});
    let checks = lint(
        &document,
        &shipped(&["apt/overlap", "apt/stale-suite"]),
        &[],
        "2026-11-11",
    );
    (document, checks)
}

#[test]
fn human_prints_one_block_per_rule_a_pair_once_and_the_worst_first() {
    let (document, checks) = sources();
    let text = lint_human(&document, &checks, 0, false, false, false);
    let expected = "Error (7.5): [apt/stale-suite] Source fetches an older release’s suite\n- /a.list:1: “noble”.\n- /c.sources:1: “xenial”.\nFix: set the suite to the host’s VERSION_CODENAME, or waive it when the vendor publishes no newer suite.\n\n\
        Warning (4.5): [apt/overlap] Repository partly listed in two places\n- /a.list:1.\n- /b.sources:1.\nFix: list each suite and component in one entry only, then run “sudo apt update”.\n\n\
        Rating            F\nErrors            2\nWarnings          2\nInfo              0\nPassed            2\n";
    assert_eq!(text, expected);
    let painted = lint_human(&document, &checks, 0, true, false, true);
    assert!(
        painted.contains("\x1b[31mError\x1b[0m (7.5): \x1b[1m[apt/stale-suite]\x1b[0m")
            && painted.contains("\x1b[33mWarning\x1b[0m"),
        "{painted}"
    );
    assert!(!painted.contains("Rating"), "quiet drops the summary");
}

#[test]
fn human_puts_a_fix_under_each_location_when_the_fixes_differ() {
    let rule = compile("x/drop", systemlint::yaml::from_str("title: Dropped value\nfact: v.*\nexpect: {const: 0}\nmessage: '{subject} holds {got}'\nfix: drop {got}\n").unwrap()).unwrap();
    let document = json!({"v": {"a": 1, "b": 2}});
    let text = lint_human(
        &document,
        &lint(&document, &[rule], &[], "2026-11-11"),
        0,
        true,
        false,
        false,
    );
    assert_eq!(
        text,
        "Warning (5.0): [x/drop] Dropped value\n- a: 1.\n  Fix: drop 1.\n- b: 2.\n  Fix: drop 2.\n\n"
    );
}

#[test]
fn human_prints_the_whole_message_of_a_subjectless_check_that_names_no_value() {
    let rule = compile("x/host", systemlint::yaml::from_str("title: Host lacks it\nfact: v\nexpect: {const: 0}\nmessage: Nothing provides it, so it never arrives\n").unwrap()).unwrap();
    let document = json!({"v": 1});
    let text = lint_human(
        &document,
        &lint(&document, &[rule], &[], "2026-11-11"),
        0,
        true,
        false,
        false,
    );
    assert_eq!(
        text,
        "Warning (5.0): [x/host] Host lacks it\n- Nothing provides it, so it never arrives.\n\n"
    );
}

#[test]
fn human_puts_each_remedy_command_under_its_location_unstopped_so_it_pastes_and_no_fix_repeats_it()
{
    let rule = compile(
        "x/mode",
        systemlint::yaml::from_str(
            "fact: files.*\nexpect: {const: 0}\nfix: clear it\nremedy: {chmod: o-w}\n",
        )
        .unwrap(),
    )
    .unwrap();
    let document = json!({"files": {"/etc/a": 1, "/etc/b b": 2, "/etc/c": 0}});
    let text = lint_human(
        &document,
        &lint(&document, &[rule], &[], "2026-11-11"),
        0,
        true,
        false,
        false,
    );
    assert_eq!(
        text,
        "Warning (5.0): [x/mode]\n- files./etc/a: 0 was expected.\n  Run: chmod o-w /etc/a\n- files./etc/b b: 0 was expected.\n  Run: chmod o-w '/etc/b b'\nOr run systemlint fix --tags x/mode to make every change.\n\n"
    );
}

const EXPLAINED: &str = "title: Dropped value\nfact: v\nexpect: {const: 0}\nfix: drop it\nrationale: a value [here] leaks\nreferences: [{title: 'CIS 1.2', url: 'https://example.org/cis'}, {title: 'Man page', url: 'https://example.org/man'}]\n";

#[test]
fn rationale_and_references_reach_every_format_and_the_human_references_only_under_verbose() {
    let rule = compile("x/drop", systemlint::yaml::from_str(EXPLAINED).unwrap()).unwrap();
    let document = json!({"v": 1});
    let checks = lint(&document, &[rule], &[], "2026-11-11");
    assert_eq!(
        lint_human(&document, &checks, 0, true, false, false),
        "Warning (5.0): [x/drop] Dropped value\nWhy: a value [here] leaks.\n- v: 0 was expected.\nFix: drop it.\n\n"
    );
    assert_eq!(
        lint_human(&document, &checks, 0, true, true, false),
        "Warning (5.0): [x/drop] Dropped value\nWhy: a value [here] leaks.\n- v: 0 was expected.\nFix: drop it.\nSee: CIS 1.2 <https://example.org/cis>\nSee: Man page <https://example.org/man>\n\n"
    );
    let report: Value = serde_json::from_str(&lint_json(&document, &checks)).unwrap();
    assert_eq!(
        (
            &report["checks"][0]["rationale"],
            &report["checks"][0]["references"][1]["url"]
        ),
        (
            &json!("a value [here] leaks"),
            &json!("https://example.org/man")
        )
    );
    let rule = &sarif(&document, &checks)["runs"][0]["tool"]["driver"]["rules"][0];
    assert_eq!(rule["shortDescription"]["text"], "Dropped value");
    assert_eq!(
        rule["helpUri"], "https://example.org/cis",
        "the first reference stands in for a missing docs link"
    );
    assert_eq!(
        rule["help"]["text"],
        "a value [here] leaks\nCIS 1.2: https://example.org/cis\nMan page: https://example.org/man"
    );
    assert_eq!(
        rule["help"]["markdown"],
        "a value [here] leaks\n\n- [CIS 1.2](https://example.org/cis)\n\n- [Man page](https://example.org/man)"
    );
    assert!(
        sarif(&document, &run(HTTPS, &facts("root"), &[]))["runs"][0]["tool"]["driver"]["rules"][0]
            .get("help")
            .is_none()
    );
}

#[test]
fn human_wraps_a_long_not_run_list_within_80_columns() {
    let mut document = facts("root");
    document["collectors"]["env-processes"] =
        json!({"status": "skipped", "reason": "needs root", "into": "env.processes"});
    let rules: Vec<_> = (0..12)
        .map(|i| {
            compile(
                &format!("env/rule-{i:02}"),
                systemlint::yaml::from_str("fact: env.*.*.vars\nexpect: {type: object}\n").unwrap(),
            )
            .unwrap()
        })
        .collect();
    let text = lint_human(
        &document,
        &lint(&document, &rules, &[], "2026-11-11"),
        0,
        true,
        false,
        false,
    );
    assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
    assert!(
        text.starts_with("Not run (env-processes): needs root\n  env/rule-00, ")
            && text.contains(",\n  env/rule-")
            && text.contains("env/rule-11\n\n"),
        "{text}"
    );
}

#[test]
fn plain_prints_a_rule_not_run_once_per_reason_whatever_its_subjects() {
    let mut document = facts("root");
    document["collectors"]["env-processes"] =
        json!({"status": "skipped", "reason": "needs root", "into": "env.processes"});
    document["collectors"]["env-defaults"] =
        json!({"status": "skipped", "reason": "needs root", "into": "env.defaults"});
    document["collectors"]["env-image"] =
        json!({"status": "skipped", "reason": "no image config", "into": "env.image"});
    document["env"] = json!({"files": {"/etc/environment": {"vars": {}}}});
    let rule = compile(
        "env/any",
        systemlint::yaml::from_str("fact: env.*.*.vars\nexpect: {type: object}\n").unwrap(),
    )
    .unwrap();
    let checks = lint(&document, &[rule], &[], "2026-11-11");
    assert!(
        checks.iter().filter(|c| c.collector.is_some()).count() >= 3,
        "{checks:?}"
    );
    let text = lint_plain(&document, &checks, true);
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("not-run\t"))
            .collect::<Vec<_>>(),
        [
            "not-run\t\tenv/any\t\tneeds root.\t",
            "not-run\t\tenv/any\t\tno image config.\t"
        ],
        "{text}"
    );
}

#[test]
fn plain_prints_one_tab_separated_line_per_finding() {
    let (document, checks) = sources();
    let text = lint_plain(&document, &checks, false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5, "{text}");
    assert_eq!(
        lines[2],
        "warning\t4.5\tapt/overlap\t/a.list:1\tlists some of the same suites and components as “/b.sources:1”.\tList each suite and component in one entry only, then run “sudo apt update”."
    );
    assert!(
        lines[0].starts_with("error\t7.5\tapt/stale-suite\t/a.list:1\t"),
        "{text}"
    );
    assert_eq!(
        lines[4],
        "rating\tF\t\t\tErrors 2, Warnings 2, Info 0, Passed 2\t"
    );
    assert!(
        lines
            .iter()
            .all(|l| l.split('\t').count() == 6 && !l.contains('\x1b')),
        "{text}"
    );
}

#[test]
fn machine_formats_carry_the_rating() {
    let document = facts("root");
    let checks = run(HTTPS, &document, &[]);
    let report: Value = serde_json::from_str(&lint_json(&document, &checks)).unwrap();
    assert_eq!(report["rating"], json!({"grade": "D", "score": 0.5}));
    assert_eq!(
        sarif(&document, &checks)["runs"][0]["properties"]["rating"]["grade"],
        "D"
    );
    assert!(
        lint_textfile(&document, &checks)
            .lines()
            .any(|l| l == "systemlint_rating{grade=\"D\"} 0.5")
    );
    assert!(
        !lint_textfile(&document, &[]).contains("systemlint_rating{"),
        "no grade, no sample"
    );
}

#[test]
fn a_subject_of_several_keys_shows_its_last_and_keeps_all_of_them_for_waivers() {
    let rule = compile("files/owner", systemlint::yaml::from_str("title: File not owned by root\nfact: files.*.*.uid\nexpect: {const: 0}\nmessage: '{subject} is owned by uid {got}'\n").unwrap()).unwrap();
    let document = json!({"files": {"path": {"/usr": {"uid": 1000}}}});
    let checks = lint(&document, std::slice::from_ref(&rule), &[], "2026-11-11");
    assert_eq!(
        (checks[0].subject_text(), checks[0].subject_label()),
        ("path, /usr".to_owned(), "/usr".to_owned())
    );
    assert_eq!(
        checks[0].message.as_deref(),
        Some("/usr is owned by uid 1000")
    );
    assert!(lint_human(&document, &checks, 0, true, false, false).contains("\n- /usr: 1000.\n"));
    assert!(
        lint_plain(&document, &checks, true)
            .contains("\tfiles/owner\t/usr\tis owned by uid 1000.\t")
    );
    for (glob, waived) in [
        ("path, /usr", true),
        ("/usr", true),
        ("/us", false),
        ("path", false),
    ] {
        let waiver = Waiver {
            rule: "files/owner".into(),
            subject: Some(glob.into()),
            reason: "r".into(),
            until: "2026-12-31".into(),
        };
        assert_eq!(
            !lint(
                &document,
                std::slice::from_ref(&rule),
                &[waiver],
                "2026-11-11"
            )[0]
            .is_failing(),
            waived,
            "waiver subject {glob:?}"
        );
    }
}

#[test]
fn plain_drops_only_a_whole_leading_subject_from_the_message() {
    let rule = |message: &str| {
        compile(
            "x/drop",
            systemlint::yaml::from_str(&format!(
                "fact: v.*\nexpect: {{const: 0}}\nmessage: '{message}'\n"
            ))
            .unwrap(),
        )
        .unwrap()
    };
    let document = json!({"v": {"a": 1}});
    let message = |m: &str| {
        lint_plain(
            &document,
            &lint(&document, &[rule(m)], &[], "2026-11-11"),
            true,
        )
        .split('\t')
        .nth(4)
        .unwrap()
        .to_owned()
    };
    assert_eq!(message("{subject} holds {got}"), "holds 1.");
    assert_eq!(
        message("{subject}b holds {got}"),
        "ab holds 1.",
        "a subject that only starts a word stays"
    );
    assert_eq!(
        message("value {subject} holds {got}"),
        "value a holds 1.",
        "a subject inside the sentence stays"
    );
    let fix = |f: &str| {
        lint_plain(
            &document,
            &lint(
                &document,
                &[compile(
                    "x/fix",
                    systemlint::yaml::from_str(&format!(
                        "fact: v.*\nexpect: {{const: 0}}\nfix: '{f}'\n"
                    ))
                    .unwrap(),
                )
                .unwrap()],
                &[],
                "2026-11-11",
            ),
            true,
        )
        .trim_end()
        .split('\t')
        .nth(5)
        .unwrap()
        .to_owned()
    };
    assert_eq!(
        (fix("évite {got}"), fix("drop it.")),
        ("Évite 1.".to_owned(), "Drop it.".to_owned()),
        "a fix opens with a capital and ends once"
    );
    assert_eq!(
        (
            fix("修正する"),
            fix("ぁ"),
            fix("ヿ"),
            fix("ठीक करें"),
            fix("ॿ"),
            fix("ऀ")
        ),
        (
            "修正する。".to_owned(),
            "ぁ。".to_owned(),
            "ヿ。".to_owned(),
            "ठीक करें।".to_owned(),
            "ॿ।".to_owned(),
            "ऀ।".to_owned()
        ),
        "a fix ends with its script’s full stop"
    );
    assert_eq!(
        (
            fix("x\u{3040}"),
            fix("\u{30a0}y"),
            fix("\u{08ff}"),
            fix("\u{0980}")
        ),
        (
            "X\u{3040}。".to_owned(),
            "\u{30a0}y.".to_owned(),
            "\u{08ff}.".to_owned(),
            "\u{0980}.".to_owned()
        ),
        "the script ranges end where Unicode ends them"
    );
    for ended in ["holds 1.", "holds 1?", "holds 1…", "holds 1。", "holds 1؟"] {
        assert_eq!(
            message(&format!("{{subject}} {ended}")),
            ended,
            "a message ended as a sentence keeps its own stop"
        );
    }
}

// Two standards’ rules on one fact that contradict each other, as `selectors` pick them.
fn contradicting(selectors: &[&str]) -> Vec<Check> {
    let yaml = "tags: [default]\nrules:\n  pw/rotate: {fact: pw.max, expect: {maximum: 365}, severity: error, tags: ['cis:5.4.1.1'], conflicts: [pw/keep]}\n  pw/keep: {fact: pw.max, expect: {minimum: 99999}, severity: error, tags: ['nist:5.1.1.2'], conflicts: [pw/rotate]}\n  pw/other: {fact: pw.max, expect: {const: 0}, severity: error}\n";
    let library = Library::new(BTreeMap::from([(
        "pw".to_owned(),
        systemlint::yaml::from_str(yaml).unwrap(),
    )]))
    .unwrap();
    let selectors: Vec<String> = selectors.iter().map(|s| (*s).to_owned()).collect();
    let rules: Vec<_> = library
        .select(&selectors)
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    lint(&json!({"pw": {"max": 99999}}), &rules, &[], "2026-11-15")
}

#[test]
fn two_selected_rules_in_conflict_print_one_block_and_fail_nothing() {
    let checks = contradicting(&[]);
    let outcome = |id: &str| checks.iter().find(|c| c.rule == id).map(|c| c.outcome);
    assert_eq!(
        (
            outcome("pw/rotate"),
            outcome("pw/keep"),
            outcome("pw/other")
        ),
        (
            Some(Outcome::Conflict),
            Some(Outcome::Conflict),
            Some(Outcome::Fail)
        )
    );
    let human = lint_human(&json!({}), &checks, 0, false, false, false);
    let line = "Conflict: pw/keep (nist:5.1.1.2) and pw/rotate (cis:5.4.1.1) contradict each other, so none of them counts; keep the standard you follow by leaving the other out with --tags '!pw/keep' or '!pw/rotate'.\n";
    assert_eq!(human.matches("Conflict:").count(), 1, "{human}");
    assert!(human.contains(line), "{human}");
    assert!(
        human.contains("Errors            1\n"),
        "only pw/other fails: {human}"
    );
    assert!(human.contains("Conflict          2\n"), "{human}");
    let conflicted: Vec<Check> = checks
        .iter()
        .filter(|c| c.rule != "pw/other")
        .cloned()
        .collect();
    assert!(
        !systemlint::report::FailOn::Level(systemlint::rules::Severity::Error).reached(&conflicted)
    );
    let json: Value = serde_json::from_str(&lint_json(&json!({}), &checks)).unwrap();
    assert_eq!(json["summary"]["conflict"], 2, "{json}");
    assert_eq!(
        lint_plain(&json!({}), &checks, true)
            .matches("conflict\t")
            .count(),
        2
    );
    assert!(
        lint_textfile(&json!({}), &checks).contains("systemlint_checks{outcome=\"conflict\"} 2")
    );
    assert_eq!(
        sarif(&json!({}), &checks)["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "review")
            .count(),
        2
    );
}

#[test]
fn leaving_one_side_out_judges_the_other_as_usual() {
    let checks = contradicting(&["!pw/keep"]);
    let outcome = |id: &str| checks.iter().find(|c| c.rule == id).map(|c| c.outcome);
    assert_eq!(
        (outcome("pw/rotate"), outcome("pw/keep")),
        (Some(Outcome::Fail), None)
    );
    let checks = contradicting(&["!pw/rotate"]);
    assert_eq!(
        checks
            .iter()
            .find(|c| c.rule == "pw/keep")
            .map(|c| c.outcome),
        Some(Outcome::Pass)
    );
}
