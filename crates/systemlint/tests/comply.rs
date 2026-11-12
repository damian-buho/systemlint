// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::comply::{Catalog, Report, Verdict, comply};
use systemlint::judge::{Rule, compile, lint};
use systemlint::report::{FailOn, comply_human, lint_human};
use systemlint::rules::Library;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/lint")
}

fn facts(name: &str) -> Value {
    systemlint::document::load(&fixtures().join(format!("facts/{name}.yaml"))).unwrap()
}

fn rules(standard: &str) -> Vec<Rule> {
    let ruleset = systemlint::yaml::from_str(&std::fs::read_to_string(fixtures().join("rulesets/fixture.yaml")).unwrap()).unwrap();
    let library = Library::new(BTreeMap::from([("fixture".to_owned(), ruleset)])).unwrap();
    library.select(&[format!("{standard}:*")]).unwrap().into_iter().map(|(id, spec)| compile(&id, spec).unwrap()).collect()
}

fn catalog(standard: &str) -> Catalog {
    systemlint::yaml::from_str(&std::fs::read_to_string(fixtures().join(format!("standards/{standard}.yaml"))).unwrap()).unwrap()
}

fn answer(standard: &str, document: &Value, catalog: Option<&Catalog>) -> Report {
    let rules = rules(standard);
    comply(standard, &rules, &lint(document, &rules, &[], "2026-11-11"), catalog)
}

fn verdicts(report: &Report) -> Vec<(&str, Verdict)> {
    report.controls.iter().map(|c| (c.id.as_str(), c.verdict)).collect()
}

#[test]
fn an_unprivileged_run_is_indeterminate_never_compliant() {
    let root = answer("fixture-b", &facts("root"), None);
    assert_eq!(root.verdict, Verdict::Compliant);
    let unprivileged = answer("fixture-b", &facts("unprivileged"), None);
    assert_eq!(unprivileged.verdict, Verdict::Indeterminate);
    assert_eq!(verdicts(&unprivileged), [("B-7", Verdict::Compliant), ("B-9", Verdict::Indeterminate)]);
    assert!(unprivileged.controls[1].reasons[0].contains("Permission denied"), "{:?}", unprivileged.controls[1].reasons);
}

#[test]
fn one_rule_tagged_for_two_standards_answers_each_independently() {
    let mut document = facts("root");
    document["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    let a = answer("fixture-a", &document, None);
    let b = answer("fixture-b", &document, None);
    assert_eq!((a.verdict, b.verdict), (Verdict::NonCompliant, Verdict::Compliant));
    assert_eq!(verdicts(&a), [("1.1", Verdict::Compliant), ("3.1", Verdict::NonCompliant)]);
    assert_eq!(verdicts(&b), [("B-7", Verdict::Compliant), ("B-9", Verdict::Compliant)]);
    assert!(a.controls[0].rules == b.controls[0].rules && a.controls[0].rules == ["os/supported"]);
}

#[test]
fn without_a_catalog_compliant_only_means_no_tagged_rule_failed() {
    let report = answer("fixture-b", &facts("root"), None);
    assert!(report.note.as_deref().unwrap().contains("compliant only means no rule tagged fixture-b:* failed"));
    assert!(report.coverage.is_none());
    assert!(comply_human(&report).contains("note: there is no catalog of fixture-b"));
}

#[test]
fn a_catalog_with_an_uncovered_control_is_indeterminate() {
    let catalog = catalog("fixture-a");
    let report = answer("fixture-a", &facts("root"), Some(&catalog));
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(verdicts(&report), [("1.1", Verdict::Compliant), ("3.1", Verdict::Compliant), ("4.2", Verdict::Manual), ("9.9", Verdict::Indeterminate)]);
    assert_eq!((report.coverage.as_ref().unwrap().covered, report.coverage.as_ref().unwrap().total), (2, 4));
    assert_eq!(report.name, "Fixture Benchmark A");
    let table = comply_human(&report);
    assert!(table.starts_with("Fixture Benchmark A: indeterminate\n") && table.contains("no rule covers it") && table.contains("coverage: 2 of 4 controls"), "{table}");
}

#[test]
fn a_failure_beats_an_uncovered_control() {
    let mut document = facts("root");
    document["os"]["release"]["VERSION_ID"] = json!("25.10");
    let report = answer("fixture-a", &document, Some(&catalog("fixture-a")));
    assert_eq!(report.verdict, Verdict::NonCompliant);
    assert!(report.controls[0].reasons[0].contains("release “25.10” is not supported"), "{:?}", report.controls[0].reasons);
}

#[test]
fn no_tagged_rule_and_no_catalog_is_indeterminate() {
    let report = comply("nothing", &[], &[], None);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert!(report.note.as_deref().unwrap().contains("no rule is tagged nothing:*"));
}

#[test]
fn fail_on_counts_unwaived_failures_at_its_level_or_score() {
    let mut document = facts("root");
    document["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    let rules = rules("fixture-a");
    let checks = lint(&document, &rules, &[], "2026-11-11");
    assert!(!"error".parse::<FailOn>().unwrap().reached(&checks), "the http source is a warning");
    assert!("warning".parse::<FailOn>().unwrap().reached(&checks));
    assert!("5".parse::<FailOn>().unwrap().reached(&checks) && !"5.1".parse::<FailOn>().unwrap().reached(&checks));
    assert!(!FailOn::Never.reached(&checks));
    assert!("0".parse::<FailOn>().is_err() && "10".parse::<FailOn>().is_err() && "0.1".parse::<FailOn>().is_ok() && "9.9".parse::<FailOn>().is_ok());
    let text = lint_human(&checks, false);
    assert!(text.contains("warning apt/https /etc/apt/sources.list.d/old.sources: /etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”"), "{text}");
    assert!(text.ends_with("3 checks: 2 pass, 1 fail, 0 waived, 0 unknown, 0 skip\n"), "{text}");
}
