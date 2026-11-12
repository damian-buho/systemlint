// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use systemlint::comply::{self, Catalog, Report, Verdict, comply, overall};
use systemlint::discovery::Trust;
use systemlint::judge::{Check, Rule, compile, lint};
use systemlint::report::{FailOn, lint_human, lint_json, lint_plain, lint_sarif, lint_textfile};
use systemlint::rules::{Library, Ruleset};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/lint")
}

fn facts(name: &str) -> Value {
    systemlint::document::load(&fixtures().join(format!("facts/{name}.yaml"))).unwrap()
}

fn library(extra: &[(&str, &str)]) -> Library {
    let mut rulesets = BTreeMap::from([("fixture".to_owned(), systemlint::yaml::from_str(&std::fs::read_to_string(fixtures().join("rulesets/fixture.yaml")).unwrap()).unwrap())]);
    rulesets.extend(extra.iter().map(|(name, text)| ((*name).to_owned(), systemlint::yaml::from_str::<Ruleset>(text).unwrap())));
    Library::new(rulesets).unwrap()
}

fn rules(base: &[&str], standards: &[&str], extra: &[(&str, &str)]) -> Vec<Rule> {
    let (base, standards): (Vec<String>, Vec<String>) = (base.iter().map(|s| (*s).to_owned()).collect(), standards.iter().map(|s| (*s).to_owned()).collect());
    library(extra).select_for(&base, &standards).unwrap().into_iter().map(|(id, spec)| compile(&id, spec).unwrap()).collect()
}

fn ids(rules: &[Rule]) -> Vec<&str> {
    rules.iter().map(|r| r.id.as_str()).collect()
}

fn catalog(standard: &str) -> Catalog {
    systemlint::yaml::from_str(&std::fs::read_to_string(fixtures().join(format!("standards/{standard}.yaml"))).unwrap()).unwrap()
}

fn run(standard: &str, document: &Value, catalog: Option<&Catalog>) -> (Vec<Check>, Report) {
    let rules = rules(&[], &[standard], &[]);
    let checks = lint(document, &rules, &[], "2026-11-11");
    let report = comply(standard, &rules, &checks, catalog);
    (checks, report)
}

fn answer(standard: &str, document: &Value, catalog: Option<&Catalog>) -> Report {
    run(standard, document, catalog).1
}

fn verdicts(report: &Report) -> Vec<(&str, Verdict)> {
    report.controls.iter().map(|c| (c.id.as_str(), c.verdict)).collect()
}

fn http_source() -> Value {
    let mut document = facts("root");
    document["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    document
}

#[test]
fn a_standard_adds_its_tagged_rules_to_the_selectors() {
    assert_eq!(ids(&rules(&[], &["fixture-a"], &[])), ["apt/https", "os/supported"]);
    assert_eq!(ids(&rules(&["files"], &["fixture-a"], &[])), ["apt/https", "os/supported", "shadow/private"]);
    assert_eq!(ids(&rules(&[], &["fixture-a", "fixture-b"], &[])), ["apt/https", "os/supported", "shadow/private"]);
    assert_eq!(ids(&rules(&["!apt"], &["fixture-a"], &[])), ["os/supported"]);
    assert_eq!(rules(&[], &[], &[]).len(), 4, "no standard and no selector is every rule");
}

#[test]
fn a_standard_no_rule_carries_selects_nothing_and_is_indeterminate() {
    assert!(rules(&[], &["nothing"], &[]).is_empty());
    assert!(rules(&["!experimental"], &["nothing"], &[]).is_empty(), "only exclusions never widen to every rule");
    assert_eq!(ids(&rules(&["os"], &["nothing"], &[])), ["os/supported"]);
    let report = comply("nothing", &[], &[], None);
    assert_eq!((report.verdict, report.verdict.code()), (Verdict::Indeterminate, 3));
    assert!(report.note.as_deref().unwrap().contains("no rule is tagged nothing:*"));
}

#[test]
fn an_unprivileged_run_is_indeterminate_never_compliant() {
    let root = answer("fixture-b", &facts("root"), None);
    assert_eq!((root.verdict, root.verdict.code()), (Verdict::Compliant, 0));
    let unprivileged = answer("fixture-b", &facts("unprivileged"), None);
    assert_eq!((unprivileged.verdict, unprivileged.verdict.code()), (Verdict::Indeterminate, 3));
    assert_eq!(verdicts(&unprivileged), [("B-7", Verdict::Compliant), ("B-9", Verdict::Indeterminate)]);
    assert!(unprivileged.controls[1].reasons[0].contains("Permission denied"), "{:?}", unprivileged.controls[1].reasons);
}

#[test]
fn a_hint_failure_fails_its_control_whatever_fail_on_says() {
    let rules = rules(&["hinted"], &["fixture-a"], &[("hinted", "extends: [fixture]\nrules: {apt/https: hint}\n")]);
    let document = http_source();
    let checks = lint(&document, &rules, &[], "2026-11-11");
    assert!(!"info".parse::<FailOn>().unwrap().reached(&checks), "a hint never reaches --fail-on");
    let report = comply("fixture-a", &rules, &checks, None);
    assert_eq!(verdicts(&report), [("1.1", Verdict::Compliant), ("3.1", Verdict::NonCompliant)]);
    assert_eq!((report.verdict, report.verdict.code()), (Verdict::NonCompliant, 1));
}

#[test]
fn one_rule_tagged_for_two_standards_answers_each_independently() {
    let document = http_source();
    let a = answer("fixture-a", &document, None);
    let b = answer("fixture-b", &document, None);
    assert_eq!((a.verdict, b.verdict), (Verdict::NonCompliant, Verdict::Compliant));
    assert_eq!(verdicts(&a), [("1.1", Verdict::Compliant), ("3.1", Verdict::NonCompliant)]);
    assert_eq!(verdicts(&b), [("B-7", Verdict::Compliant), ("B-9", Verdict::Compliant)]);
    assert!(a.controls[0].rules == b.controls[0].rules && a.controls[0].rules == ["os/supported"]);
}

#[test]
fn several_standards_answer_the_worst_verdict() {
    let (compliant, failing) = (answer("fixture-b", &http_source(), None), answer("fixture-a", &http_source(), None));
    let unknown = answer("fixture-b", &facts("unprivileged"), None);
    assert_eq!(overall(&[]), Verdict::Indeterminate);
    assert_eq!(overall(std::slice::from_ref(&compliant)), Verdict::Compliant);
    assert_eq!(overall(&[compliant.clone(), unknown.clone()]), Verdict::Indeterminate);
    assert_eq!(overall(&[unknown, failing, compliant]), Verdict::NonCompliant);
    assert_eq!(Verdict::Manual.code(), 3);
}

#[test]
fn without_a_catalog_compliant_only_means_no_tagged_rule_failed() {
    let (checks, report) = run("fixture-b", &facts("root"), None);
    assert!(report.note.as_deref().unwrap().contains("compliant only means no rule tagged fixture-b:* failed"));
    assert!(report.coverage.is_none());
    let text = lint_human(&facts("root"), &checks, &[report], false, false);
    assert!(text.contains("Note: there is no catalog of fixture-b"), "{text}");
}

#[test]
fn a_catalog_with_an_uncovered_control_is_indeterminate() {
    let catalog = catalog("fixture-a");
    let report = answer("fixture-a", &facts("root"), Some(&catalog));
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(verdicts(&report), [("1.1", Verdict::Compliant), ("3.1", Verdict::Compliant), ("4.2", Verdict::Manual), ("9.9", Verdict::Indeterminate)]);
    assert_eq!((report.coverage.as_ref().unwrap().covered, report.coverage.as_ref().unwrap().total), (2, 4));
    assert_eq!(report.name, "Fixture Benchmark A");
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
fn the_human_report_closes_with_a_standard_section_before_the_rating() {
    let document = http_source();
    let (checks, report) = run("fixture-a", &document, Some(&catalog("fixture-a")));
    let text = lint_human(&document, &checks, std::slice::from_ref(&report), false, false);
    let section = "Standard: non-compliant [fixture-a] Fixture Benchmark A\n- 1.1  compliant      Run a supported release\n- 3.1  non-compliant  Fetch packages over TLS\n       apt/https /etc/apt/sources.list.d/old.sources: /etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”\n- 4.2  manual         Review the backup policy\n- 9.9  indeterminate  A control no rule covers yet\n       no rule covers it\nCoverage: 2 of 4 controls\n\nRating";
    assert!(text.contains(section), "{text}");
    assert!(text.find("Warning (5.0): [apt/https]").unwrap() < text.find("Standard:").unwrap(), "{text}");
    assert!(lint_human(&document, &checks, &[report], false, true).contains("Standard: \x1b[31mnon-compliant\x1b[0m"));
}

#[test]
fn machine_formats_carry_each_standard() {
    let document = http_source();
    let (checks, report) = run("fixture-a", &document, Some(&catalog("fixture-a")));
    let compliance = [report];
    let json: Value = serde_json::from_str(&lint_json(&document, &checks, &compliance)).unwrap();
    assert_eq!((json["compliance"]["fixture-a"]["verdict"].as_str(), json["compliance"]["fixture-a"]["coverage"]["covered"].as_u64()), (Some("non-compliant"), Some(2)));
    assert!(serde_json::from_str::<Value>(&lint_json(&document, &checks, &[])).unwrap().get("compliance").is_none());
    let sarif: Value = serde_json::from_str(&lint_sarif(&document, &checks, &compliance)).unwrap();
    let run = &sarif["runs"][0];
    assert_eq!((run["taxonomies"][0]["name"].as_str(), run["taxonomies"][0]["taxa"].as_array().unwrap().len()), (Some("fixture-a"), 4));
    assert_eq!(run["properties"]["compliance"]["fixture-a"], "non-compliant");
    let https = run["tool"]["driver"]["rules"].as_array().unwrap().iter().find(|r| r["id"] == "apt/https").unwrap();
    assert_eq!(https["relationships"], json!([{"target": {"id": "3.1", "toolComponent": {"name": "fixture-a", "index": 0}}, "kinds": ["relevant"]}]));
    let text = lint_textfile(&document, &checks, &compliance);
    for line in ["systemlint_controls{standard=\"fixture-a\",verdict=\"manual\"} 1", "systemlint_controls{standard=\"fixture-a\",verdict=\"compliant\"} 1", "systemlint_compliance{standard=\"fixture-a\",verdict=\"non-compliant\"} 1", "systemlint_compliance{standard=\"fixture-a\",verdict=\"compliant\"} 0"] {
        assert!(text.lines().any(|l| l == line), "{line} missing from {text}");
    }
    assert!(!lint_textfile(&document, &checks, &[]).contains("systemlint_compliance"));
}

#[test]
fn the_plain_report_carries_each_standard_before_the_rating() {
    let document = http_source();
    let (checks, report) = run("fixture-a", &document, Some(&catalog("fixture-a")));
    let text = lint_plain(&document, &checks, std::slice::from_ref(&report), false);
    let rows = "standard\tnon-compliant\tfixture-a\t\t2 of 4\tFixture Benchmark A\ncontrol\tcompliant\tfixture-a\t1.1\t\tRun a supported release\ncontrol\tnon-compliant\tfixture-a\t3.1\tapt/https /etc/apt/sources.list.d/old.sources: /etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”\tFetch packages over TLS\ncontrol\tmanual\tfixture-a\t4.2\t\tReview the backup policy\ncontrol\tindeterminate\tfixture-a\t9.9\tno rule covers it\tA control no rule covers yet\nrating\t";
    assert!(text.contains(rows), "{text}");
    assert!(text.find("\tapt/https\t").unwrap() < text.find("standard\t").unwrap(), "{text}");
    assert!(!lint_plain(&document, &checks, &[], false).contains("standard\t"));
}

fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&base);
    for (path, from) in files {
        let path = base.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(path.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&path, std::fs::read_to_string(fixtures().join(from)).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    base
}

fn trust(top: &Path) -> Trust {
    Trust { uids: vec![rustix::process::getuid().as_raw()], top: top.to_owned() }
}

#[test]
fn a_catalog_is_found_in_a_rules_directory_or_its_standards_sibling() {
    let base = tree("comply-sibling", &[("rules/fixture.yaml", "rulesets/fixture.yaml"), ("standards/fixture-a.yaml", "standards/fixture-a.yaml")]);
    let dirs = comply::directories(&[base.join("rules")]);
    assert_eq!(dirs, [base.join("rules"), base.join("standards")]);
    let (found, refusals) = comply::catalog(&dirs, &trust(&base), "fixture-a");
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(found.unwrap().unwrap().controls.len(), 4);
    assert!(comply::catalog(&dirs, &trust(&base), "fixture-b").0.unwrap().is_none());
}

#[test]
fn a_catalog_beside_rulesets_is_no_ruleset_and_a_ruleset_is_no_catalog() {
    let base = tree("comply-beside", &[("rules/fixture.yaml", "rulesets/fixture.yaml"), ("rules/fixture-a.yaml", "standards/fixture-a.yaml"), ("standards/fixture.yaml", "rulesets/fixture.yaml")]);
    let rules = [base.join("rules")];
    let (library, refusals) = Library::load(&rules, &trust(&base), &BTreeMap::new());
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(library.unwrap().rulesets.keys().collect::<Vec<_>>(), ["fixture"]);
    assert_eq!(comply::catalog(&comply::directories(&rules), &trust(&base), "fixture-a").0.unwrap().unwrap().name.as_deref(), Some("Fixture Benchmark A"));
    assert!(comply::catalog(&comply::directories(&rules), &trust(&base), "fixture").0.unwrap().is_none());
}
