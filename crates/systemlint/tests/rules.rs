// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use systemlint::discovery::Trust;
use systemlint::judge::compile;
use systemlint::rules::{Library, Ruleset, Score, Severity, glob};

fn fixture() -> Ruleset {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/lint/rulesets/fixture.yaml");
    systemlint::yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn library(extra: &[(&str, &str)]) -> Library {
    let mut rulesets = BTreeMap::from([("fixture".to_owned(), fixture())]);
    for (name, yaml) in extra {
        rulesets.insert((*name).to_owned(), systemlint::yaml::from_str(yaml).unwrap());
    }
    Library::new(rulesets).unwrap()
}

fn ids(selected: &BTreeMap<String, systemlint::rules::Spec>) -> Vec<&str> {
    selected.keys().map(String::as_str).collect()
}

#[test]
fn glob_stars_cross_slashes_and_colons() {
    assert!(glob("apt/*", "apt/https"));
    assert!(glob("fixture-a:*", "fixture-a:3.1"));
    assert!(glob("*", "a/b:c"));
    assert!(glob("s?h/*", "ssh/patched"));
    assert!(!glob("apt/*", "os/supported"));
    assert!(!glob("fixture-a:*", "fixture-a"));
}

#[test]
fn selectors_union_rulesets_ids_and_tags_and_bang_removes() {
    let lib = library(&[]);
    assert_eq!(ids(&lib.select(&["apt".into(), "os/*".into()]).unwrap()), ["apt/https", "os/supported"]);
    assert_eq!(ids(&lib.select(&["fixture-a:*".into()]).unwrap()), ["apt/https", "os/supported"]);
    assert_eq!(ids(&lib.select(&["fixture".into(), "!experimental".into()]).unwrap()), ["apt/https", "os/supported", "shadow/private"]);
    assert_eq!(ids(&lib.select(&["*".into(), "!*".into()]).unwrap()), Vec::<&str>::new());
}

#[test]
fn a_name_no_ruleset_carries_is_a_rule_id_or_glob() {
    let lib = library(&[("mine", "extends: [ssh/patched]\n")]);
    assert_eq!(ids(&lib.resolve("ssh/patched").unwrap()), ["ssh/patched"]);
    assert_eq!(ids(&lib.resolve("mine").unwrap()), ["ssh/patched"]);
    assert!(lib.resolve("ssh/no-such-rule").unwrap_err().contains("no rule ID or tag matches it"));
    assert!(lib.select(&["!nothing".into()]).unwrap_err().contains("nothing"));
}

#[test]
fn ruleset_overrides_merge_expect_by_keyword_and_drop_the_old_message() {
    let lib = library(&[("strict", "extends: [fixture]\nrules:\n  os/supported: {expect: {enum: [\"26.04\"]}}\n  apt/https: error\n")]);
    let strict = lib.resolve("strict").unwrap();
    let os = &strict["os/supported"];
    assert_eq!(os.expect.as_ref().unwrap()["enum"], serde_json::json!(["26.04"]));
    assert_eq!(os.message, None, "a new expect drops the sentence stating the old bounds");
    assert_eq!(os.severity, Some(Severity::Error));
    assert_eq!((strict["apt/https"].severity, strict["apt/https"].pinned), (Some(Severity::Error), true));
}

#[test]
fn an_override_replaces_the_rationale_and_adds_references_once() {
    let lib = library(&[("t", "rules:\n  a/x: {fact: x, expect: {minLength: 3}, rationale: old, references: [{title: A, url: 'https://a.example'}]}\n"), ("p", "extends: [t]\nrules:\n  a/x: {rationale: new, references: [{title: A, url: 'https://a.example'}, {title: B, url: 'https://b.example'}]}\n")]);
    let x = &lib.resolve("p").unwrap()["a/x"];
    assert_eq!(x.rationale.as_deref(), Some("new"));
    assert_eq!(x.references.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(), ["A", "B"]);
    let bad = BTreeMap::from([("bad".to_owned(), systemlint::yaml::from_str::<Ruleset>("rules:\n  a/y: {fact: y, expect: {}, references: [{url: 'https://a.example'}]}\n").unwrap())]);
    assert!(Library::new(bad).unwrap_err().contains("missing field `title`"), "a reference needs a title");
}

#[test]
fn a_policy_overrides_a_rule_by_id_without_extending_and_selection_keeps_it() {
    let lib = library(&[("lenient", "rules:\n  os/supported: 4.2\n  shadow/private: off\n")]);
    let picked = lib.select(&["lenient".into(), "fixture-b:*".into()]).unwrap();
    assert_eq!(ids(&picked), ["os/supported"], "off drops shadow/private, the tag pick keeps the override");
    assert_eq!((picked["os/supported"].score.clone(), picked["os/supported"].severity), (Some(Score::Fixed(4.2)), None));
}

#[test]
fn excludes_and_overrides_by_id_or_glob() {
    let lib = library(&[("t", "rules:\n  a/x: {fact: x, expect: {minLength: 3}}\n  a/y: {fact: y, expect: {minLength: 3}}\n  b/z: {fact: z, expect: {minLength: 3}}\n"), ("p", "extends: [t]\nrules:\n  a/x: info\n  a/y: error\n")]);
    assert_eq!(ids(&lib.select(&["t".into(), "!a/*".into()]).unwrap()), ["b/z"]);
    assert_eq!(ids(&lib.select(&["t".into(), "!a/x".into()]).unwrap()), ["a/y", "b/z"]);
    assert_eq!(ids(&lib.select(&["!a/*".into()]).unwrap()), ["apt/https", "b/z", "os/supported", "shadow/private", "ssh/patched"], "only exclusions start from every rule");
    assert_eq!(ids(&lib.select(&["a/*".into(), "!a/x".into()]).unwrap()), ["a/y"], "an include keeps the base to what it picks");
    let p = lib.select(&["p".into()]).unwrap();
    assert_eq!([p["a/x"].severity, p["a/y"].severity, p["b/z"].severity], [Some(Severity::Info), Some(Severity::Error), None]);
}

#[test]
fn a_rule_defined_twice_an_unknown_override_and_a_cycle_are_refused() {
    let twice = BTreeMap::from([("fixture".to_owned(), fixture()), ("copy".to_owned(), fixture())]);
    assert!(Library::new(twice).unwrap_err().contains("already defined in ruleset"));
    let lib = library(&[("ghost", "rules:\n  no/such: error\n"), ("a", "extends: [b]\n"), ("b", "extends: [a]\n")]);
    assert!(lib.resolve("ghost").unwrap_err().contains("overrides a rule no ruleset defines"));
    assert!(lib.resolve("a").unwrap_err().contains("extends itself through a → b"));
    let rulesets = BTreeMap::from([("bad".to_owned(), systemlint::yaml::from_str::<Ruleset>("rules:\n  x/y: {fact: x}\n").unwrap())]);
    assert!(Library::new(rulesets).unwrap_err().contains("has fact but no expect"));
}

#[test]
fn load_reads_trusted_files_by_stem_and_refuses_a_clash_with_the_config() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rules-load");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fixture.yaml"), std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/lint/rulesets/fixture.yaml")).unwrap()).unwrap();
    std::fs::set_permissions(dir.join("fixture.yaml"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let trust = Trust { uids: vec![rustix::process::getuid().as_raw()], top: dir.clone() };
    let (lib, refusals) = Library::load(std::slice::from_ref(&dir), &trust, &BTreeMap::new());
    assert!(refusals.is_empty(), "{refusals:?}");
    assert_eq!(lib.unwrap().definitions.len(), 4);
    let inline = BTreeMap::from([("fixture".to_owned(), Ruleset::default())]);
    assert!(Library::load(&[dir], &trust, &inline).0.unwrap_err().contains("in the config is also a file"));
}

#[test]
fn a_ruleset_when_guards_the_rules_it_defines_and_every_ruleset_that_brings_them() {
    let library = library(&[("debian", "when: {os.release.ID: debian}\nrules:\n  deb/one: {fact: a, expect: {}}\n"), ("strict", "extends: [debian]\nwhen: {os.release.VERSION_ID: '13'}\nrules:\n  deb/one: error\n")]);
    let names = |selectors: &[&str]| library.select(&selectors.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap()["deb/one"].applies.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    assert_eq!(names(&["strict"]), ["debian", "strict"], "an extending ruleset adds its own when to the parent’s");
    assert_eq!(names(&["deb/one"]), ["debian"], "a pick by ID keeps the defining ruleset’s when");
    assert!(library.select(&["os/supported".to_owned()]).unwrap()["os/supported"].applies.is_empty(), "a ruleset without when guards nothing");
}

#[test]
fn a_manual_rule_is_defined_without_fact_and_refuses_one() {
    let library = library(&[("review", "rules:\n  review/backups: {manual: true, title: Review the backup policy, rationale: read the policy}\n"), ("stricter", "rules:\n  review/backups: error\n")]);
    let spec = &library.select(&["stricter".to_owned()]).unwrap()["review/backups"];
    assert!(spec.manual && spec.severity == Some(Severity::Error), "an override keeps the rule manual: {spec:?}");
    for (yaml, why) in [("rules:\n  m: {manual: true, fact: a}\n", "fact"), ("rules:\n  m: {manual: true, expect: {}}\n", "expect"), ("rules:\n  m: {manual: true, facts: {any: []}}\n", "facts")] {
        let error = Library::new(BTreeMap::from([("bad".to_owned(), systemlint::yaml::from_str(yaml).unwrap())])).unwrap_err();
        assert!(error.contains("is manual, so it takes no fact, expect or facts"), "{why}: {error}");
    }
}

#[test]
fn facts_refuse_a_fact_or_an_expect_beside_them_an_overriding_one_included() {
    let defined = "rules:\n  x/one: {facts: {any: [{fact: a, expect: {const: 1}}, {fact: b, expect: {const: 2}}]}}\n";
    let over = library(&[("base", defined), ("over", "extends: [base]\nrules:\n  x/one: {expect: {const: 3}}\n"), ("both", "rules:\n  x/two: {fact: a, facts: {all: [{fact: a, expect: {}}]}}\n")]);
    assert!(compile("x/one", over.select(&["base".to_owned()]).unwrap().remove("x/one").unwrap()).is_ok());
    for (selector, id) in [("over", "x/one"), ("both", "x/two")] {
        let error = compile(id, over.select(&[selector.to_owned()]).unwrap().remove(id).unwrap()).err().unwrap_or_default();
        assert!(error.contains("has facts, so it takes no fact or expect of its own"), "{selector}: {error}");
    }
}
