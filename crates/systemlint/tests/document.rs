// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use systemlint::document::{expire, load, parse, render, save};
use systemlint::judge::{Outcome, compile, lint};

fn dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("document")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample() -> serde_json::Value {
    json!({"meta": {"schema": 1, "collected-at": "2026-11-11T12:00:00Z"}, "collectors": {"apt": {"status": "ok"}}, "apt": {"enabled": "no", "version": "26.04"}})
}

#[test]
fn save_picks_the_format_by_extension_and_round_trips() {
    let dir = dir("roundtrip");
    for name in ["facts.json", "facts.yaml"] {
        let path = dir.join(name);
        save(&sample(), &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{name}"
        );
        assert_eq!(load(&path).unwrap(), sample(), "{name}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.trim_start().starts_with('{'),
            name.ends_with(".json"),
            "{text}"
        );
    }
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        2,
        "no temporary file is left behind"
    );
}

#[test]
fn save_replaces_an_existing_document() {
    let path = dir("replace").join("facts.yaml");
    std::fs::write(&path, "old").unwrap();
    save(&sample(), &path).unwrap();
    assert_eq!(load(&path).unwrap(), sample());
}

#[test]
fn save_into_a_missing_directory_names_the_path() {
    let path = dir("missing").join("absent/facts.yaml");
    let error = save(&sample(), &path).unwrap_err();
    assert!(
        error.contains(&format!(
            "Can’t write facts.yaml into {}: it does not exist.",
            path.parent().unwrap().display()
        )),
        "{error}"
    );
}

#[test]
fn yaml_keeps_strings_that_look_like_other_types() {
    let text = render(&sample(), false).unwrap();
    assert_eq!(parse(&text).unwrap()["apt"]["enabled"], "no");
    assert_eq!(parse(&text).unwrap()["apt"]["version"], "26.04");
}

#[test]
fn parse_refuses_another_schema_or_none() {
    assert!(
        parse("meta: {schema: 2}")
            .unwrap_err()
            .contains("schema 2, this systemlint reads schema 1")
    );
    assert!(parse("meta: {schema: 0}").unwrap_err().contains("schema 0"));
    assert_eq!(parse("os: {}").unwrap_err(), "no meta.schema");
    assert!(
        load(Path::new("/nonexistent/facts.yaml"))
            .unwrap_err()
            .contains("/nonexistent/facts.yaml")
    );
}

#[test]
fn hand_written_yaml_keeps_yaml_1_1_booleans_as_strings() {
    let document =
        parse("meta: {schema: 1}\napt: {enabled: no, legacy: off, short: y, real: true}\n")
            .unwrap();
    assert_eq!(
        document["apt"],
        json!({"enabled": "no", "legacy": "off", "short": "y", "real": true})
    );
}

// 2026-11-15T10:00:00Z, the instant every ttl document below was collected.
const COLLECTED: i64 = 1_794_736_800;

// A document whose `clock` collector declares `ttl` seconds and whose `files` collector declares none.
fn aged(ttl: u64) -> serde_json::Value {
    json!({
        "meta": {"collected-at": "2026-11-15T10:00:00Z"},
        "clock": {"skew": 0},
        "files": {"etc": {"mode": "0644"}},
        "collectors": {
            "clock": {"status": "ok", "into": "clock", "ttl": ttl},
            "files-etc": {"status": "ok", "into": "files.etc"},
        },
    })
}

#[test]
fn facts_exactly_ttl_old_are_judged_and_one_second_older_are_dropped() {
    let mut fresh = aged(60);
    expire(&mut fresh, COLLECTED + 60);
    assert_eq!(fresh, aged(60));
    let mut stale = aged(60);
    expire(&mut stale, COLLECTED + 61);
    assert!(stale.get("clock").is_none(), "{stale}");
    assert_eq!(stale["collectors"]["clock"]["status"], "skipped");
    assert_eq!(stale["collectors"]["clock"]["expired"], true);
    assert_eq!(
        stale["collectors"]["clock"]["reason"],
        "facts from collector clock are 61 s old, past their ttl of 60 s: collect again"
    );
    assert_eq!(stale["files"], aged(60)["files"], "no ttl means forever");
}

#[test]
fn a_ttl_of_zero_holds_only_at_the_collecting_instant() {
    let mut now = aged(0);
    expire(&mut now, COLLECTED);
    assert_eq!(now, aged(0));
    let mut later = aged(0);
    expire(&mut later, COLLECTED + 3 * 3600);
    assert_eq!(
        later["collectors"]["clock"]["reason"],
        "facts from collector clock are 3 h old, past their ttl of 0 s: collect again"
    );
}

#[test]
fn a_ttl_expires_facts_from_the_future_or_without_a_collection_time() {
    let mut future = aged(3600);
    expire(&mut future, COLLECTED - 1);
    assert!(
        future["collectors"]["clock"]["reason"]
            .as_str()
            .unwrap()
            .contains("after this run’s clock"),
        "{future}"
    );
    let mut undated = aged(3600);
    undated["meta"]["collected-at"] = json!("yesterday");
    expire(&mut undated, COLLECTED);
    assert!(
        undated["collectors"]["clock"]["reason"]
            .as_str()
            .unwrap()
            .contains("no valid meta.collected-at (yesterday)"),
        "{undated}"
    );
    assert_eq!(undated["files"], aged(3600)["files"]);
}

#[test]
fn an_expired_collector_leaves_its_rules_not_run_and_others_judged() {
    let rules = [
        compile(
            "clock/skew",
            systemlint::yaml::from_str("fact: clock.skew\nexpect: {const: 0}\n").unwrap(),
        )
        .unwrap(),
        compile(
            "files/mode",
            systemlint::yaml::from_str("fact: files.etc.mode\nexpect: {const: '0644'}\n").unwrap(),
        )
        .unwrap(),
    ];
    let mut document = aged(0);
    expire(&mut document, COLLECTED + 1);
    let checks = lint(&document, &rules, &[], "2026-11-15");
    let outcome = |id: &str| {
        checks
            .iter()
            .find(|c| c.rule == id)
            .map(|c| (c.outcome, c.collector.clone()))
    };
    assert_eq!(
        outcome("clock/skew"),
        Some((Outcome::Unknown, Some("clock".to_owned())))
    );
    assert_eq!(outcome("files/mode").map(|o| o.0), Some(Outcome::Pass));
}
