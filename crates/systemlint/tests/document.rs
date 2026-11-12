// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use systemlint::document::{load, parse, render, save};

fn dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("document").join(name);
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
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{name}");
        assert_eq!(load(&path).unwrap(), sample(), "{name}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim_start().starts_with('{'), name.ends_with(".json"), "{text}");
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "no temporary file is left behind");
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
    assert!(save(&sample(), &path).unwrap_err().contains("absent/facts.yaml"));
}

#[test]
fn yaml_keeps_strings_that_look_like_other_types() {
    let text = render(&sample(), false).unwrap();
    assert_eq!(parse(&text).unwrap()["apt"]["enabled"], "no");
    assert_eq!(parse(&text).unwrap()["apt"]["version"], "26.04");
}

#[test]
fn parse_refuses_another_schema_or_none() {
    assert!(parse("meta: {schema: 2}").unwrap_err().contains("schema 2, this systemlint reads schema 1"));
    assert!(parse("meta: {schema: 0}").unwrap_err().contains("schema 0"));
    assert_eq!(parse("os: {}").unwrap_err(), "no meta.schema");
    assert!(load(Path::new("/nonexistent/facts.yaml")).unwrap_err().contains("/nonexistent/facts.yaml"));
}

#[test]
fn hand_written_yaml_keeps_yaml_1_1_booleans_as_strings() {
    let document = parse("meta: {schema: 1}\napt: {enabled: no, legacy: off, short: y, real: true}\n").unwrap();
    assert_eq!(document["apt"], json!({"enabled": "no", "legacy": "off", "short": "y", "real": true}));
}
