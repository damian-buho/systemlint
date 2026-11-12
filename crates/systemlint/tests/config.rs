// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use systemlint::config::Config;

fn write(name: &str, text: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("config").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn relative_directories_resolve_beside_the_file() {
    let path = write("relative", "plugins:\n  directories: [plugins, /opt/systemlint/plugins]\ncollect:\n  directories: [collectors]\n");
    let config = Config::load(&path).unwrap();
    assert_eq!(config.plugins.directories, [path.parent().unwrap().join("plugins"), PathBuf::from("/opt/systemlint/plugins")]);
    assert_eq!(config.collect.directories, [path.parent().unwrap().join("collectors")]);
}

#[test]
fn empty_file_is_the_default() {
    let config = Config::load(&write("empty", "{}\n")).unwrap();
    assert!(config.plugins.directories.is_empty());
}

#[test]
fn unknown_key_is_refused() {
    let error = Config::load(&write("unknown", "plugin:\n  directories: []\n")).unwrap_err();
    assert!(error.contains("not a valid configuration"), "{error}");
}

#[test]
fn missing_file_names_the_path() {
    let error = Config::load(Path::new("/nonexistent/systemlint.yaml")).unwrap_err();
    assert!(error.contains("/nonexistent/systemlint.yaml"), "{error}");
}

#[test]
fn lint_and_comply_sections_resolve_directories_and_read_waivers() {
    let path = write("lint", "lint:\n  directories: [rules]\n  tags: [fixture, '!experimental']\n  fail-on: warning\n  rulesets:\n    strict: {extends: [fixture], rules: {apt/https: error}}\n  waivers:\n    - {rule: apt/*, subject: /etc/apt/*, reason: mirror moves in December, until: 2026-12-31}\ncomply:\n  directories: [standards]\n");
    let config = Config::load(&path).unwrap();
    assert_eq!(config.lint.directories, [path.parent().unwrap().join("rules")]);
    assert_eq!(config.comply.directories, [path.parent().unwrap().join("standards")]);
    assert_eq!((config.lint.tags.len(), config.lint.waivers[0].until.as_str()), (2, "2026-12-31"));
    assert!(config.lint.rulesets.contains_key("strict"));
}

#[test]
fn a_waiver_without_a_day_or_reason_and_a_bad_fail_on_are_refused() {
    for (name, text) in [("no-day", "lint:\n  waivers: [{rule: a, reason: r, until: soon}]\n"), ("no-reason", "lint:\n  waivers: [{rule: a, reason: ' ', until: 2026-12-31}]\n")] {
        assert!(Config::load(&write(name, text)).unwrap_err().contains("needs a reason and an until day"), "{name}");
    }
    assert!(Config::load(&write("fail-on", "lint:\n  fail-on: loud\n")).unwrap_err().contains("lint.fail-on \"loud\""));
}

#[test]
fn a_hash_key_needs_16_characters() {
    assert!(Config::load(&write("key-15", "collect:\n  hash-key: fifteen-chars-x\n")).unwrap_err().contains("16 characters or more"));
    assert!(Config::load(&write("key-15-wide", "collect:\n  hash-key: ñññññññññññññññ\n")).is_err(), "characters, not bytes");
    assert_eq!(Config::load(&write("key-16", "collect:\n  hash-key: sixteen-chars-xx\n")).unwrap().collect.hash_key.as_deref(), Some("sixteen-chars-xx"));
}
