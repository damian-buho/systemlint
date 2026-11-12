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
    let path = write("relative", "plugins:\n  directories: [plugins, /opt/systemlint/plugins]\n");
    let config = Config::load(&path).unwrap();
    assert_eq!(config.plugins.directories, [path.parent().unwrap().join("plugins"), PathBuf::from("/opt/systemlint/plugins")]);
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
