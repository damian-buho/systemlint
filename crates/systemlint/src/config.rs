// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The YAML configuration file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::judge::{Waiver, valid_day};
use crate::report::FailOn;
use crate::rules::Ruleset;

/// The system-wide configuration, read when `--config` is not given and the file exists.
pub const SYSTEM: &str = "/etc/systemlint/config.yaml";

/// The whole configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub plugins: Plugins,
    #[serde(default)]
    pub collect: Collect,
    #[serde(default)]
    pub lint: Lint,
}

/// The `lint:` section: where rulesets live, inline ones, the default selectors, the threshold and waivers.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lint {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    #[serde(default)]
    pub rulesets: BTreeMap<String, Ruleset>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, rename = "fail-on")]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub waivers: Vec<Waiver>,
}

/// The `collect:` section: where collectors live, and the key hashed values share across runs.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collect {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    #[serde(default, rename = "hash-key")]
    pub hash_key: Option<String>,
    /// Seconds an `exec` or a plugin call may take, 1 or more [default: 30]
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// The `plugins:` section.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugins {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
}

impl Config {
    /// Reads `path`, resolving relative plugin and collector directories against the file’s own directory.
    pub fn load(path: &Path) -> Result<Self, String> {
        let fixes = [(std::io::ErrorKind::NotFound, "Pass an existing file to --config, or drop --config to use the defaults."), (std::io::ErrorKind::PermissionDenied, "Run with sudo, or pass --config a file you can read.")];
        let text = std::fs::read_to_string(path).map_err(|e| crate::explain::io("read the configuration", path, &e, &fixes))?;
        let mut config: Self = crate::yaml::from_str(&text).map_err(|e| format!("{} is not a valid configuration: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for dir in config.plugins.directories.iter_mut().chain(&mut config.collect.directories).chain(&mut config.lint.directories) {
            if dir.is_relative() {
                *dir = base.join(&*dir);
            }
        }
        if config.collect.hash_key.as_deref().is_some_and(|k| k.chars().count() < 16) {
            return Err(format!("{}: collect.hash-key needs 16 characters or more, or a hash of a short value is guessed", path.display()));
        }
        if config.collect.timeout == Some(0) {
            return Err(format!("{}: collect.timeout needs 1 second or more, or every plugin call fails", path.display()));
        }
        if let Some(text) = &config.lint.fail_on {
            text.parse::<FailOn>().map_err(|e| format!("{}: lint.{e}", path.display()))?;
        }
        if let Some(w) = config.lint.waivers.iter().find(|w| !valid_day(&w.until) || w.reason.trim().is_empty()) {
            return Err(format!("{}: the waiver of rule {} needs a reason and an until day as YYYY-MM-DD, got until {:?}", path.display(), w.rule, w.until));
        }
        log::debug!("config {} names {} plugin and {} collector directories", path.display(), config.plugins.directories.len(), config.collect.directories.len());
        Ok(config)
    }
}

