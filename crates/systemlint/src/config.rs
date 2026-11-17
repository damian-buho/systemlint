// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The YAML configuration files, layered system, user, project, environment and flag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::collector::Collector;
use crate::judge::{Waiver, valid_day};
use crate::report::{Colour, FailOn, Format};
use crate::rules::Ruleset;
use crate::runner::MAX_CHILDREN;

/// The system-wide configuration, the lowest layer, read when it exists.
pub const SYSTEM: &str = "/etc/systemlint/config.yaml";

/// The project configuration in the working directory, read when it exists.
pub const PROJECT: &str = ".systemlint.yaml";

/// The variable naming a configuration file above the project one.
pub const ENV: &str = "SYSTEMLINT_CONFIG";

/// The key in the system or user configuration that skips the project layer when false.
pub const PROJECT_KEY: &str = "project-config";

/// What a configuration layer is: read when present, the project file, or one that must exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Optional,
    Project,
    Required,
}

/// The configuration files to read, lowest first, each with its kind; the project file only when `project`.
pub fn layers(
    explicit: Option<&Path>,
    project: bool,
    var: impl Fn(&str) -> Option<String>,
    cwd: &Path,
) -> Vec<(PathBuf, Layer)> {
    let user = var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| var("HOME").map(|home| Path::new(&home).join(".config")));
    let mut out = vec![(PathBuf::from(SYSTEM), Layer::Optional)];
    out.extend(user.map(|dir| (dir.join("systemlint/config.yaml"), Layer::Optional)));
    out.extend(project.then(|| (cwd.join(PROJECT), Layer::Project)));
    out.extend(
        var(ENV)
            .filter(|p| !p.is_empty())
            .map(|p| (PathBuf::from(p), Layer::Required)),
    );
    out.extend(explicit.map(|p| (p.to_path_buf(), Layer::Required)));
    out
}

/// The whole configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub plugins: Plugins,
    #[serde(default)]
    pub collect: Collect,
    #[serde(default)]
    pub check: Check,
    #[serde(default)]
    pub fix: Fix,
    #[serde(default, rename = "project-config")]
    pub project_config: Option<bool>,
}

/// The `fix:` section.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fix {
    /// Whether `systemlint fix` may change files [default: true]
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// The `check:` section: where rulesets live, inline ones, the default selectors, var values, the threshold and waivers.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    #[serde(default)]
    pub rulesets: BTreeMap<String, Ruleset>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vars: serde_json::Map<String, serde_json::Value>,
    #[serde(default, rename = "fail-on")]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub waivers: Vec<Waiver>,
    #[serde(default)]
    pub format: Option<Format>,
    #[serde(default)]
    pub color: Option<Colour>,
    #[serde(default)]
    pub plain: Option<bool>,
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
    /// Collectors run at once, 1 to 64 [default: the available CPUs, at most 64]
    #[serde(default)]
    pub jobs: Option<u64>,
    /// Run the `network: true` collectors [default: false]
    #[serde(default)]
    pub network: Option<bool>,
    /// Run the `containers: true` collectors [default: false]
    #[serde(default)]
    pub containers: Option<bool>,
    /// Check only the containers these globs name, by key, name or short ID; any turns `containers` on
    #[serde(default)]
    pub container: Vec<String>,
    #[serde(default)]
    pub format: Option<FactsFormat>,
    #[serde(default)]
    pub collectors: Vec<Collector>,
}

/// The `plugins:` section.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugins {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    #[serde(default)]
    pub format: Option<ListFormat>,
}

/// How `facts` encodes its document, the `--format` choice, also `collect.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactsFormat {
    Yaml,
    Json,
}

/// How `plugin list` prints its plugins, the `--format` choice, also `plugins.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    Human,
    Json,
}

impl Config {
    /// Reads `path`, resolving relative plugin and collector directories against the file’s own directory.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::check(path, Self::read(path)?)
    }

    /// Reads every layer that exists, or must, lowest first, a higher one replacing a lower one key by key.
    pub fn layered(layers: &[(PathBuf, Layer)]) -> Result<Self, String> {
        let mut merged = Value::Object(serde_json::Map::new());
        let mut read = Vec::new();
        for (path, layer) in layers {
            if *layer != Layer::Required && !path.exists() {
                log::debug!("config {} is absent, skipped", path.display());
                continue;
            }
            if *layer == Layer::Project && merged[PROJECT_KEY] == false {
                log::debug!(
                    "config {} skipped: {PROJECT_KEY} is false in {}",
                    path.display(),
                    read.join(", ")
                );
                continue;
            }
            let config = Self::read(path)?;
            if *layer != Layer::Optional && config.get(PROJECT_KEY).is_some() {
                return Err(format!(
                    "{}: {PROJECT_KEY} works only in {SYSTEM} or the user configuration. Pass --no-project-config to skip {PROJECT} on one run.",
                    path.display()
                ));
            }
            Self::check(path, config.clone())?;
            log::debug!("config {} read as layer {}", path.display(), read.len() + 1);
            merge(&mut merged, config);
            read.push(path.display().to_string());
        }
        let config = serde_json::from_value(merged).map_err(|e| {
            format!(
                "{} merge into an invalid configuration: {e}",
                read.join(", ")
            )
        })?;
        Self::check(Path::new(&read.join(", ")), config)
    }

    /// `path` as a JSON tree, its relative directories resolved against its own directory.
    fn read(path: &Path) -> Result<Value, String> {
        let fixes = [
            (
                std::io::ErrorKind::NotFound,
                "Pass an existing file to --config or SYSTEMLINT_CONFIG, or drop it to use the defaults.",
            ),
            (
                std::io::ErrorKind::PermissionDenied,
                "Run with sudo, or name a configuration file you can read.",
            ),
        ];
        let text = std::fs::read_to_string(path)
            .map_err(|e| crate::explain::io("read the configuration", path, &e, &fixes))?;
        let mut tree: Value = crate::yaml::from_str::<Option<Value>>(&text)
            .map_err(|e| format!("{} is not a valid configuration: {e}", path.display()))?
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let base = path.parent().unwrap_or(Path::new("."));
        for pointer in [
            "/plugins/directories",
            "/collect/directories",
            "/check/directories",
        ] {
            for dir in tree
                .pointer_mut(pointer)
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                if let Some(relative) = dir.as_str().filter(|d| Path::new(d).is_relative()) {
                    *dir = Value::from(base.join(relative).display().to_string());
                }
            }
        }
        Ok(tree)
    }

    /// `tree` as a configuration, refused with `path` named when a value is out of range.
    fn check(path: &Path, tree: Value) -> Result<Self, String> {
        let mut config: Self = serde_json::from_value(tree)
            .map_err(|e| format!("{} is not a valid configuration: {e}", path.display()))?;
        if config
            .collect
            .hash_key
            .as_deref()
            .is_some_and(|k| k.chars().count() < 16)
        {
            return Err(format!(
                "{}: collect.hash-key needs 16 characters or more, or a hash of a short value is guessed",
                path.display()
            ));
        }
        if config.collect.timeout == Some(0) {
            return Err(format!(
                "{}: collect.timeout needs 1 second or more, or every plugin call fails",
                path.display()
            ));
        }
        if config
            .collect
            .jobs
            .is_some_and(|j| !(1..=MAX_CHILDREN as u64).contains(&j))
        {
            return Err(format!(
                "{}: collect.jobs needs 1 to {MAX_CHILDREN}, as many collectors as Ctrl-C can stop",
                path.display()
            ));
        }
        for collector in &mut config.collect.collectors {
            collector.inline = true;
            collector.validate().map_err(|e| {
                format!(
                    "{}: collect.collectors {}: {e}",
                    path.display(),
                    collector.id
                )
            })?;
            if collector.read.runs() || collector.network {
                return Err(format!(
                    "{}: collect.collectors {}: an inline collector can’t exec or reach the network; put it in a collect.directories file",
                    path.display(),
                    collector.id
                ));
            }
        }
        if let Some(text) = &config.check.fail_on {
            text.parse::<FailOn>()
                .map_err(|e| format!("{}: check.{e}", path.display()))?;
        }
        if let Some(w) = config
            .check
            .waivers
            .iter()
            .find(|w| !valid_day(&w.until) || w.reason.trim().is_empty())
        {
            return Err(format!(
                "{}: the waiver of rule {} needs a reason and an until day as YYYY-MM-DD, got until {:?}",
                path.display(),
                w.rule,
                w.until
            ));
        }
        log::debug!(
            "config {} names {} plugin and {} collector directories",
            path.display(),
            config.plugins.directories.len(),
            config.collect.directories.len()
        );
        Ok(config)
    }
}

/// Merges `top` over `base`: maps key by key, any other value replaced whole.
fn merge(base: &mut Value, top: Value) {
    match (base, top) {
        (Value::Object(base), Value::Object(top)) => {
            for (key, value) in top {
                match base.get_mut(&key) {
                    Some(slot) => merge(slot, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (slot, value) => *slot = value,
    }
}
