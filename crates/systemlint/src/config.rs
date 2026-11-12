// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The YAML configuration file.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The system-wide configuration, read when `--config` is not given and the file exists.
pub const SYSTEM: &str = "/etc/systemlint/config.yaml";

/// The whole configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub plugins: Plugins,
}

/// The `plugins:` section.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugins {
    #[serde(default)]
    pub directories: Vec<PathBuf>,
}

impl Config {
    /// Reads `path`, resolving relative plugin directories against the file’s own directory.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("can’t read {}: {e}", path.display()))?;
        let mut config: Self = serde_saphyr::from_str(&text).map_err(|e| format!("{} is not a valid configuration: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for dir in &mut config.plugins.directories {
            if dir.is_relative() {
                *dir = base.join(&*dir);
            }
        }
        log::debug!("config {} names {} plugin directories", path.display(), config.plugins.directories.len());
        Ok(config)
    }
}

