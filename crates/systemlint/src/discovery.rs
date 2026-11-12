// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Finds plugin executables beside the core and in configured directories, refusing any a stranger could replace.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The filename prefix every plugin carries.
pub const PREFIX: &str = "systemlint-";

/// The plugin directory relative to the core binary’s own directory.
pub const BESIDE: &str = "../lib/systemlint/plugins";

/// A plugin found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plugin {
    pub name: String,
    pub path: PathBuf,
}

/// A directory or file discovery refused, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub path: PathBuf,
    pub reason: String,
}

/// Who may own a plugin and every directory above it.
#[derive(Debug, Clone)]
pub struct Trust {
    pub uids: Vec<u32>,
    pub top: PathBuf,
}

impl Trust {
    /// Root and the user running systemlint, as sudo trusts its own files.
    pub fn invoking_user() -> Self {
        let uid = rustix::process::getuid().as_raw();
        log::debug!("trusting owners uid 0 and uid {uid}");
        Self { uids: vec![0, uid], top: PathBuf::from("/") }
    }

    /// Fails unless `path` and every directory above it up to `top`, symlinks resolved, has a trusted owner and no group or other write bit.
    pub fn check(&self, path: &Path) -> Result<PathBuf, Refusal> {
        let refuse = |reason: String| Refusal { path: path.to_path_buf(), reason };
        let real = path.canonicalize().map_err(|e| refuse(format!("can’t resolve it: {e}")))?;
        for ancestor in real.ancestors() {
            let meta = std::fs::symlink_metadata(ancestor).map_err(|e| refuse(format!("can’t stat {}: {e}", ancestor.display())))?;
            let mode = meta.permissions().mode() & 0o7777;
            if !self.uids.contains(&meta.uid()) {
                return Err(refuse(format!("{} is owned by uid {}, not root or you; run chown root {}", ancestor.display(), meta.uid(), ancestor.display())));
            }
            if mode & 0o022 != 0 {
                return Err(refuse(format!("group or others can write {} (mode {mode:04o}); run chmod go-w {}", ancestor.display(), ancestor.display())));
            }
            log::trace!("trusted {} uid {} mode {mode:04o}", ancestor.display(), meta.uid());
            if ancestor == self.top {
                break;
            }
        }
        Ok(real)
    }
}

/// The directories to search, in order: beside the core binary, then the configured ones.
pub fn directories(exe: &Path, configured: &[PathBuf]) -> Vec<PathBuf> {
    let beside = exe.parent().unwrap_or(Path::new("/")).join(BESIDE);
    std::iter::once(beside).chain(configured.iter().cloned()).collect()
}

/// Every trusted plugin in `dirs`, the first of a name winning, plus every refusal.
pub fn discover(dirs: &[PathBuf], trust: &Trust) -> (Vec<Plugin>, Vec<Refusal>) {
    let (mut plugins, mut refusals) = (Vec::<Plugin>::new(), Vec::new());
    for dir in dirs {
        if !dir.exists() {
            log::debug!("plugin directory {} does not exist, skipped", dir.display());
            continue;
        }
        let dir = match trust.check(dir) {
            Ok(real) => real,
            Err(refusal) => {
                refusals.push(refusal);
                continue;
            }
        };
        let mut entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(read) => read.filter_map(|e| e.ok().map(|e| e.path())).collect(),
            Err(error) => {
                refusals.push(Refusal { path: dir.clone(), reason: format!("can’t list it: {error}") });
                continue;
            }
        };
        entries.sort();
        log::debug!("plugin directory {} holds {} entries", dir.display(), entries.len());
        for path in entries {
            let Some(name) = plugin_name(&path) else {
                log::trace!("{} is not named {PREFIX}<name>, skipped", path.display());
                continue;
            };
            if !is_executable(&path) {
                log::debug!("{} is not an executable file, skipped", path.display());
                continue;
            }
            if let Some(first) = plugins.iter().find(|p| p.name == name) {
                log::info!("plugin {name} at {} is shadowed by {}", path.display(), first.path.display());
                continue;
            }
            match trust.check(&path) {
                Ok(_) => {
                    log::debug!("found plugin {name} at {}", path.display());
                    plugins.push(Plugin { name, path });
                }
                Err(refusal) => refusals.push(refusal),
            }
        }
    }
    (plugins, refusals)
}

fn plugin_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?.strip_prefix(PREFIX)?;
    let valid = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    valid.then(|| name.to_owned())
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

