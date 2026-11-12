// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The remedies a rule may declare, the plan a lint run yields, and applying it through [`Root`].

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};

use crate::judge::{Check, Rule};
use crate::source::Root;

/// A change the core knows how to make to a rule’s subject path, the closed set that bounds what `fix` can do.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Remedy {
    /// Clears permission bits, symbolic like `g-w,o-rwx`, so it never loosens a mode.
    Chmod(String),
    /// Sets the owning uid, leaving the group; only 0, so a fix never hands a file to a user.
    Chown(u32),
    /// Sets the owning gid, leaving the user; only 0, so a fix never hands a file to a group of users.
    Chgrp(u32),
}

impl Remedy {
    /// Checks the remedy, so a bad ruleset fails as config before any run.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Chmod(spec) => cleared(spec).map(|_| ()),
            Self::Chown(0) => Ok(()),
            Self::Chown(uid) => Err(format!("remedy chown {uid}: only chown 0 is allowed, a fix never hands a file to a user")),
            Self::Chgrp(0) => Ok(()),
            Self::Chgrp(gid) => Err(format!("remedy chgrp {gid}: only chgrp 0 is allowed, a fix never hands a file to a group of users")),
        }
    }

    /// The shell command this remedy stands for on `path`.
    pub fn command(&self, path: &str) -> String {
        match self {
            Self::Chmod(spec) => format!("chmod {spec} {}", quote(path)),
            Self::Chown(uid) => format!("chown {uid} {}", quote(path)),
            Self::Chgrp(gid) => format!("chgrp {gid} {}", quote(path)),
        }
    }
}

/// The mode bits a symbolic `who-perms[,…]` clears; only `-` is accepted.
pub fn cleared(spec: &str) -> Result<u32, String> {
    let bad = |why: &str| format!("remedy chmod {spec:?}: {why}; write who-perms like g-w,o-rwx");
    spec.split(',').try_fold(0, |mask, clause| {
        let (who, perms) = clause.split_once('-').ok_or_else(|| bad("only - is allowed, a fix never adds a permission"))?;
        let who = if who == "a" { "ugo" } else { who };
        if who.is_empty() || perms.is_empty() {
            return Err(bad("a clause needs who and perms"));
        }
        who.chars().try_fold(mask, |mask, w| {
            let shift = match w {
                'u' => 6,
                'g' => 3,
                'o' => 0,
                _ => return Err(bad(&format!("who {w:?} is not u, g, o or a"))),
            };
            perms.chars().try_fold(mask, |mask, p| match (p, w) {
                ('r', _) => Ok(mask | (0o4 << shift)),
                ('w', _) => Ok(mask | (0o2 << shift)),
                ('x', _) => Ok(mask | (0o1 << shift)),
                ('s', 'u') => Ok(mask | 0o4000),
                ('s', 'g') => Ok(mask | 0o2000),
                ('t', 'o') => Ok(mask | 0o1000),
                ('s' | 't', _) => Ok(mask),
                _ => Err(bad(&format!("perm {p:?} is not r, w, x, s or t"))),
            })
        })
    })
}

/// `path` as one shell word, single-quoted unless it holds only safe characters.
fn quote(path: &str) -> String {
    if !path.is_empty() && path.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+:@%".contains(c)) { path.to_owned() } else { format!("'{}'", path.replace('\'', r"'\''")) }
}

/// One change to make: the remedy of `rule` on the subject `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub rule: String,
    pub path: String,
    pub remedy: Remedy,
}

/// The changes the failing checks call for, one per path and remedy, in path order.
pub fn plan(checks: &[Check], rules: &[Rule]) -> Vec<Change> {
    let remedies: BTreeMap<&str, &Remedy> = rules.iter().filter_map(|r| r.spec.remedy.as_ref().map(|m| (r.id.as_str(), m))).collect();
    let mut changes: Vec<Change> = checks.iter().filter(|c| c.is_failing()).filter_map(|c| remedies.get(c.rule.as_str()).map(|m| Change { rule: c.rule.clone(), path: c.subject_label(), remedy: (*m).clone() })).filter(|c| c.path.starts_with('/')).collect();
    changes.sort_by(|a, b| (&a.path, a.remedy.command("")).cmp(&(&b.path, b.remedy.command(""))));
    changes.dedup_by(|a, b| a.path == b.path && a.remedy == b.remedy);
    log::debug!("{} changes planned from {} checks", changes.len(), checks.len());
    changes
}

/// What applying a change did: the state before and after, or none when it was already made.
pub type Applied = Option<(String, String)>;

/// Makes `change` on the file it names under `root`, re-read right before, refusing a symlink or a special file.
pub fn apply(root: &Root, change: &Change) -> Result<Applied, std::io::Error> {
    change.remedy.validate().map_err(std::io::Error::other)?;
    let file = root.open_for_change(&change.path).map_err(|e| if e.raw_os_error() == Some(libc::ELOOP) { std::io::Error::new(std::io::ErrorKind::InvalidInput, "it is a symbolic link now, so lint again before fixing") } else { e })?;
    let meta = file.metadata()?;
    if !meta.is_file() && !meta.is_dir() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file or directory"));
    }
    match &change.remedy {
        Remedy::Chmod(spec) => {
            let before = meta.mode() & 0o7777;
            let after = before & !cleared(spec).map_err(std::io::Error::other)?;
            log::debug!("{}: mode {before:04o}, wanted {after:04o}", change.path);
            if after == before {
                return Ok(None);
            }
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(after))?;
            Ok(Some((format!("{before:04o}"), format!("{after:04o}"))))
        }
        Remedy::Chown(uid) => {
            log::debug!("{}: uid {}, wanted {uid}", change.path, meta.uid());
            if meta.uid() == *uid {
                return Ok(None);
            }
            rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(*uid)), None)?;
            Ok(Some((format!("uid {}", meta.uid()), format!("uid {uid}"))))
        }
        Remedy::Chgrp(gid) => {
            log::debug!("{}: gid {}, wanted {gid}", change.path, meta.gid());
            if meta.gid() == *gid {
                return Ok(None);
            }
            rustix::fs::fchown(&file, None, Some(rustix::process::Gid::from_raw(*gid)))?;
            Ok(Some((format!("gid {}", meta.gid()), format!("gid {gid}"))))
        }
    }
}
