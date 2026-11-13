// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The remedies a rule may declare, the plan a lint run yields, and applying it through [`Root`].

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Comments out the subject line, only in a syntax where every line grants access.
    #[serde(rename = "disable-line")]
    DisableLine(Lines),
}

/// A file syntax whose every line only grants access, so commenting one out only takes access away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Lines {
    /// `authorized_keys`, where each line lets one more key log in.
    AuthorizedKeys,
}

/// `subject` split into its path and 1-based line number, as `path:line` keys name a line.
pub fn line_of(subject: &str) -> Option<(&str, usize)> {
    let (path, line) = subject.rsplit_once(':')?;
    line.parse().ok().filter(|n| *n > 0).map(|n| (path, n))
}

/// The SHA-256 of one line in lowercase hex, as `line-sha256` facts carry it.
pub fn line_sha256(line: &str) -> String {
    Sha256::digest(line.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Remedy {
    /// Checks the remedy, so a bad ruleset fails as config before any run.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Chmod(spec) => cleared(spec).map(|_| ()),
            Self::Chown(0) => Ok(()),
            Self::Chown(uid) => Err(format!(
                "remedy chown {uid}: only chown 0 is allowed, a fix never hands a file to a user"
            )),
            Self::Chgrp(0) => Ok(()),
            Self::Chgrp(gid) => Err(format!(
                "remedy chgrp {gid}: only chgrp 0 is allowed, a fix never hands a file to a group of users"
            )),
            Self::DisableLine(_) => Ok(()),
        }
    }

    /// The shell command this remedy stands for on `subject`, a path or for a line `path:line`.
    pub fn command(&self, subject: &str) -> String {
        match self {
            Self::Chmod(spec) => format!("chmod {spec} {}", quote(subject)),
            Self::Chown(uid) => format!("chown {uid} {}", quote(subject)),
            Self::Chgrp(gid) => format!("chgrp {gid} {}", quote(subject)),
            Self::DisableLine(_) => match line_of(subject) {
                Some((path, line)) => format!("sed -i '{line}s/^/#/' {}", quote(path)),
                None => format!("# no line named in {}", quote(subject)),
            },
        }
    }
}

/// The mode bits a symbolic `who-perms[,…]` clears; only `-` is accepted.
pub fn cleared(spec: &str) -> Result<u32, String> {
    let bad = |why: &str| format!("remedy chmod {spec:?}: {why}; write who-perms like g-w,o-rwx");
    spec.split(',').try_fold(0, |mask, clause| {
        let (who, perms) = clause
            .split_once('-')
            .ok_or_else(|| bad("only - is allowed, a fix never adds a permission"))?;
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
    if !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%".contains(c))
    {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', r"'\''"))
    }
}

/// One change to make: the remedy of `rule` on the subject `path`, or on its line holding the given SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub rule: String,
    pub path: String,
    pub line: Option<(usize, String)>,
    pub remedy: Remedy,
}

impl Change {
    /// The path, or `path:line` for a line change.
    pub fn subject(&self) -> String {
        match &self.line {
            Some((n, _)) => format!("{}:{n}", self.path),
            None => self.path.clone(),
        }
    }
}

/// The changes the failing checks over `document` call for, one per subject and remedy, in path order.
pub fn plan(checks: &[Check], rules: &[Rule], document: &serde_json::Value) -> Vec<Change> {
    let remedies: BTreeMap<&str, (&Rule, &Remedy)> = rules
        .iter()
        .filter_map(|r| r.spec.remedy.as_ref().map(|m| (r.id.as_str(), (r, m))))
        .collect();
    let mut changes: Vec<Change> = checks
        .iter()
        .filter(|c| c.is_failing())
        .filter_map(|c| {
            let (rule, remedy) = remedies.get(c.rule.as_str())?;
            let subject = c.subject_label();
            let (path, line) = match remedy {
                Remedy::DisableLine(_) => {
                    let (path, n) = line_of(&subject)?;
                    let sha = rule
                        .subject_value(document, &c.subject)
                        .and_then(|v| v.get("line-sha256"))
                        .and_then(serde_json::Value::as_str);
                    log::debug!("{} on {subject}: line-sha256 {sha:?}", c.rule);
                    (path.to_owned(), Some((n, sha?.to_owned())))
                }
                _ => (subject, None),
            };
            Some(Change {
                rule: c.rule.clone(),
                path,
                line,
                remedy: (*remedy).clone(),
            })
        })
        .filter(|c| c.path.starts_with('/'))
        .collect();
    let key = |c: &Change| (c.path.clone(), c.line.clone(), c.remedy.command(""));
    changes.sort_by_key(key);
    changes.dedup_by(|a, b| a.path == b.path && a.line == b.line && a.remedy == b.remedy);
    log::debug!(
        "{} changes planned from {} checks",
        changes.len(),
        checks.len()
    );
    changes
}

/// What applying a change did: the state before and after, or none when it was already made.
pub type Applied = Option<(String, String)>;

/// Makes `change` on the file it names under `root`, re-read right before, refusing a symlink or a special file.
pub fn apply(root: &Root, change: &Change) -> Result<Applied, std::io::Error> {
    change.remedy.validate().map_err(std::io::Error::other)?;
    if let Remedy::DisableLine(_) = change.remedy {
        return disable(root, change);
    }
    let file = root.open_for_change(&change.path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "it is a symbolic link now, so lint again before fixing",
            )
        } else {
            e
        }
    })?;
    let meta = file.metadata()?;
    if !meta.is_file() && !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file or directory",
        ));
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
        Remedy::DisableLine(_) => disable(root, change),
    }
}

/// Comments out the line `change` names, refusing when it no longer holds the text the lint hashed.
fn disable(root: &Root, change: &Change) -> Result<Applied, std::io::Error> {
    let invalid = |why: String| std::io::Error::new(std::io::ErrorKind::InvalidData, why);
    let (number, sha) = change
        .line
        .as_ref()
        .ok_or_else(|| invalid("the subject names no line".to_owned()))?;
    let mut file = root.open_for_edit(&change.path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(invalid("not a regular file".to_owned()));
    }
    if meta.len() > crate::runner::OUTPUT_CAP {
        return Err(invalid(format!(
            "{} bytes is past what systemlint rewrites",
            meta.len()
        )));
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let mut text = String::new();
    (&mut file)
        .take(crate::runner::OUTPUT_CAP)
        .read_to_string(&mut text)?;
    let mut offset = 0;
    let found = text.split_inclusive('\n').enumerate().find_map(|(i, raw)| {
        let start = offset;
        offset += raw.len();
        (i + 1 == *number).then_some((start, raw))
    });
    let (start, raw) = found.ok_or_else(|| {
        invalid(format!(
            "line {number} is gone, so lint again before fixing"
        ))
    })?;
    let line = raw.strip_suffix('\n').unwrap_or(raw);
    let line = line.strip_suffix('\r').unwrap_or(line);
    log::debug!(
        "{}: line {number} hashes {}, wanted {sha}",
        change.path,
        line_sha256(line)
    );
    if line
        .strip_prefix('#')
        .is_some_and(|rest| line_sha256(rest) == *sha)
    {
        return Ok(None);
    }
    if line_sha256(line) != *sha {
        return Err(invalid(format!(
            "line {number} changed since the lint, so lint again before fixing"
        )));
    }
    let tail = format!("#{}", &text[start..]);
    file.write_all_at(tail.as_bytes(), start as u64)?;
    file.sync_all()?;
    Ok(Some(("active".to_owned(), "commented out".to_owned())))
}
