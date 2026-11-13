// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Collector files: what to read, which plugin op parses it, where the facts land.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::discovery::{Refusal, Trust};

/// The collector directory relative to the core binary’s own directory.
pub const BESIDE: &str = "../share/systemlint/collectors";

/// Top-level keys of the facts document a collector may not write into.
pub const RESERVED: &[&str] = &["meta", "collectors"];

/// One collector file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collector {
    pub id: String,
    #[serde(default)]
    pub read: Read,
    pub parse: Parse,
    pub into: String,
    #[serde(default)]
    pub live: bool,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub secret: bool,
    #[serde(skip)]
    pub inline: bool,
}

/// The `read:` sources.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Read {
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub stat: Vec<String>,
    #[serde(default)]
    pub exec: Option<Vec<String>>,
    #[serde(default, rename = "image-config")]
    pub image_config: bool,
    #[serde(default, rename = "files-from")]
    pub files_from: Vec<String>,
    #[serde(default, rename = "stat-from")]
    pub stat_from: Vec<String>,
    #[serde(default, rename = "stat-keep")]
    pub stat_keep: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub hash: Vec<Digest>,
    #[serde(default)]
    pub statfs: Vec<String>,
    #[serde(default, rename = "statfs-from")]
    pub statfs_from: Vec<String>,
}

/// A digest `read.hash` adds to the stat of each regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Digest {
    Sha256,
    Sha512,
}

impl Read {
    /// The fact paths that name paths to read or stat.
    pub fn named(&self) -> impl Iterator<Item = &String> {
        self.files_from
            .iter()
            .chain(&self.stat_from)
            .chain(&self.statfs_from)
    }
}

/// The literal part of a fact pattern, every segment before the first `*`.
pub fn prefix(pattern: &str) -> String {
    pattern
        .split('.')
        .take_while(|s| *s != "*")
        .collect::<Vec<_>>()
        .join(".")
}

/// The `parse:` plugin op.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parse {
    pub plugin: String,
    pub op: String,
}

impl Collector {
    /// Parses and validates one collector from YAML text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let collector: Self =
            crate::yaml::from_str(text).map_err(|e| format!("not a valid collector: {e}"))?;
        collector.validate()?;
        Ok(collector)
    }

    /// Checks the fields one collector can get wrong on its own.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!(
                "id {:?} is not a slug of lowercase letters, digits and -",
                self.id
            ));
        }
        if let Some(glob) = self
            .read
            .files
            .iter()
            .chain(&self.read.stat)
            .chain(&self.read.statfs)
            .find(|g| !g.starts_with('/'))
        {
            return Err(format!("read glob {glob} is not absolute"));
        }
        if let Some(glob) = self
            .read
            .files
            .iter()
            .chain(&self.read.stat)
            .chain(&self.read.statfs)
            .find(|g| g.contains("**") && !g.ends_with("/**"))
        {
            return Err(format!(
                "read glob {glob} holds ** other than as its whole last component"
            ));
        }
        if !self.read.hash.is_empty() && self.read.stat.is_empty() && self.read.stat_from.is_empty()
        {
            return Err(
                "read.hash adds digests to stats; list the files under read.stat or read.stat-from"
                    .to_owned(),
            );
        }
        if let Some(keep) = &self.read.stat_keep {
            if self.read.stat.is_empty() && self.read.stat_from.is_empty() {
                return Err(
                    "read.stat-keep filters stats; list the files under read.stat or read.stat-from"
                        .to_owned(),
                );
            }
            crate::judge::schema(keep)
                .map_err(|e| format!("read.stat-keep is no valid schema: {e}"))?;
        }
        match self.read.exec.as_deref() {
            Some([]) => return Err("read.exec is empty; give an argv list".to_owned()),
            Some([program, ..]) if !program.starts_with('/') => {
                return Err(format!(
                    "read.exec program {program} is not an absolute path; PATH is never searched"
                ));
            }
            _ => {}
        }
        for pattern in self.read.named() {
            if pattern
                .split('.')
                .any(|s| s.is_empty() || (s.contains('*') && s != "*"))
            {
                return Err(format!(
                    "read pattern {pattern:?} is not a dotted fact path whose wildcards are whole segments"
                ));
            }
            match prefix(pattern) {
                p if p.is_empty() => {
                    return Err(format!(
                        "read pattern {pattern} starts with a wildcard; name the fact it reads from"
                    ));
                }
                p if overlaps(&p, &self.into) => {
                    return Err(format!(
                        "read pattern {pattern} reads {p}, which this collector writes"
                    ));
                }
                _ => {}
            }
        }
        let segments: Vec<&str> = self.into.split('.').collect();
        if segments.iter().any(|s| s.is_empty()) {
            return Err(format!("into {:?} is not a dotted fact path", self.into));
        }
        if RESERVED.contains(&segments[0]) {
            return Err(format!(
                "into {} writes into the reserved {}",
                self.into, segments[0]
            ));
        }
        Ok(())
    }
}

/// Whether one dotted fact path equals the other or lies under it, either way round.
pub fn overlaps(a: &str, b: &str) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    long == short
        || long
            .strip_prefix(short)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// `collector` when its id and `into` are free among `collectors`.
pub fn admit(collectors: &[Collector], collector: Collector) -> Result<Collector, String> {
    match collectors
        .iter()
        .find(|o| o.id == collector.id || overlaps(&o.into, &collector.into))
    {
        Some(o) if o.id == collector.id => Err(format!("id {} is already taken", collector.id)),
        Some(o) => Err(format!(
            "into {} overlaps {} of collector {}",
            collector.into, o.into, o.id
        )),
        None => Ok(collector),
    }
}

/// The directories to search, in order: beside the core binary, then the configured ones.
pub fn directories(exe: &Path, configured: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::directories(exe, BESIDE, configured)
}

/// Every trusted collector in `dirs`, refusing an invalid file, a repeated id or an `into` overlapping an earlier one.
pub fn load(dirs: &[PathBuf], trust: &Trust) -> (Vec<Collector>, Vec<Refusal>) {
    let (texts, mut refusals) = crate::discovery::yaml_files(dirs, trust);
    let mut collectors = Vec::<Collector>::new();
    for (path, text) in texts {
        match Collector::parse(&text).and_then(|c| admit(&collectors, c)) {
            Ok(c) => {
                log::debug!("collector {} from {} into {}", c.id, path.display(), c.into);
                collectors.push(c);
            }
            Err(reason) => refusals.push(Refusal { path, reason }),
        }
    }
    (collectors, refusals)
}
