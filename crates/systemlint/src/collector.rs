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
        let collector: Self = crate::yaml::from_str(text).map_err(|e| format!("not a valid collector: {e}"))?;
        collector.validate()?;
        Ok(collector)
    }

    fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || !self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!("id {:?} is not a slug of lowercase letters, digits and -", self.id));
        }
        if let Some(glob) = self.read.files.iter().chain(&self.read.stat).find(|g| !g.starts_with('/')) {
            return Err(format!("read glob {glob} is not absolute"));
        }
        match self.read.exec.as_deref() {
            Some([]) => return Err("read.exec is empty; give an argv list".to_owned()),
            Some([program, ..]) if !program.starts_with('/') => return Err(format!("read.exec program {program} is not an absolute path; PATH is never searched")),
            _ => {}
        }
        let segments: Vec<&str> = self.into.split('.').collect();
        if segments.iter().any(|s| s.is_empty()) {
            return Err(format!("into {:?} is not a dotted fact path", self.into));
        }
        if RESERVED.contains(&segments[0]) {
            return Err(format!("into {} writes into the reserved {}", self.into, segments[0]));
        }
        Ok(())
    }
}

/// Whether one dotted fact path equals the other or lies under it, either way round.
pub fn overlaps(a: &str, b: &str) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    long == short || long.strip_prefix(short).is_some_and(|rest| rest.starts_with('.'))
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
        let collector = Collector::parse(&text).and_then(|c| match collectors.iter().find(|o| o.id == c.id || overlaps(&o.into, &c.into)) {
            Some(o) if o.id == c.id => Err(format!("id {} is already taken", c.id)),
            Some(o) => Err(format!("into {} overlaps {} of collector {}", c.into, o.into, o.id)),
            None => Ok(c),
        });
        match collector {
            Ok(c) => {
                log::debug!("collector {} from {} into {}", c.id, path.display(), c.into);
                collectors.push(c);
            }
            Err(reason) => refusals.push(Refusal { path, reason }),
        }
    }
    (collectors, refusals)
}
