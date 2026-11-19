// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The remedies a rule may declare, the plan a lint run yields, and applying it through [`Root`].

use std::collections::{BTreeMap, BTreeSet};
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
    /// Writes one systemlint-owned file of lines that only turn something off, refused when it holds anything else.
    #[serde(rename = "drop-in")]
    DropIn(DropIn),
}

/// A drop-in file: the directory it goes in, the name it takes after `60-systemlint-`, and its lines.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DropIn {
    pub into: Directory,
    pub name: String,
    pub lines: Vec<String>,
    /// Unloads every module its lines name from the running kernel once written, `into: modprobe` only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unload: bool,
}

/// A configuration directory a drop-in may go in, each with the only lines it may write there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Directory {
    /// `/etc/modprobe.d`, for `install <module> /bin/false` and `blacklist <module>`.
    Modprobe,
    /// `/etc/apt/apt.conf.d`, for turning off recommended and suggested packages.
    Apt,
}

/// The modprobe that unloads a module, the one the kernel-modules collectors run.
const MODPROBE: &str = "/usr/sbin/modprobe";

/// How long one unload may take before it counts as failed.
const UNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The apt settings a drop-in may write, each turning off an install default.
const APT_LINES: [&str; 4] = [
    "APT::Install-Recommends \"0\";",
    "APT::Install-Recommends \"false\";",
    "APT::Install-Suggests \"0\";",
    "APT::Install-Suggests \"false\";",
];

impl Directory {
    /// Where its drop-ins go.
    fn path(self) -> &'static str {
        match self {
            Self::Modprobe => "/etc/modprobe.d",
            Self::Apt => "/etc/apt/apt.conf.d",
        }
    }

    /// Whether `line` only turns something off here.
    fn admits(self, line: &str) -> bool {
        let module = |m: &str| {
            !m.is_empty()
                && m.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        match (self, line.split(' ').collect::<Vec<_>>().as_slice()) {
            (
                Self::Modprobe,
                [
                    "install",
                    m,
                    "/bin/false" | "/bin/true" | "/usr/bin/false" | "/usr/bin/true",
                ],
            ) => module(m),
            (Self::Modprobe, ["blacklist", m]) => module(m),
            (Self::Apt, _) => APT_LINES.contains(&line),
            _ => false,
        }
    }
}

impl DropIn {
    /// The file it writes.
    pub fn path(&self) -> String {
        format!("{}/60-systemlint-{}.conf", self.into.path(), self.name)
    }

    /// Its text: every line ended by a newline.
    pub fn text(&self) -> String {
        self.lines.iter().map(|l| format!("{l}\n")).collect()
    }

    /// The modules its lines name, as `install <module> …` and `blacklist <module>` spell them.
    pub fn modules(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|l| l.split(' ').nth(1))
            .collect()
    }

    /// The command that unloads its modules, when it unloads any.
    fn unloading(&self) -> Option<String> {
        self.unload
            .then(|| format!("modprobe -r {}", self.modules().join(" ")))
    }

    /// The fix steps a reader follows to do by hand what `systemlint fix` does: the very file it writes, then any unload.
    pub fn steps(&self) -> crate::rules::Fix {
        use crate::rules::{Fix, Shown, Step};
        let these = if self.lines.len() == 1 {
            "this line"
        } else {
            "these lines"
        };
        let mut steps = vec![
            Step::Say(format!("Write {these} to “{}”:", self.path())),
            Step::Show(Shown::Lines(self.lines.clone())),
        ];
        if let Some(command) = self.unloading() {
            let them = if self.modules().len() == 1 {
                "it"
            } else {
                "them"
            };
            steps.push(Step::Say(format!("Unload {them} from the running kernel:")));
            steps.push(Step::Show(Shown::Run(command)));
        }
        Fix::Steps(steps)
    }
}

/// A file syntax whose every line only grants access, so commenting one out only takes access away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Lines {
    /// `authorized_keys`, where each line lets one more key log in.
    AuthorizedKeys,
    /// One-line apt sources (`.list`), where each line trusts one more repository.
    AptList,
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
            Self::DropIn(drop) => {
                let named = !drop.name.is_empty()
                    && drop.name.len() <= 64
                    && drop
                        .name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                if !named {
                    return Err(format!(
                        "remedy drop-in name {:?}: write lowercase letters, digits and -",
                        drop.name
                    ));
                }
                if drop.unload && drop.into != Directory::Modprobe {
                    return Err("remedy drop-in unload takes into: modprobe".to_owned());
                }
                if drop.lines.is_empty() || drop.lines.len() > 16 {
                    return Err("remedy drop-in takes 1 to 16 lines".to_owned());
                }
                match drop.lines.iter().find(|l| !drop.into.admits(l)) {
                    Some(line) => Err(format!(
                        "remedy drop-in line {line:?} is not one that only turns something off in {}",
                        drop.into.path()
                    )),
                    None => Ok(()),
                }
            }
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
            Self::DropIn(drop) => {
                let lines: Vec<String> = drop.lines.iter().map(|l| quote(l)).collect();
                let written = format!(
                    "printf '%s\\n' {} > {}",
                    lines.join(" "),
                    quote(&drop.path())
                );
                match drop.unloading() {
                    Some(command) => format!("{written} && {command}"),
                    None => written,
                }
            }
        }
    }
}

/// Whether a remedy command writes a drop-in file, which a fix’s steps explain better than its shell line.
pub fn writes(command: &str) -> bool {
    command.starts_with("printf '%s\\n' ")
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
pub(crate) fn quote(path: &str) -> String {
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

/// The changes a lint calls for, and the line changes held back since each would disable the last line of its owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub kept: Vec<(Change, String)>,
}

/// The changes the failing checks over `document` call for, one per subject and remedy, in path order.
pub fn plan(checks: &[Check], rules: &[Rule], document: &serde_json::Value) -> Plan {
    let remedies: BTreeMap<&str, (&Rule, &Remedy)> = rules
        .iter()
        .filter_map(|r| r.spec.remedy.as_ref().map(|m| (r.id.as_str(), (r, m))))
        .collect();
    let mut owners: BTreeMap<String, Vec<(String, BTreeSet<String>)>> = BTreeMap::new();
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
                        .subject_value(document, &c.subject, 1)
                        .and_then(|v| v.get("line-sha256"))
                        .and_then(serde_json::Value::as_str);
                    log::debug!("{} on {subject}: line-sha256 {sha:?}", c.rule);
                    let siblings = rule
                        .subject_value(document, &c.subject, 2)
                        .and_then(serde_json::Value::as_object)
                        .map(|m| m.keys().cloned().collect())
                        .unwrap_or_default();
                    let owner = match c.subject[..c.subject.len().saturating_sub(1)].join(", ") {
                        owner if owner.is_empty() => "this host".to_owned(),
                        owner => owner,
                    };
                    owners
                        .entry(subject.clone())
                        .or_default()
                        .push((owner, siblings));
                    (path.to_owned(), Some((n, sha?.to_owned())))
                }
                Remedy::DropIn(drop) => (drop.path(), None),
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
    changes.dedup_by(|a, b| match (&a.remedy, &mut b.remedy) {
        (Remedy::DropIn(later), Remedy::DropIn(kept))
            if later.lines == kept.lines && a.path == b.path =>
        {
            log::debug!(
                "{}: one write, unload {}",
                a.path,
                later.unload || kept.unload
            );
            kept.unload |= later.unload;
            true
        }
        _ => a.path == b.path && a.line == b.line && a.remedy == b.remedy,
    });
    let mut disabled: BTreeSet<String> = BTreeSet::new();
    let mut plan = Plan::default();
    for change in changes {
        let subject = change.subject();
        let last = owners
            .get(&subject)
            .into_iter()
            .flatten()
            .find(|(_, lines)| lines.iter().all(|l| *l == subject || disabled.contains(l)));
        match (change.line.is_some(), last) {
            (true, Some((owner, _))) => {
                log::debug!("{subject} kept: the last line {owner} has");
                let reason = format!("it is the last line left for {owner}");
                plan.kept.push((change, reason));
            }
            _ => {
                disabled.insert(subject);
                plan.changes.push(change);
            }
        }
    }
    log::debug!(
        "{} changes planned, {} kept, from {} checks",
        plan.changes.len(),
        plan.kept.len(),
        checks.len()
    );
    plan
}

/// What applying a change did: the state before and after, or none when it was already made.
pub type Applied = Option<(String, String)>;

/// Makes `change` on the file it names under `root`, re-read right before, refusing a symlink or a special file.
pub fn apply(root: &Root, change: &Change) -> Result<Applied, std::io::Error> {
    change.remedy.validate().map_err(std::io::Error::other)?;
    match &change.remedy {
        Remedy::DisableLine(_) => return disable(root, change),
        Remedy::DropIn(drop) => return drop_in(root, drop),
        _ => {}
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
        Remedy::DropIn(drop) => drop_in(root, drop),
    }
}

/// Writes `drop` and unloads its modules, refusing first when the running kernel uses one of them.
fn drop_in(root: &Root, drop: &DropIn) -> Result<Applied, std::io::Error> {
    let live = root.path() == std::path::Path::new("/");
    if drop.into == Directory::Modprobe && live {
        let listed =
            String::from_utf8_lossy(&root.read("/proc/modules", crate::runner::OUTPUT_CAP)?)
                .into_owned();
        let used = in_use(&listed, &drop.modules());
        log::debug!("{}: {} of its modules in use", drop.path(), used.len());
        if !used.is_empty() {
            let named: Vec<String> = used
                .iter()
                .map(|(m, n)| format!("{m} ({n} users)"))
                .collect();
            return Err(std::io::Error::other(format!(
                "the running kernel uses {}, so systemlint writes nothing: blocking it would break what uses it at the next boot",
                named.join(", ")
            )));
        }
    }
    write(root, drop).and_then(|w| unload(root, drop, w))
}

/// The `modules` that `/proc/modules` text lists with a use count above 0, and that count.
pub fn in_use<'a>(listed: &str, modules: &[&'a str]) -> Vec<(&'a str, u64)> {
    modules
        .iter()
        .copied()
        .filter_map(|m| {
            let spelled = m.replace('-', "_");
            let line = listed
                .lines()
                .find(|l| l.split(' ').next() == Some(spelled.as_str()))?;
            let users = line.split(' ').nth(2)?.parse::<u64>().ok()?;
            log::debug!("module {m}: {users} users");
            (users > 0).then_some((m, users))
        })
        .collect()
}

/// Writes `drop` as a new file, nothing when it already holds exactly its lines, refusing one that holds anything else.
fn write(root: &Root, drop: &DropIn) -> Result<Applied, std::io::Error> {
    let path = drop.path();
    let text = drop.text();
    let name = path.rsplit('/').next().unwrap_or_default();
    match root.write_new(drop.into.path(), name, &text, 0o644) {
        Ok(()) => {
            log::debug!("{path}: written, {} lines", drop.lines.len());
            Ok(Some(("absent".to_owned(), "written".to_owned())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut held = String::new();
            root.open_for_change(&path)?
                .take(crate::runner::OUTPUT_CAP)
                .read_to_string(&mut held)?;
            log::debug!("{path}: exists, holds its lines {}", held == text);
            match held == text {
                true => Ok(None),
                false => Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "it exists with other lines, so systemlint leaves it",
                )),
            }
        }
        Err(e) => Err(e),
    }
}

/// The `modules` that `/proc/modules` text lists, either spelling (`usb-storage`, `usb_storage`) matching kmod’s.
pub fn loaded<'a>(listed: &str, modules: &[&'a str]) -> Vec<&'a str> {
    let spelled = |m: &str| m.replace('-', "_");
    modules
        .iter()
        .copied()
        .filter(|m| {
            listed
                .lines()
                .any(|l| l.split(' ').next() == Some(spelled(m).as_str()))
        })
        .collect()
}

/// Unloads the modules of `drop` the running kernel lists, only on the live root, adding what it did to `written`.
fn unload(root: &Root, drop: &DropIn, written: Applied) -> Result<Applied, std::io::Error> {
    let live = root.path() == std::path::Path::new("/");
    log::debug!("{}: unload {}, live root {live}", drop.path(), drop.unload);
    if !drop.unload || !live {
        return Ok(written);
    }
    let listed = String::from_utf8_lossy(&root.read("/proc/modules", crate::runner::OUTPUT_CAP)?)
        .into_owned();
    let loaded = loaded(&listed, &drop.modules());
    log::debug!("{}: {} of its modules loaded", drop.path(), loaded.len());
    if loaded.is_empty() {
        return Ok(written);
    }
    let mut args = vec!["-r"];
    args.extend(&loaded);
    let output = crate::runner::run(
        std::path::Path::new(MODPROBE),
        &args,
        None,
        UNLOAD_TIMEOUT,
        crate::runner::OUTPUT_CAP,
        None,
    )
    .map_err(std::io::Error::other)?;
    log::debug!("modprobe -r {}: exit {}", loaded.join(" "), output.code());
    let names = loaded.join(", ");
    if output.code() != 0 {
        let answer = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let (before, after) = written.unwrap_or(("unchanged".to_owned(), "unchanged".to_owned()));
        return Ok(Some((
            format!("{before}, {names} loaded"),
            format!(
                "{after}, {names} still loaded until the next boot (modprobe -r answered “{answer}”)"
            ),
        )));
    }
    Ok(Some(match written {
        Some((before, after)) => (
            format!("{before}, {names} loaded"),
            format!("{after}, {names} unloaded"),
        ),
        None => (format!("{names} loaded"), format!("{names} unloaded")),
    }))
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
