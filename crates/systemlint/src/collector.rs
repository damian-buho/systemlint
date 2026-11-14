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
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub network: bool,
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
    #[serde(default, rename = "stat-parents")]
    pub stat_parents: bool,
    #[serde(default)]
    pub hash: Vec<Digest>,
    #[serde(default)]
    pub statfs: Vec<String>,
    #[serde(default, rename = "statfs-from")]
    pub statfs_from: Vec<String>,
    #[serde(default)]
    pub addr: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default = "dns_types", rename = "dns-types")]
    pub dns_types: Vec<String>,
    #[serde(default, rename = "dns-server")]
    pub dns_server: Option<String>,
    #[serde(default)]
    pub http: Vec<Http>,
}

/// The record types a `dns` probe asks for unless `dns-types` names others.
fn dns_types() -> Vec<String> {
    vec!["A".to_owned(), "AAAA".to_owned()]
}

/// The record types a `dns` probe may ask for.
pub const DNS_TYPES: &[&str] = &[
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
];

/// One `read.http` request: a URL, or a map adding credentials, a CA file and how to read the body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, from = "HttpEntry")]
pub struct Http {
    pub url: String,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    pub body: Option<Body>,
}

/// How an `http` probe turns its body into facts beside `body-sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Body {
    Json,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HttpEntry {
    Url(String),
    Full {
        url: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default, rename = "password-file")]
        password_file: Option<PathBuf>,
        #[serde(default, rename = "ca-file")]
        ca_file: Option<PathBuf>,
        #[serde(default)]
        body: Option<Body>,
    },
}

impl From<HttpEntry> for Http {
    fn from(entry: HttpEntry) -> Self {
        match entry {
            HttpEntry::Url(url) => Self {
                url,
                ..Self::default()
            },
            HttpEntry::Full {
                url,
                username,
                password_file,
                ca_file,
                body,
            } => Self {
                url,
                username,
                password_file,
                ca_file,
                body,
            },
        }
    }
}

/// A digest `read.hash` adds to the stat of each regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Digest {
    Sha256,
    Sha512,
}

impl Read {
    /// Every `read.*-from` entry, as written.
    pub fn from(&self) -> impl Iterator<Item = &String> {
        self.files_from
            .iter()
            .chain(&self.stat_from)
            .chain(&self.statfs_from)
    }

    /// Whether any network probe is listed.
    pub fn probes(&self) -> bool {
        !(self.addr.is_empty() && self.dns.is_empty() && self.http.is_empty())
    }

    /// Whether any source other than a network probe is listed.
    pub fn local(&self) -> bool {
        !(self.files.is_empty()
            && self.stat.is_empty()
            && self.statfs.is_empty()
            && self.exec.is_none()
            && !self.image_config
            && self.from().next().is_none())
    }

    /// The fact paths that name paths to read or stat.
    pub fn named(&self) -> impl Iterator<Item = &str> {
        self.from().map(|entry| template(entry).0)
    }
}

/// A `read.*-from` entry split into its fact pattern and the glob after a `{pattern}`, empty for a bare pattern.
pub fn template(entry: &str) -> (&str, &str) {
    entry
        .strip_prefix('{')
        .and_then(|rest| rest.split_once('}'))
        .unwrap_or((entry, ""))
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
        if self.read.stat_parents && self.read.stat.is_empty() && self.read.stat_from.is_empty() {
            return Err(
                "read.stat-parents stats the directories above stats; list the files under read.stat or read.stat-from"
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
        for entry in self.read.from() {
            let (pattern, suffix) = template(entry);
            if pattern.contains(['{', '}'])
                || !(suffix.is_empty() || suffix.starts_with('/'))
                || (suffix.contains("**") && !suffix.ends_with("/**"))
            {
                return Err(format!(
                    "read pattern {entry:?} is not a fact path, nor {{a fact path}} then a /glob whose ** is its whole last component"
                ));
            }
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
        self.validate_network()?;
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

impl Collector {
    /// Checks `network` against the probes, and each probe target.
    fn validate_network(&self) -> Result<(), String> {
        let read = &self.read;
        match (self.network, read.probes(), read.local()) {
            (true, false, _) => {
                return Err("network is true, but read lists no addr, dns or http".to_owned());
            }
            (false, true, _) => {
                return Err(
                    "read.addr, dns and http reach the network; set network: true".to_owned(),
                );
            }
            (true, true, true) => {
                return Err(
                    "a network collector reads only addr, dns and http; read files in another collector"
                        .to_owned(),
                );
            }
            _ => {}
        }
        for target in &read.addr {
            crate::net::split_addr(target).map_err(|e| format!("read.addr {target:?}: {e}"))?;
        }
        if let Some(name) = read
            .dns
            .iter()
            .find(|n| n.trim().is_empty() || n.contains(' '))
        {
            return Err(format!("read.dns {name:?} is not a hostname"));
        }
        if let Some(kind) = read
            .dns_types
            .iter()
            .find(|t| !DNS_TYPES.contains(&t.as_str()))
        {
            return Err(format!(
                "read.dns-types {kind} is not one of {}",
                DNS_TYPES.join(", ")
            ));
        }
        if let Some(server) = &read.dns_server {
            crate::net::dns_server(server)
                .map_err(|e| format!("read.dns-server {server:?}: {e}"))?;
        }
        for http in &read.http {
            http.validate()
                .map_err(|e| format!("read.http {}: {e}", http.url))?;
        }
        Ok(())
    }
}

impl Http {
    /// Checks the URL and that credentials only travel over TLS.
    pub fn validate(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.url).map_err(|e| format!("not a URL: {e}"))?;
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            other => return Err(format!("scheme {other} is neither http nor https")),
        };
        if url.host_str().is_none_or(str::is_empty) {
            return Err("names no host".to_owned());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "carries credentials in the URL; use username and password-file".to_owned(),
            );
        }
        if self.username.is_some() != self.password_file.is_some() {
            return Err("username and password-file go together".to_owned());
        }
        if self.username.is_some() && !https {
            return Err("sends credentials only over https".to_owned());
        }
        if self.ca_file.is_some() && !https {
            return Err("ca-file verifies TLS, and the URL is not https".to_owned());
        }
        if let Some(path) = self
            .password_file
            .iter()
            .chain(&self.ca_file)
            .find(|p| p.is_relative())
        {
            return Err(format!("{} is not an absolute path", path.display()));
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
