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
    #[serde(default)]
    pub containers: bool,
    #[serde(default)]
    pub ttl: Option<u64>,
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
    #[serde(default, rename = "exec-from")]
    pub exec_from: Option<ExecFrom>,
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
    /// A missing stat path lands as `exists: false`, as an inline collector’s does.
    #[serde(default, rename = "stat-absent")]
    pub stat_absent: bool,
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
    #[serde(default, rename = "dns-server-from")]
    pub dns_server_from: Vec<String>,
    #[serde(default)]
    pub http: Vec<Http>,
    #[serde(default)]
    pub order: Order,
    #[serde(default)]
    pub prefer: Option<Prefer>,
}

/// `read.exec-from`: one command per entry of the map at `each` that `keep` admits, `{key}` in `argv` replaced by the entry’s key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecFrom {
    pub each: String,
    #[serde(default)]
    pub keep: Option<serde_json::Map<String, serde_json::Value>>,
    pub argv: Vec<String>,
    /// Runs the op once per command and lands each reply at `into.<key>`.
    #[serde(default)]
    pub split: bool,
}

/// The order `read.files` reach the plugin in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Order {
    /// Sorted by path.
    #[default]
    Path,
    /// As systemd reads a conf directory set: per file name the earliest glob’s match, by name, then each literal path in listed order.
    DropIn,
}

/// Which source answers when a collector reads both files and a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Prefer {
    /// The command’s stdout when it exited 0, else the files.
    Exec,
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
            && !self.runs()
            && !self.image_config
            && self.from().next().is_none())
    }

    /// Whether commands are all it reads, so an absent program leaves it nothing.
    pub fn commands_only(&self) -> bool {
        self.runs()
            && self.files.is_empty()
            && self.stat.is_empty()
            && self.statfs.is_empty()
            && !self.image_config
            && self.from().next().is_none()
            && !self.probes()
    }

    /// Whether a command is listed, plain or one per fact entry.
    pub fn runs(&self) -> bool {
        self.exec.is_some() || self.exec_from.is_some()
    }

    /// The program the first listed command runs.
    pub fn program(&self) -> &str {
        self.exec
            .as_deref()
            .or(self.exec_from.as_ref().map(|e| e.argv.as_slice()))
            .and_then(<[String]>::first)
            .map_or("", String::as_str)
    }

    /// The fact paths that name paths to read or stat, servers to ask, or commands to run.
    pub fn named(&self) -> impl Iterator<Item = &str> {
        self.from()
            .chain(&self.dns_server_from)
            .map(|entry| template(entry).0)
            .chain(self.exec_from.iter().map(|e| e.each.as_str()))
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

/// The `parse:` plugin op, with the text steps before it and the tree steps after it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "serde_json::Value")]
pub struct Parse {
    pub plugin: String,
    pub op: String,
    pub with: serde_json::Map<String, serde_json::Value>,
    pub text: Vec<Text>,
    pub tree: Vec<Tree>,
}

/// A step over each input’s text before the op reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Text {
    /// Only the indented lines under each line starting with this header, up to a blank or unindented line.
    Section(String),
    /// Every line after the first N.
    Skip(usize),
}

/// A step over the op’s facts at `at`, a dotted fact path whose `*` matches any key, none meaning the whole reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub at: Option<String>,
    pub shape: Shape,
}

/// What a tree step does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// A map’s keys split on the character into nested maps.
    Nest(char),
    /// Nested maps joined back into keys on the character.
    Flatten(char),
    /// Each value split on blanks (`None`) or a literal into a list, or into a map of `fields`.
    Split(Option<String>, Option<Vec<String>>),
    /// Each `<integer> <unit>` value into a number of bytes.
    Bytes,
    /// Each `a-b` or `a` list on the separator into `[{from, to}]`.
    Ranges(String),
}

/// One `parse:` list entry as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    plugin: Option<String>,
    op: Option<String>,
    #[serde(default)]
    with: serde_json::Map<String, serde_json::Value>,
    section: Option<String>,
    skip: Option<usize>,
    nest: Option<char>,
    flatten: Option<char>,
    split: Option<String>,
    fields: Option<Vec<String>>,
    unit: Option<String>,
    ranges: Option<String>,
    at: Option<String>,
}

/// The word `split` takes for a run of blanks.
pub const WHITESPACE: &str = "whitespace";

impl TryFrom<serde_json::Value> for Parse {
    type Error = String;

    fn try_from(value: serde_json::Value) -> Result<Self, String> {
        let entries = match value {
            serde_json::Value::Array(items) => items,
            one @ serde_json::Value::Object(_) => vec![one],
            _ => return Err("parse is neither an op nor a list of steps".to_owned()),
        };
        let (mut op, mut text, mut tree) = (None, Vec::new(), Vec::new());
        for (index, entry) in (1..).zip(entries) {
            let entry: Entry =
                serde_json::from_value(entry).map_err(|e| format!("parse step {index}: {e}"))?;
            let step = Step::try_from(entry).map_err(|e| format!("parse step {index}: {e}"))?;
            match (step, &op) {
                (Step::Op(plugin, name, with), None) => op = Some((plugin, name, with)),
                (Step::Op(..), Some(_)) => {
                    return Err(format!(
                        "parse step {index} is a second op; give exactly one"
                    ));
                }
                (Step::Text(t), None) => text.push(t),
                (Step::Text(_), Some(_)) => {
                    return Err(format!(
                        "parse step {index} reads text, so it goes before the op"
                    ));
                }
                (Step::Tree(_), None) => {
                    return Err(format!(
                        "parse step {index} shapes facts, so it goes after the op"
                    ));
                }
                (Step::Tree(t), Some(_)) => tree.push(t),
            }
        }
        let (plugin, op, with) = op.ok_or("parse names no plugin op")?;
        Ok(Self {
            plugin,
            op,
            with,
            text,
            tree,
        })
    }
}

/// One checked `parse:` entry.
enum Step {
    Op(String, String, serde_json::Map<String, serde_json::Value>),
    Text(Text),
    Tree(Tree),
}

impl TryFrom<Entry> for Step {
    type Error = String;

    fn try_from(e: Entry) -> Result<Self, String> {
        let shapes = [
            e.nest.is_some(),
            e.flatten.is_some(),
            e.split.is_some(),
            e.unit.is_some(),
            e.ranges.is_some(),
        ];
        let kinds = usize::from(e.plugin.is_some() || e.op.is_some())
            + usize::from(e.section.is_some())
            + usize::from(e.skip.is_some())
            + shapes.iter().filter(|s| **s).count();
        if kinds != 1 {
            return Err("give exactly one of plugin with op, section, skip, nest, flatten, split, unit, ranges".to_owned());
        }
        if e.fields.is_some() && e.split.is_none() {
            return Err("fields names what split yields; give split".to_owned());
        }
        if !e.with.is_empty() && e.op.is_none() {
            return Err("with belongs to the op".to_owned());
        }
        if e.at.is_some() && !shapes.contains(&true) {
            return Err("at belongs to a tree step".to_owned());
        }
        if let Some(at) = e.at.as_ref().filter(|at| {
            at.split('.')
                .any(|s| s.is_empty() || (s.contains('*') && s != "*"))
        }) {
            return Err(format!(
                "at {at:?} is not a dotted fact path whose wildcards are whole segments"
            ));
        }
        let shape = match (
            e.plugin, e.op, e.section, e.skip, e.nest, e.flatten, e.split, e.unit, e.ranges,
        ) {
            (Some(plugin), Some(op), ..) => return Ok(Self::Op(plugin, op, e.with)),
            (Some(_), None, ..) | (None, Some(_), ..) => {
                return Err("plugin and op go together".to_owned());
            }
            (_, _, Some(header), ..) if header.is_empty() => {
                return Err("section is empty".to_owned());
            }
            (_, _, Some(header), ..) => return Ok(Self::Text(Text::Section(header))),
            (_, _, _, Some(lines), ..) => return Ok(Self::Text(Text::Skip(lines))),
            (_, _, _, _, Some(c), ..) => Shape::Nest(c),
            (_, _, _, _, _, Some(c), ..) => Shape::Flatten(c),
            (.., Some(by), _, _) if by.is_empty() => {
                return Err("split is empty; give whitespace or a literal".to_owned());
            }
            (.., Some(by), _, _) => Shape::Split((by != WHITESPACE).then_some(by), e.fields),
            (.., Some(unit), _) if unit == "bytes" => Shape::Bytes,
            (.., Some(unit), _) => return Err(format!("unit {unit} is not bytes")),
            (.., Some(by)) if by.is_empty() => {
                return Err("ranges is empty; give the separator between ranges".to_owned());
            }
            (.., Some(by)) => Shape::Ranges(by),
            _ => unreachable!("one kind is set"),
        };
        Ok(Self::Tree(Tree { at: e.at, shape }))
    }
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
        if self.read.stat_absent && self.read.stat.is_empty() && self.read.stat_from.is_empty() {
            return Err(
                "read.stat-absent records missing stats; list the files under read.stat or read.stat-from"
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
        if self.read.order == Order::DropIn && self.read.files.is_empty() {
            return Err("read.order drop-in orders files; list them under read.files".to_owned());
        }
        if self.read.prefer.is_some() && (self.read.exec.is_none() || self.read.files.is_empty()) {
            return Err("read.prefer exec chooses between a command and files; give both read.exec and read.files".to_owned());
        }
        let from = self.read.exec_from.as_ref();
        for (field, argv) in [
            ("read.exec", self.read.exec.as_deref()),
            ("read.exec-from argv", from.map(|e| e.argv.as_slice())),
        ] {
            match argv {
                Some([]) => return Err(format!("{field} is empty; give an argv list")),
                Some([program, ..]) if !program.starts_with('/') || program.contains('{') => {
                    return Err(format!(
                        "{field} program {program} is not an absolute path; PATH is never searched"
                    ));
                }
                _ => {}
            }
        }
        if let Some(from) = from {
            if from
                .each
                .split('.')
                .any(|s| s.is_empty() || s.contains('*'))
                || overlaps(&from.each, &self.into)
            {
                return Err(format!(
                    "read.exec-from each {:?} is not a dotted fact path without wildcards that this collector does not write",
                    from.each
                ));
            }
            if let Some(keep) = &from.keep {
                crate::judge::schema(keep)
                    .map_err(|e| format!("read.exec-from keep is no valid schema: {e}"))?;
            }
            if from.split && (self.read.exec.is_some() || !self.read.commands_only()) {
                return Err(
                    "read.exec-from split lands one reply per key; read nothing else".to_owned(),
                );
            }
        }
        for entry in self.read.from().chain(&self.read.dns_server_from) {
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
        match (
            read.dns_server_from.as_slice(),
            &read.dns_server,
            read.dns.is_empty(),
        ) {
            ([], _, _) => {}
            (_, Some(_), _) => {
                return Err(
                    "read.dns-server and dns-server-from both name servers; keep one".to_owned(),
                );
            }
            (_, None, true) => {
                return Err(
                    "read.dns-server-from asks each named server the read.dns names; list one"
                        .to_owned(),
                );
            }
            (from, None, false) => {
                if let Some(entry) = from.iter().find(|e| e.contains(['{', '}'])) {
                    return Err(format!(
                        "read.dns-server-from {entry:?} is a fact path, never a {{template}}"
                    ));
                }
            }
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
