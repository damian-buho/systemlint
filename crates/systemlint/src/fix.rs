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
    /// Masks the subject unit through `systemctl mask`, `--now` on the live host, `--root` otherwise.
    Mask,
    /// Sets one key of a file with no drop-in directory to a value the core lists.
    #[serde(rename = "set-key")]
    SetKey(SetKey),
}

/// A key of a whitespace-separated file the last line of wins, set to `value` on every line naming it, or on a new one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetKey {
    pub file: KeyFile,
    pub key: String,
    pub value: String,
    /// The value the lint read, none when no line set it, which the file must still hold.
    #[serde(skip)]
    pub was: Option<String>,
}

/// A file a `set-key` may change, each with the keys and values it may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeyFile {
    /// `/etc/login.defs`, for the keys in [`LOGIN_DEFS`].
    LoginDefs,
}

/// The login.defs keys a `set-key` may write, each with the values that only take something away.
const LOGIN_DEFS: &[(&str, &[&str])] = &[
    ("UMASK", &["027", "077"]),
    ("ENCRYPT_METHOD", &["SHA512", "YESCRYPT"]),
];

impl KeyFile {
    /// Its directory and name.
    fn place(self) -> (&'static str, &'static str) {
        match self {
            Self::LoginDefs => ("/etc", "login.defs"),
        }
    }

    /// Its path.
    pub fn path(self) -> String {
        let (dir, name) = self.place();
        format!("{dir}/{name}")
    }
}

impl SetKey {
    /// It holding the value of its key in `fact`, the map the lint judged, as the value the file must still hold.
    pub fn read_from(&self, fact: Option<&serde_json::Value>) -> Self {
        let was = fact
            .and_then(|v| v.get(&self.key))
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned));
        log::debug!("set-key {}: the lint read {was:?}", self.key);
        Self {
            was,
            ..self.clone()
        }
    }

    /// The value a live line of `text` sets its key to, the last one winning, none when no line does.
    pub fn current<'a>(&self, text: &'a str) -> Option<&'a str> {
        text.lines().rev().find_map(|l| {
            let mut words = l.split_whitespace();
            (words.next() == Some(self.key.as_str())).then(|| words.next().unwrap_or_default())
        })
    }

    /// `text` with every live line of its key set to its value, or that line added when none is.
    pub fn applied(&self, text: &str) -> String {
        let line = format!("{} {}", self.key, self.value);
        let named = |l: &str| l.split_whitespace().next() == Some(self.key.as_str());
        let mut out: String = text
            .split_inclusive('\n')
            .map(|l| match named(l) {
                true => format!("{line}\n"),
                false => l.to_owned(),
            })
            .collect();
        if self.current(text).is_none() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out += &format!("{line}\n");
        }
        out
    }
}

/// Where a mask link goes.
const UNITS: &str = "/etc/systemd/system";

/// The systemctl that masks and stops a unit on the live host.
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// The unit types a mask may name.
const UNIT_TYPES: [&str; 8] = [
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".target",
    ".mount",
    ".automount",
    ".swap",
];

/// The unit a subject or mask path ends in, none when it holds anything systemd never puts in a unit name.
pub fn unit_of(subject: &str) -> Option<&str> {
    let unit = subject.rsplit('/').next()?;
    let named = unit.len() <= 255
        && !unit.starts_with(['.', '-'])
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":_.@-\\".contains(c))
        && UNIT_TYPES
            .iter()
            .any(|t| unit.len() > t.len() && unit.ends_with(t));
    log::debug!("unit of {subject:?}: {unit:?}, named {named}");
    named.then_some(unit)
}

/// A drop-in file: the directory it goes in, the name it takes after `<order>-systemlint-`, and its lines.
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
    /// `/etc/sysctl.d`, for the kernel settings in [`SYSCTL`] at their hardened values, loaded at once on the live host.
    Sysctl,
    /// `/etc/sudoers.d`, for the Defaults in [`SUDOERS_LINES`], each file passing `visudo --check` before it takes its name.
    Sudoers,
}

/// The sudo Defaults a drop-in may write, each adding a safeguard.
const SUDOERS_LINES: [&str; 2] = ["Defaults use_pty", "Defaults logfile=\"/var/log/sudo.log\""];

/// The visudo that checks a sudoers drop-in before it takes its name.
const VISUDO: &str = "/usr/sbin/visudo";

/// The sysctl program that loads a drop-in into the running kernel.
const SYSCTL_PROGRAM: &str = "/usr/sbin/sysctl";

/// The kernel settings a sysctl drop-in may write, `*` one interface, each with the values that only take something away.
const SYSCTL: &[(&str, &[&str])] = &[
    ("dev.tty.ldisc_autoload", &["0"]),
    ("fs.protected_fifos", &["1", "2"]),
    ("fs.protected_hardlinks", &["1"]),
    ("fs.protected_regular", &["1", "2"]),
    ("fs.protected_symlinks", &["1"]),
    ("fs.suid_dumpable", &["0"]),
    ("kernel.dmesg_restrict", &["1"]),
    ("kernel.kptr_restrict", &["1", "2"]),
    ("kernel.perf_event_paranoid", &["2", "3"]),
    ("kernel.randomize_va_space", &["2"]),
    ("kernel.sysrq", &["0"]),
    ("kernel.unprivileged_bpf_disabled", &["1", "2"]),
    ("kernel.yama.ptrace_scope", &["1", "2", "3"]),
    ("net.ipv4.conf.*.accept_redirects", &["0"]),
    ("net.ipv4.conf.*.accept_source_route", &["0"]),
    ("net.ipv4.conf.*.log_martians", &["1"]),
    ("net.ipv4.conf.*.route_localnet", &["0"]),
    ("net.ipv4.conf.*.rp_filter", &["1"]),
    ("net.ipv4.conf.*.secure_redirects", &["0"]),
    ("net.ipv4.conf.*.send_redirects", &["0"]),
    ("net.ipv4.icmp_echo_ignore_broadcasts", &["1"]),
    ("net.ipv4.icmp_ignore_bogus_error_responses", &["1"]),
    ("net.ipv4.icmp_ratemask", &["88089"]),
    ("net.ipv4.tcp_rfc1337", &["1"]),
    ("net.ipv4.tcp_syncookies", &["1"]),
    ("net.ipv6.conf.*.accept_redirects", &["0"]),
    ("net.ipv6.conf.*.accept_source_route", &["0"]),
];

/// The sysctl key a drop-in may set to a list of ports, which a later file replaces whole, so its one line holds every port.
const RESERVED_PORTS: &str = "net.ipv4.ip_local_reserved_ports";

/// The only fact a drop-in line may name: the ports already reserved, which its line keeps.
const RESERVED_FACT: &str = "{facts.sysctl.settings.net.ipv4.ip_local_reserved_ports}";

/// Whether `value` is a comma list of ports and `a-b` port ranges, as `ip_local_reserved_ports` takes them.
fn ports(value: &str) -> bool {
    let port = |p: &str| p.parse::<u16>().is_ok_and(|n| n > 0);
    value.split(',').all(|item| match item.split_once('-') {
        Some((a, b)) => port(a) && port(b) && a.parse::<u16>().ok() <= b.parse::<u16>().ok(),
        None => port(item),
    })
}

/// `line` with a port list’s repeated and empty items dropped, any other line as it is.
fn listed(line: &str) -> String {
    let Some(value) = line
        .strip_prefix(RESERVED_PORTS)
        .and_then(|v| v.strip_prefix(" = "))
    else {
        return line.to_owned();
    };
    let mut items: Vec<&str> = Vec::new();
    for item in value.split(',').filter(|i| !i.is_empty()) {
        if !items.contains(&item) {
            items.push(item);
        }
    }
    format!("{RESERVED_PORTS} = {}", items.join(","))
}

/// The key of a sysctl `key = value` line, which a later line of the same key replaces.
fn sysctl_key(line: &str) -> Option<&str> {
    line.split_once(" = ").map(|(key, _)| key)
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
            Self::Sysctl => "/etc/sysctl.d",
            Self::Sudoers => "/etc/sudoers.d",
        }
    }

    /// The name suffix of its drop-ins: sudo skips a name holding a dot.
    fn suffix(self) -> &'static str {
        match self {
            Self::Sudoers => "",
            _ => ".conf",
        }
    }

    /// The mode of its drop-ins, 0440 for sudoers as visudo makes them.
    fn mode(self) -> u32 {
        match self {
            Self::Sudoers => 0o440,
            _ => 0o644,
        }
    }

    /// The name prefix that orders its drop-ins: apt lets the last file read win, so its own reads last.
    fn order(self) -> u8 {
        match self {
            Self::Modprobe => 60,
            Self::Apt | Self::Sysctl | Self::Sudoers => 99,
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
            (Self::Sudoers, _) => SUDOERS_LINES.contains(&line),
            (Self::Sysctl, [key, "=", value]) if *key == RESERVED_PORTS => ports(value),
            (Self::Sysctl, [key, "=", value]) => SYSCTL
                .iter()
                .any(|(k, values)| values.contains(value) && same_key(k, key)),
            _ => false,
        }
    }
}

/// Whether the sysctl `key` is `pattern`, whose `*` stands for one segment of letters, digits, `_` and `-`.
fn same_key(pattern: &str, key: &str) -> bool {
    let (mut want, mut got) = (pattern.split('.'), key.split('.'));
    loop {
        match (want.next(), got.next()) {
            (None, None) => return true,
            (Some("*"), Some(g))
                if !g.is_empty()
                    && g.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c)) => {}
            (Some(w), Some(g)) if w == g => {}
            _ => return false,
        }
    }
}

/// What a drop-in’s `{subject}` stands for when its lines are checked at load, as an interface name.
const SUBJECT_EXAMPLE: &str = "eth0";

impl DropIn {
    /// It with each `{subject}` filled from `subject`, none when the subject holds anything but letters, digits, `_` and `-`.
    pub fn for_subject(&self, subject: &str) -> Option<Self> {
        if !self.lines.iter().any(|l| l.contains("{subject}")) {
            return Some(self.clone());
        }
        let plain = !subject.is_empty()
            && subject
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c));
        log::debug!(
            "drop-in {} for subject {subject:?}: plain {plain}",
            self.name
        );
        plain.then(|| {
            let mut lines: Vec<String> = Vec::new();
            for line in self.lines.iter().map(|l| l.replace("{subject}", subject)) {
                if !lines.contains(&line) {
                    lines.push(line);
                }
            }
            Self {
                lines,
                ..self.clone()
            }
        })
    }

    /// The command that loads it into the running kernel, a sysctl drop-in’s only.
    fn loading(&self) -> Option<String> {
        (self.into == Directory::Sysctl).then(|| format!("sysctl --load={}", self.path()))
    }

    /// The command that checks it, a sudoers drop-in’s only.
    fn checking(&self) -> Option<String> {
        (self.into == Directory::Sudoers).then(|| {
            let path = quote(&self.path());
            format!("chmod 0440 {path} && visudo --check --file={path}")
        })
    }

    /// The file it writes.
    pub fn path(&self) -> String {
        format!(
            "{}/{}-systemlint-{}{}",
            self.into.path(),
            self.into.order(),
            self.name,
            self.into.suffix()
        )
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
        let each = self.lines.iter().any(|l| l.contains("{subject}"));
        let list = self
            .lines
            .iter()
            .any(|l| l.starts_with(RESERVED_PORTS) && l.contains("{subject}"));
        let lines = self
            .lines
            .iter()
            .map(|l| match l.starts_with(RESERVED_PORTS) {
                true => l.replace("{subject}", "<ports>"),
                false => l.replace("{subject}", "<name>"),
            })
            .collect();
        let what = if list {
            format!(
                "Write {these} to “{}”, “<ports>” standing for every port listed, joined by commas:",
                self.path()
            )
        } else if each {
            format!(
                "Write {these} to “{}”, the “<name>” line once for each one listed:",
                self.path()
            )
        } else {
            format!("Write {these} to “{}”:", self.path())
        };
        let mut steps = vec![Step::Say(what), Step::Show(Shown::Lines(lines))];
        if let Some(command) = self.checking() {
            steps.push(Step::Say(
                "Make it read-only, as sudo expects, and check it:".to_owned(),
            ));
            steps.push(Step::Show(Shown::Run(command)));
        }
        if let Some(command) = self.loading() {
            steps.push(Step::Say("Load it into the running kernel:".to_owned()));
            steps.push(Step::Show(Shown::Run(command)));
        }
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
                let example = |l: &str| {
                    let subject = match l.starts_with(RESERVED_PORTS) {
                        true => "1",
                        false => SUBJECT_EXAMPLE,
                    };
                    l.replace(RESERVED_FACT, "1").replace("{subject}", subject)
                };
                match drop.lines.iter().find(|l| !drop.into.admits(&example(l))) {
                    Some(line) => Err(format!(
                        "remedy drop-in line {line:?} is not one that only turns something off in {}",
                        drop.into.path()
                    )),
                    None => Ok(()),
                }
            }
            Self::Mask => Ok(()),
            Self::SetKey(set) => {
                let listed = match set.file {
                    KeyFile::LoginDefs => LOGIN_DEFS,
                };
                match listed.iter().find(|(k, _)| *k == set.key) {
                    Some((_, values)) if values.contains(&set.value.as_str()) => Ok(()),
                    _ => Err(format!(
                        "remedy set-key {} {}: not a key and value that only take something away in {}",
                        set.key,
                        set.value,
                        set.file.path()
                    )),
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
                let drop = drop.for_subject(subject).unwrap_or_else(|| drop.clone());
                let lines: Vec<String> = drop.lines.iter().map(|l| quote(l)).collect();
                let written = format!(
                    "printf '%s\\n' {} > {}",
                    lines.join(" "),
                    quote(&drop.path())
                );
                match drop
                    .unloading()
                    .or_else(|| drop.loading())
                    .or_else(|| drop.checking())
                {
                    Some(command) => format!("{written} && {command}"),
                    None => written,
                }
            }
            Self::Mask => match unit_of(subject) {
                Some(unit) => format!("systemctl mask --now {}", quote(unit)),
                None => format!("# no unit named in {}", quote(subject)),
            },
            Self::SetKey(set) => {
                let path = match subject.starts_with('/') {
                    true => subject.to_owned(),
                    false => set.file.path(),
                };
                let line = format!("{} {}", set.key, set.value);
                match set.was {
                    Some(_) => format!(
                        "sed --in-place {} {}",
                        quote(&format!("s/^{}[[:space:]].*/{line}/", set.key)),
                        quote(&path)
                    ),
                    None => format!("echo {} >> {}", quote(&line), quote(&path)),
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
                Remedy::Mask => (format!("{UNITS}/{}", unit_of(&subject)?), None),
                Remedy::SetKey(set) => (set.file.path(), None),
                _ => (subject.clone(), None),
            };
            let remedy = match remedy {
                Remedy::DropIn(drop) => {
                    let drop = drop.for_subject(&subject)?;
                    let lines = drop
                        .lines
                        .iter()
                        .map(|l| listed(&crate::judge::with_facts(l, document, &c.subject, "")))
                        .collect();
                    Remedy::DropIn(DropIn { lines, ..drop })
                }
                Remedy::SetKey(set) => {
                    Remedy::SetKey(set.read_from(rule.subject_value(document, &c.subject, 0)))
                }
                other => (*other).clone(),
            };
            Some(Change {
                rule: c.rule.clone(),
                path,
                line,
                remedy,
            })
        })
        .filter(|c| c.path.starts_with('/'))
        .collect();
    let key = |c: &Change| (c.path.clone(), c.line.clone(), c.remedy.command(""));
    changes.sort_by_key(key);
    changes.dedup_by(|a, b| match (&a.remedy, &mut b.remedy) {
        (Remedy::DropIn(later), Remedy::DropIn(kept)) if a.path == b.path => {
            log::debug!(
                "{}: one write, unload {}",
                a.path,
                later.unload || kept.unload
            );
            kept.unload |= later.unload;
            for line in &later.lines {
                let same = kept.lines.iter().position(|k| {
                    k.starts_with(RESERVED_PORTS) && sysctl_key(k) == sysctl_key(line)
                });
                match same {
                    Some(at) => {
                        let tail = line.split_once(" = ").map_or("", |(_, v)| v);
                        kept.lines[at] = listed(&format!("{},{tail}", kept.lines[at]));
                    }
                    None if !kept.lines.contains(line) => kept.lines.push(line.clone()),
                    None => {}
                }
            }
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
        Remedy::Mask => return mask(root, change),
        Remedy::SetKey(set) => return set_key(root, set),
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
        Remedy::Mask => mask(root, change),
        Remedy::SetKey(set) => set_key(root, set),
    }
}

/// Sets `set`’s key in its file, refusing when the file no longer holds the value the lint read.
fn set_key(root: &Root, set: &SetKey) -> Result<Applied, std::io::Error> {
    let path = set.file.path();
    let file = root.open_for_change(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > crate::runner::OUTPUT_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file systemlint rewrites",
        ));
    }
    let mut held = String::new();
    file.take(crate::runner::OUTPUT_CAP)
        .read_to_string(&mut held)?;
    let current = set.current(&held);
    log::debug!(
        "{path}: {} is {current:?}, the lint read {:?}, wanted {}",
        set.key,
        set.was,
        set.value
    );
    let shown = |v: Option<&str>| format!("{} {}", set.key, v.unwrap_or("unset"));
    if current == Some(set.value.as_str()) {
        return Ok(None);
    }
    if current != set.was.as_deref() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} changed since the lint, so lint again before fixing",
                set.key
            ),
        ));
    }
    let (dir, name) = set.file.place();
    let check = |_: &std::path::Path| Ok(());
    root.replace(
        dir,
        name,
        &set.applied(&held),
        meta.mode() & 0o7777,
        &held,
        &check,
    )?;
    Ok(Some((shown(current), shown(Some(&set.value)))))
}

/// Masks the unit `change` names through systemctl, stopping it too on the live root.
fn mask(root: &Root, change: &Change) -> Result<Applied, std::io::Error> {
    let unit = unit_of(&change.path)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "it names no unit"))?;
    let live = root.path() == std::path::Path::new("/");
    let at = format!("--root={}", root.path().display());
    let args = match live {
        true => ["mask", "--now", "--", unit],
        false => [at.as_str(), "mask", "--", unit],
    };
    let output = crate::runner::run(
        std::path::Path::new(SYSTEMCTL),
        &args,
        None,
        UNLOAD_TIMEOUT,
        crate::runner::OUTPUT_CAP,
        None,
    )
    .map_err(std::io::Error::other)?;
    log::debug!("systemctl {}: exit {}", args.join(" "), output.code());
    if output.code() != 0 {
        let answer = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(std::io::Error::other(format!(
            "systemctl answered “{answer}”"
        )));
    }
    let after = if live { "masked and stopped" } else { "masked" };
    Ok(Some(("unmasked".to_owned(), after.to_owned())))
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
    write(root, drop)
        .and_then(|w| unload(root, drop, w))
        .and_then(|w| load(root, drop, w))
}

/// Loads a sysctl drop-in into the running kernel, only on the live root, adding what it did to `written`.
fn load(root: &Root, drop: &DropIn, written: Applied) -> Result<Applied, std::io::Error> {
    let live = root.path() == std::path::Path::new("/");
    log::debug!(
        "{}: load {}, live root {live}",
        drop.path(),
        drop.into == Directory::Sysctl
    );
    if drop.into != Directory::Sysctl || !live {
        return Ok(written);
    }
    let path = format!("--load={}", drop.path());
    let output = crate::runner::run(
        std::path::Path::new(SYSCTL_PROGRAM),
        &[path.as_str()],
        None,
        UNLOAD_TIMEOUT,
        crate::runner::OUTPUT_CAP,
        None,
    )
    .map_err(std::io::Error::other)?;
    log::debug!("sysctl {path}: exit {}", output.code());
    let (before, after) = written.unwrap_or(("unchanged".to_owned(), "unchanged".to_owned()));
    if output.code() != 0 {
        let answer = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Ok(Some((
            before,
            format!("{after}, not loaded until the next boot (sysctl answered “{answer}”)"),
        )));
    }
    Ok(Some((before, format!("{after}, loaded"))))
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

/// Writes `drop` as a new file, adding its missing lines to one holding only lines its directory admits, refusing one that holds anything else.
fn write(root: &Root, drop: &DropIn) -> Result<Applied, std::io::Error> {
    let path = drop.path();
    let text = drop.text();
    let name = path.rsplit('/').next().unwrap_or_default();
    let check = |path: &std::path::Path| checked(drop, path);
    match root.write_new(drop.into.path(), name, &text, drop.into.mode(), &check) {
        Ok(()) => {
            log::debug!("{path}: written, {} lines", drop.lines.len());
            Ok(Some(("absent".to_owned(), "written".to_owned())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut held = String::new();
            root.open_for_change(&path)?
                .take(crate::runner::OUTPUT_CAP)
                .read_to_string(&mut held)?;
            let lines: Vec<&str> = held.lines().collect();
            let admitted = held.ends_with('\n') && lines.iter().all(|l| drop.into.admits(l));
            let missing: Vec<&String> = drop
                .lines
                .iter()
                .filter(|l| !lines.contains(&l.as_str()))
                .collect();
            log::debug!(
                "{path}: exists with {} lines, all admitted {admitted}, {} missing",
                lines.len(),
                missing.len()
            );
            if missing.is_empty() && admitted {
                return Ok(None);
            }
            if !admitted {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "it exists with other lines, so systemlint leaves it",
                ));
            }
            let replaced = |l: &str| {
                drop.into == Directory::Sysctl
                    && missing
                        .iter()
                        .any(|m| sysctl_key(m).is_some() && sysctl_key(m) == sysctl_key(l))
            };
            let kept: String = lines
                .iter()
                .filter(|l| !replaced(l))
                .map(|l| format!("{l}\n"))
                .collect();
            let merged: String = missing.iter().fold(kept, |t, l| format!("{t}{l}\n"));
            root.replace(
                drop.into.path(),
                name,
                &merged,
                drop.into.mode(),
                &held,
                &check,
            )?;
            let count = |n: usize| format!("{n} line{}", if n == 1 { "" } else { "s" });
            Ok(Some((count(lines.len()), count(merged.lines().count()))))
        }
        Err(e) => Err(e),
    }
}

/// Passes a sudoers drop-in at `path` through `visudo --check`, and any other at once.
fn checked(drop: &DropIn, path: &std::path::Path) -> Result<(), std::io::Error> {
    if drop.into != Directory::Sudoers {
        return Ok(());
    }
    let file = format!("--file={}", path.display());
    let output = crate::runner::run(
        std::path::Path::new(VISUDO),
        &["--check", file.as_str()],
        None,
        UNLOAD_TIMEOUT,
        crate::runner::OUTPUT_CAP,
        None,
    )
    .map_err(|e| std::io::Error::other(format!("visudo {e}")))?;
    log::debug!("visudo --check {file}: exit {}", output.code());
    if output.code() != 0 {
        let answer = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(std::io::Error::other(format!(
            "visudo refused it, so systemlint writes nothing: “{answer}”"
        )));
    }
    Ok(())
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
