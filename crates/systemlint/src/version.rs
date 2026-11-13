// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Version orderings `x-version` compares by scheme: dpkg, SemVer 2.0.0, rpm, apk-tools and pacman.

use std::cmp::Ordering;

/// The epoch, upstream version and revision of a Debian version, or why it is not one.
pub fn parse_deb(text: &str) -> Result<(u64, &str, &str), String> {
    let (epoch, rest) = match text.split_once(':') {
        Some((epoch, rest)) => (
            epoch
                .parse::<u64>()
                .map_err(|_| format!("“{text}” has an epoch that is not a number"))?,
            rest,
        ),
        None => (0, text),
    };
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, ""));
    if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(format!(
            "“{text}” is not a Debian version: its upstream part does not start with a digit"
        ));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || ".+~-:".contains(c);
    if let Some(bad) = rest.chars().find(|c| !allowed(*c)) {
        return Err(format!(
            "“{text}” is not a Debian version: it holds “{bad}”"
        ));
    }
    Ok((epoch, upstream, revision))
}

/// dpkg’s order of `a` against `b`; either failing to parse is an error.
pub fn compare_deb(a: &str, b: &str) -> Result<Ordering, String> {
    let ((ea, ua, ra), (eb, ub, rb)) = (parse_deb(a)?, parse_deb(b)?);
    Ok(ea
        .cmp(&eb)
        .then_with(|| part(ua, ub))
        .then_with(|| part(ra, rb)))
}

fn weight(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        while a.first().is_some_and(|c| !c.is_ascii_digit())
            || b.first().is_some_and(|c| !c.is_ascii_digit())
        {
            let (wa, wb) = (weight(a.first().copied()), weight(b.first().copied()));
            if wa != wb {
                return wa.cmp(&wb);
            }
            (a, b) = (
                a.get(1..).unwrap_or_default(),
                b.get(1..).unwrap_or_default(),
            );
        }
        let digits = |s: &[u8]| s.iter().take_while(|c| c.is_ascii_digit()).count();
        let (na, nb) = (digits(a), digits(b));
        let trim = |s: &[u8]| -> Vec<u8> { s.iter().copied().skip_while(|c| *c == b'0').collect() };
        let (da, db) = (trim(&a[..na]), trim(&b[..nb]));
        let order = da.len().cmp(&db.len()).then_with(|| da.cmp(&db));
        if order != Ordering::Equal {
            return order;
        }
        (a, b) = (&a[na..], &b[nb..]);
    }
    Ordering::Equal
}

/// A version ordering `x-version` names by its `scheme`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Deb,
    Semver,
    Rpm,
    Apk,
    Pacman,
}

impl Scheme {
    /// Every scheme, in the order an error lists them.
    pub const ALL: [Scheme; 5] = [
        Scheme::Deb,
        Scheme::Semver,
        Scheme::Rpm,
        Scheme::Apk,
        Scheme::Pacman,
    ];

    /// The scheme a rule names, or `None`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The name a rule writes.
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Deb => "deb",
            Scheme::Semver => "semver",
            Scheme::Rpm => "rpm",
            Scheme::Apk => "apk",
            Scheme::Pacman => "pacman",
        }
    }

    /// The version kind a message names, with its article.
    pub fn noun(self) -> &'static str {
        match self {
            Scheme::Deb => "a Debian version",
            Scheme::Semver => "a SemVer version",
            Scheme::Rpm => "an RPM version",
            Scheme::Apk => "an Alpine version",
            Scheme::Pacman => "a pacman version",
        }
    }

    /// The scheme’s order of `a` against `b`; either failing to parse is an error.
    pub fn compare(self, a: &str, b: &str) -> Result<Ordering, String> {
        match self {
            Scheme::Deb => compare_deb(a, b),
            Scheme::Semver => compare_semver(a, b),
            Scheme::Rpm => Ok(evr(self, a)?.cmp_rpm(&evr(self, b)?)),
            Scheme::Pacman => Ok(evr(self, a)?.cmp_pacman(&evr(self, b)?)),
            Scheme::Apk => {
                apk_valid(a)?;
                apk_valid(b)?;
                Ok(compare_apk(a.as_bytes(), b.as_bytes()))
            }
        }
    }
}

/// Two digit runs by value, leading zeros ignored, any length.
fn numeric(a: &[u8], b: &[u8]) -> Ordering {
    let (a, b) = (
        &a[a.iter().take_while(|c| **c == b'0').count()..],
        &b[b.iter().take_while(|c| **c == b'0').count()..],
    );
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// The core and pre-release identifiers of a SemVer 2.0.0 version, its build metadata checked and dropped.
fn parse_semver(text: &str) -> Result<(Vec<&str>, Vec<&str>), String> {
    let bad = |why: &str| format!("“{text}” is not a SemVer version: {why}");
    let identifiers = |part: &'_ str| -> bool {
        part.split('.')
            .all(|i| !i.is_empty() && i.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
    };
    let leading_zero =
        |i: &str| i.len() > 1 && i.starts_with('0') && i.bytes().all(|c| c.is_ascii_digit());
    let (rest, build) = text
        .split_once('+')
        .map_or((text, None), |(r, b)| (r, Some(b)));
    if build.is_some_and(|b| !identifiers(b)) {
        return Err(bad(
            "its build metadata holds an empty identifier or a character outside [0-9A-Za-z-]",
        ));
    }
    let (core, pre) = rest
        .split_once('-')
        .map_or((rest, None), |(c, p)| (c, Some(p)));
    let core: Vec<&str> = core.split('.').collect();
    if core.len() != 3
        || core
            .iter()
            .any(|n| n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) || leading_zero(n))
    {
        return Err(bad(
            "it needs MAJOR.MINOR.PATCH, three numbers without leading zeros",
        ));
    }
    let Some(pre) = pre else {
        return Ok((core, Vec::new()));
    };
    if !identifiers(pre) || pre.split('.').any(leading_zero) {
        return Err(bad(
            "its pre-release holds an empty identifier, a character outside [0-9A-Za-z-] or a number with a leading zero",
        ));
    }
    Ok((core, pre.split('.').collect()))
}

/// SemVer 2.0.0 precedence of `a` against `b`, build metadata ignored.
pub fn compare_semver(a: &str, b: &str) -> Result<Ordering, String> {
    let ((ca, pa), (cb, pb)) = (parse_semver(a)?, parse_semver(b)?);
    let core = ca
        .iter()
        .zip(&cb)
        .map(|(x, y)| numeric(x.as_bytes(), y.as_bytes()))
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal);
    let is_number = |i: &str| i.bytes().all(|c| c.is_ascii_digit());
    let pre = match (pa.is_empty(), pb.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => pa
            .iter()
            .zip(&pb)
            .map(|(x, y)| match (is_number(x), is_number(y)) {
                (true, true) => numeric(x.as_bytes(), y.as_bytes()),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => x.cmp(y),
            })
            .find(|o| o.is_ne())
            .unwrap_or_else(|| pa.len().cmp(&pb.len())),
    };
    Ok(core.then(pre))
}

/// An `[epoch:]version[-release]` split as rpm’s and pacman’s `parseEVR` split it.
struct Evr<'a> {
    epoch: Option<&'a str>,
    version: &'a str,
    release: Option<&'a str>,
}

impl Evr<'_> {
    /// rpm’s `rpmverCmp`: a missing epoch is `0`, a missing release sorts first.
    fn cmp_rpm(&self, other: &Self) -> Ordering {
        rpmvercmp(self.epoch.unwrap_or("0"), other.epoch.unwrap_or("0"))
            .then_with(|| rpmvercmp(self.version, other.version))
            .then_with(|| match (self.release, other.release) {
                (Some(a), Some(b)) => rpmvercmp(a, b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            })
    }

    /// pacman’s `alpm_pkg_vercmp`: a missing epoch is `0`, a release compared only when both carry one.
    fn cmp_pacman(&self, other: &Self) -> Ordering {
        let release = match (self.release, other.release) {
            (Some(a), Some(b)) => alpm_vercmp(a, b),
            _ => Ordering::Equal,
        };
        alpm_vercmp(self.epoch.unwrap_or("0"), other.epoch.unwrap_or("0"))
            .then_with(|| alpm_vercmp(self.version, other.version))
            .then(release)
    }
}

/// `text` split into epoch, version and release, or why it is not a version of `scheme`.
fn evr(scheme: Scheme, text: &str) -> Result<Evr<'_>, String> {
    if text.is_empty() || text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "“{text}” is not {}: it is empty or holds a space or control character",
            scheme.noun()
        ));
    }
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (epoch, rest) = match text[digits..].strip_prefix(':') {
        Some(rest) => (Some(if digits == 0 { "0" } else { &text[..digits] }), rest),
        None => (None, text),
    };
    let (version, release) = match text[digits..].rfind('-').map(|i| digits + i) {
        Some(dash) => (
            &rest[..dash - (text.len() - rest.len())],
            Some(&text[dash + 1..]),
        ),
        None => (rest, None),
    };
    Ok(Evr {
        epoch,
        version,
        release,
    })
}

/// The byte at `i`, NUL past the end, as the C loops read a string.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// The end of the digit or letter run starting at `i`.
fn run(s: &[u8], i: usize, digit: bool) -> usize {
    i + s[i..]
        .iter()
        .take_while(|c| {
            if digit {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        })
        .count()
}

/// rpm’s `rpmvercmp`, `~` sorting before everything and `^` after the end only.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a == b {
        return Ordering::Equal;
    }
    let separator = |c: u8| c != 0 && !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    let (mut i, mut j) = (0, 0);
    while at(a, i) != 0 || at(b, j) != 0 {
        while separator(at(a, i)) {
            i += 1;
        }
        while separator(at(b, j)) {
            j += 1;
        }
        let (x, y) = (at(a, i), at(b, j));
        if x == b'~' || y == b'~' {
            if x != b'~' {
                return Ordering::Greater;
            }
            if y != b'~' {
                return Ordering::Less;
            }
            (i, j) = (i + 1, j + 1);
            continue;
        }
        if x == b'^' || y == b'^' {
            if x == 0 {
                return Ordering::Less;
            }
            if y == 0 || x != b'^' {
                return Ordering::Greater;
            }
            if y != b'^' {
                return Ordering::Less;
            }
            (i, j) = (i + 1, j + 1);
            continue;
        }
        if x == 0 || y == 0 {
            break;
        }
        let digit = x.is_ascii_digit();
        let (ei, ej) = (run(a, i, digit), run(b, j, digit));
        if ej == j {
            return if digit {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let order = if digit {
            numeric(&a[i..ei], &b[j..ej])
        } else {
            a[i..ei].cmp(&b[j..ej])
        };
        if order.is_ne() {
            return order;
        }
        (i, j) = (ei, ej);
    }
    match (at(a, i), at(b, j)) {
        (0, 0) => Ordering::Equal,
        (0, _) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// pacman’s `rpmvercmp`: no `~` or `^`, separator lengths compared, a trailing letter run sorting first.
fn alpm_vercmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a == b {
        return Ordering::Equal;
    }
    let (mut i, mut j, mut segment_a, mut segment_b) = (0, 0, 0, 0);
    while at(a, i) != 0 && at(b, j) != 0 {
        while at(a, i) != 0 && !at(a, i).is_ascii_alphanumeric() {
            i += 1;
        }
        while at(b, j) != 0 && !at(b, j).is_ascii_alphanumeric() {
            j += 1;
        }
        if at(a, i) == 0 || at(b, j) == 0 {
            break;
        }
        if i - segment_a != j - segment_b {
            return (i - segment_a).cmp(&(j - segment_b));
        }
        let digit = at(a, i).is_ascii_digit();
        let (ei, ej) = (run(a, i, digit), run(b, j, digit));
        if ej == j {
            return if digit {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let order = if digit {
            numeric(&a[i..ei], &b[j..ej])
        } else {
            a[i..ei].cmp(&b[j..ej])
        };
        if order.is_ne() {
            return order;
        }
        (i, j, segment_a, segment_b) = (ei, ej, ei, ej);
    }
    let (x, y) = (at(a, i), at(b, j));
    if x == 0 && y == 0 {
        Ordering::Equal
    } else if (x == 0 && !y.is_ascii_alphabetic()) || x.is_ascii_alphabetic() {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// apk-tools token kinds, in the order a version may hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Token {
    InitialDigit,
    Digit,
    Letter,
    Suffix,
    SuffixNo,
    CommitHash,
    RevisionNo,
    End,
    Invalid,
}

/// apk-tools suffix ranks; `NONE` (5) separates pre-releases from post-releases.
const SUFFIX_NONE: u8 = 5;

fn suffix_rank(word: &[u8]) -> u8 {
    match word {
        b"alpha" => 1,
        b"beta" => 2,
        b"pre" => 3,
        b"rc" => 4,
        b"cvs" => 6,
        b"svn" => 7,
        b"git" => 8,
        b"hg" => 9,
        b"p" => 10,
        _ => 0,
    }
}

/// apk-tools’ tokenizer over `digit{.digit}…{letter}{_suf{#}}…{~hash}{-r#}`.
struct Tokens<'a> {
    rest: &'a [u8],
    token: Token,
    suffix: u8,
    value: &'a [u8],
}

impl<'a> Tokens<'a> {
    fn new(text: &'a [u8]) -> Self {
        let mut tokens = Tokens {
            rest: text,
            token: Token::InitialDigit,
            suffix: 0,
            value: &[],
        };
        tokens.digits();
        tokens
    }

    fn take(&mut self, keep: impl Fn(&u8) -> bool) -> &'a [u8] {
        let n = self.rest.iter().take_while(|c| keep(c)).count();
        let (taken, rest) = self.rest.split_at(n);
        self.rest = rest;
        taken
    }

    fn digits(&mut self) {
        self.value = self.take(u8::is_ascii_digit);
        if self.value.is_empty() {
            self.token = Token::Invalid;
        }
    }

    fn next(&mut self) {
        let Some(&c) = self.rest.first() else {
            self.token = Token::End;
            return;
        };
        let token = self.token;
        self.token = Token::Invalid;
        match c {
            b'a'..=b'z' if token <= Token::Digit => {
                self.value = &self.rest[..1];
                self.rest = &self.rest[1..];
                self.token = Token::Letter;
            }
            b'.' | b'0'..=b'9'
                if (c == b'.' && token <= Token::Digit)
                    || (c != b'.'
                        && matches!(token, Token::InitialDigit | Token::Digit | Token::Suffix)) =>
            {
                self.rest = if c == b'.' {
                    &self.rest[1..]
                } else {
                    self.rest
                };
                self.token = if token == Token::Suffix {
                    Token::SuffixNo
                } else {
                    Token::Digit
                };
                self.digits();
            }
            b'_' if token <= Token::SuffixNo => {
                self.rest = &self.rest[1..];
                self.value = self.take(u8::is_ascii_lowercase);
                self.suffix = suffix_rank(self.value);
                if self.suffix != 0 {
                    self.token = Token::Suffix;
                }
            }
            b'~' if token < Token::CommitHash => {
                self.rest = &self.rest[1..];
                self.value = self.take(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
                if !self.value.is_empty() {
                    self.token = Token::CommitHash;
                }
            }
            b'-' if token < Token::RevisionNo && self.rest.starts_with(b"-r") => {
                self.rest = &self.rest[2..];
                self.token = Token::RevisionNo;
                self.digits();
            }
            _ => {}
        }
    }

    /// apk-tools’ `token_cmp` for two tokens of the same kind.
    fn cmp_value(&self, other: &Self) -> Ordering {
        match self.token {
            Token::Digit if self.value[0] == b'0' || other.value[0] == b'0' => {
                self.value.cmp(other.value)
            }
            Token::InitialDigit | Token::Digit | Token::SuffixNo | Token::RevisionNo => {
                numeric(self.value, other.value)
            }
            Token::Suffix => self.suffix.cmp(&other.suffix),
            _ => self.value.cmp(other.value),
        }
    }
}

/// apk-tools’ `apk_version_validate`, as an error naming the version.
fn apk_valid(text: &str) -> Result<(), String> {
    let mut tokens = Tokens::new(text.as_bytes());
    while tokens.token < Token::End {
        tokens.next();
    }
    (tokens.token == Token::End).then_some(()).ok_or_else(|| format!("“{text}” is not an Alpine version: apk reads digit{{.digit}}…{{letter}}{{_suffix{{#}}}}…{{~hash}}{{-r#}}"))
}

/// apk-tools’ `apk_version_compare` of two valid versions.
fn compare_apk(a: &[u8], b: &[u8]) -> Ordering {
    let (mut ta, mut tb) = (Tokens::new(a), Tokens::new(b));
    while ta.token == tb.token && ta.token < Token::End {
        let order = ta.cmp_value(&tb);
        if order.is_ne() {
            return order;
        }
        ta.next();
        tb.next();
    }
    if ta.token == tb.token {
        Ordering::Equal
    } else if ta.token == Token::Suffix && ta.suffix < SUFFIX_NONE {
        Ordering::Less
    } else if tb.token == Token::Suffix && tb.suffix < SUFFIX_NONE {
        Ordering::Greater
    } else {
        tb.token.cmp(&ta.token)
    }
}
