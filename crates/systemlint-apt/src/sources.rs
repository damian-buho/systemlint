// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! apt sources, deb822 and one-line, one subject per paragraph or line, judged against the host release and the cached lists.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::deb822::{self, Stanza};

/// Ubuntu and Debian release codenames, oldest first.
pub const CODENAMES: &[&str] = &[
    "warty", "hoary", "breezy", "dapper", "edgy", "feisty", "gutsy", "hardy", "intrepid", "jaunty",
    "karmic", "lucid", "maverick", "natty", "oneiric", "precise", "quantal", "raring", "saucy",
    "trusty", "utopic", "vivid", "wily", "xenial", "yakkety", "zesty", "artful", "bionic",
    "cosmic", "disco", "eoan", "focal", "groovy", "hirsute", "impish", "jammy", "kinetic", "lunar",
    "mantic", "noble", "oracular", "plucky", "questing", "resolute", "buzz", "rex", "bo", "hamm",
    "slink", "potato", "woody", "sarge", "etch", "lenny", "squeeze", "wheezy", "jessie", "stretch",
    "buster", "bullseye", "bookworm", "trixie", "forky", "duke", "sid",
];

/// The source options that weaken or switch off signature checks.
const INSECURE: &[&str] = &[
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
];

/// One source paragraph or line.
#[derive(Debug, Default)]
struct Source {
    key: String,
    file: String,
    line: u64,
    format: &'static str,
    enabled: bool,
    types: Vec<String>,
    uris: Vec<String>,
    suites: Vec<String>,
    components: Vec<String>,
    architectures: Vec<String>,
    signed_by: Vec<String>,
    insecure: Vec<String>,
    options: Map<String, Value>,
    line_sha256: Option<String>,
}

fn words(text: &str) -> Vec<String> {
    text.split([' ', '\t', '\n', ','])
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

pub use systemlint_formats::mask;

/// The `/var/lib/apt/lists` file name apt derives from `uri` and `suite`, before `InRelease` or `Release`.
pub fn list_name(uri: &str, suite: &str) -> String {
    let rest = match uri.split_once("://") {
        Some((_, rest)) => {
            let authority = rest.split('/').next().unwrap_or_default();
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            format!("{host}{}", &rest[authority.len()..])
        }
        None => uri.split_once(':').map_or(uri, |(_, path)| path).to_owned(),
    };
    let base = if rest.ends_with('/') {
        rest
    } else {
        format!("{rest}/")
    };
    let full = match suite {
        "/" => base,
        flat if flat.ends_with('/') => format!("{base}{flat}"),
        _ => format!("{base}dists/{suite}/"),
    };
    let mut name = String::with_capacity(full.len());
    for byte in full.bytes() {
        match byte {
            b'/' => name.push('_'),
            b'\\' | b'|' | b'{' | b'}' | b'[' | b']' | b'<' | b'>' | b'"' | b'^' | b'~' | b'_'
            | b'=' | b'!' | b'@' | b'#' | b'$' | b'%' | b'&' | b'*' => {
                name.push_str(&format!("%{byte:02x}"))
            }
            b if b <= 0x20 || b >= 0x7f => name.push_str(&format!("%{b:02x}")),
            b => name.push(b as char),
        }
    }
    name
}

/// The first Ubuntu or Debian codename among the words of `text`, such as `questing` in `llvm-toolchain-questing-22`.
pub fn codename(text: &str) -> Option<&'static str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .find_map(|w| {
            CODENAMES
                .iter()
                .find(|c| c.eq_ignore_ascii_case(w))
                .copied()
        })
}

/// `text` with its first release codename word replaced by `to`, as `llvm-toolchain-resolute-22` from `llvm-toolchain-questing-22`.
pub fn recode(text: &str, to: &str) -> Option<String> {
    let mut start = None;
    for (i, c) in text
        .char_indices()
        .chain(std::iter::once((text.len(), '-')))
    {
        if c.is_ascii_alphanumeric() {
            start.get_or_insert(i);
        } else if let Some(s) = start.take().filter(|s| {
            CODENAMES
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&text[*s..i]))
        }) {
            return Some(format!("{}{to}{}", &text[..s], &text[i..]));
        }
    }
    None
}

/// The byte range of the release number `uri` embeds after the distribution `id`, as `26.04` in `xUbuntu_26.04/` or `2404` in `ubuntu2404/`.
pub fn release_in(uri: &str, id: &str) -> Option<(usize, usize)> {
    let lower = uri.to_ascii_lowercase();
    lower.match_indices(id).find_map(|(at, _)| {
        let mut i = at + id.len();
        i += usize::from(lower[i..].starts_with(['_', '/', '-']));
        let digits = |from: usize| lower[from..].bytes().take_while(u8::is_ascii_digit).count();
        let whole = digits(i);
        let end = match (
            whole,
            lower[i + whole..]
                .strip_prefix('.')
                .map(|_| digits(i + whole + 1)),
        ) {
            (0, _) => return None,
            (_, Some(minor)) if minor > 0 => i + whole + 1 + minor,
            _ => i + whole,
        };
        (!lower[end..].starts_with(|c: char| c.is_ascii_alphanumeric())).then_some((i, end))
    })
}

fn deb822_source(
    path: &str,
    stanza: &Stanza,
    diagnose: &mut impl FnMut(Option<u64>, String),
) -> Option<Source> {
    let missing: Vec<&str> = ["Types", "URIs", "Suites"]
        .into_iter()
        .filter(|f| stanza.get(f).is_none_or(|v| v.trim().is_empty()))
        .collect();
    if !missing.is_empty() {
        diagnose(
            Some(stanza.line),
            format!(
                "the paragraph lacks {}, so apt ignores it",
                missing.join(", ")
            ),
        );
        return None;
    }
    let mut source = Source {
        format: "deb822",
        enabled: true,
        line: stanza.line,
        file: path.to_owned(),
        ..Source::default()
    };
    for field in &stanza.fields {
        let name = field.name.to_ascii_lowercase();
        let flag = || deb822::boolean(&field.value);
        match name.as_str() {
            "types" => source.types = words(&field.value),
            "uris" => source.uris = words(&field.value),
            "suites" => source.suites = words(&field.value),
            "components" => source.components = words(&field.value),
            "architectures" => source.architectures = words(&field.value),
            "signed-by" if field.value.contains("BEGIN PGP PUBLIC KEY BLOCK") => {
                source.signed_by = vec!["(inline)".to_owned()]
            }
            "signed-by" => source.signed_by = words(&field.value),
            "enabled" => match flag() {
                Some(enabled) => source.enabled = enabled,
                None => diagnose(
                    Some(stanza.line),
                    format!(
                        "Enabled {:?} is no boolean; apt reads it as yes",
                        field.value
                    ),
                ),
            },
            insecure if INSECURE.contains(&insecure) => {
                if flag() == Some(true) {
                    source.insecure.push(name.clone());
                }
            }
            _ => {
                source
                    .options
                    .insert(name, Value::from(field.value.clone()));
            }
        }
    }
    Some(source)
}

fn one_line_source(
    path: &str,
    number: u64,
    raw: &str,
    diagnose: &mut impl FnMut(Option<u64>, String),
) -> Option<Source> {
    let line = raw.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return None;
    }
    let (kind, mut rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    if kind != "deb" && kind != "deb-src" {
        diagnose(
            Some(number),
            format!("type {kind:?} is neither deb nor deb-src"),
        );
        return None;
    }
    let mut source = Source {
        format: "one-line",
        enabled: true,
        line: number,
        file: path.to_owned(),
        types: vec![kind.to_owned()],
        ..Source::default()
    };
    rest = rest.trim_start();
    if let Some(open) = rest.strip_prefix('[') {
        let Some((options, after)) = open.split_once(']') else {
            diagnose(
                Some(number),
                "an option list [ with no closing ]".to_owned(),
            );
            return None;
        };
        for option in options.split_whitespace() {
            let Some((name, value)) = option.split_once('=') else {
                diagnose(Some(number), format!("option {option:?} has no ="));
                continue;
            };
            let name = name.trim_end_matches(['+', '-']).to_ascii_lowercase();
            match name.as_str() {
                "arch" => source.architectures = words(value),
                "signed-by" => source.signed_by = words(value),
                insecure if INSECURE.contains(&insecure) => {
                    if deb822::boolean(value) == Some(true) {
                        source.insecure.push(name.clone());
                    }
                }
                _ => {
                    source.options.insert(name, Value::from(value));
                }
            }
        }
        rest = after;
    }
    let mut fields = rest.split_whitespace().map(str::to_owned);
    let (Some(uri), Some(suite)) = (fields.next(), fields.next()) else {
        diagnose(
            Some(number),
            "a source line needs a URI and a suite".to_owned(),
        );
        return None;
    };
    (source.uris, source.suites, source.components) = (vec![uri], vec![suite], fields.collect());
    let userinfo = source.uris.iter().any(|u| {
        u.split_once("://")
            .is_some_and(|(_, rest)| rest.split('/').next().unwrap_or_default().contains('@'))
    });
    source.line_sha256 = (!userinfo).then(|| {
        Sha256::digest(raw.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    });
    Some(source)
}

fn parse_file(
    path: &str,
    text: &str,
    diagnose: &mut impl FnMut(Option<u64>, String),
) -> Vec<Source> {
    if path.ends_with(".sources") {
        let (stanzas, problems) = deb822::parse(text);
        for (line, message) in problems {
            diagnose(Some(line), message);
        }
        return stanzas
            .iter()
            .filter_map(|s| deb822_source(path, s, diagnose))
            .collect();
    }
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| one_line_source(path, i as u64 + 1, line, diagnose))
        .collect()
}

fn keyed(mut source: Source) -> Source {
    source.key = format!("{}:{}", source.file, source.line);
    source
}

/// The host’s release codenames from `os.release`, its own first, then the Ubuntu or Debian one it builds on.
fn host_codenames(facts: &BTreeMap<String, Value>) -> Vec<String> {
    let release = facts.get("os.release");
    let mut names: Vec<String> = ["VERSION_CODENAME", "UBUNTU_CODENAME", "DEBIAN_CODENAME"]
        .iter()
        .filter_map(|k| release.and_then(|r| r[k].as_str()))
        .filter(|c| !c.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    names.dedup();
    names
}

/// The host’s distribution `ID` and `VERSION_ID`, when `os.release` names both.
fn host_release(facts: &BTreeMap<String, Value>) -> Option<(String, String)> {
    let release = facts.get("os.release")?;
    let text = |k: &str| {
        release[k]
            .as_str()
            .filter(|v| !v.is_empty())
            .map(str::to_ascii_lowercase)
    };
    Some((text("ID")?, text("VERSION_ID")?))
}

/// One fact per source, keyed `path:line`, with the suites and URIs off the host release and their replacements, the cached lists, duplicates and key conflicts.
pub fn sources(inputs: &[Input], facts: &BTreeMap<String, Value>) -> Reply {
    let mut reply = Reply::default();
    let mut all = Vec::new();
    for input in inputs {
        let Input::File(file) = input else { continue };
        let mut diagnose = |line: Option<u64>, message: String| {
            reply.diagnostics.push(Diagnostic {
                path: file.path.clone(),
                line,
                message,
            })
        };
        match file.content.as_deref() {
            Some(text) => all.extend(
                parse_file(&file.path, text, &mut diagnose)
                    .into_iter()
                    .map(keyed),
            ),
            None => diagnose(None, "not UTF-8 text, skipped".to_owned()),
        }
    }
    let host = host_codenames(facts);
    let distro = host_release(facts);
    if host.is_empty() && !all.is_empty() {
        reply.diagnostics.push(Diagnostic {
            path: "os.release".to_owned(),
            line: None,
            message: "no VERSION_CODENAME, so stale suites are not judged".to_owned(),
        });
    }
    let cached: BTreeMap<&str, (&str, &Value)> = facts
        .get("apt.lists")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(path, fact)| {
            (
                path.rsplit('/').next().unwrap_or(path),
                (path.as_str(), fact),
            )
        })
        .collect();
    let indexes: Vec<BTreeSet<String>> = all
        .iter()
        .map(|s| {
            s.uris
                .iter()
                .flat_map(|u| s.suites.iter().map(move |x| list_name(u, x)))
                .collect()
        })
        .collect();
    let mut targets = vec![BTreeSet::new(); all.len()];
    for (set, s) in targets.iter_mut().zip(&all) {
        let components = if s.components.is_empty() {
            vec![String::new()]
        } else {
            s.components.clone()
        };
        for (t, u, x) in s.types.iter().flat_map(|t| {
            s.uris
                .iter()
                .flat_map(move |u| s.suites.iter().map(move |x| (t, u, x)))
        }) {
            for c in &components {
                set.insert((t.clone(), list_name(u, x), c.clone()));
            }
        }
    }
    let lookup = |name: &str| {
        cached
            .get(format!("{name}InRelease").as_str())
            .or_else(|| cached.get(format!("{name}Release").as_str()))
            .copied()
    };
    for (i, source) in all.iter().enumerate() {
        let mut fact = json!({
            "file": source.file, "line": source.line, "format": source.format, "enabled": source.enabled,
            "types": source.types, "uris": source.uris.iter().map(|u| mask(u)).collect::<Vec<_>>(), "suites": source.suites, "components": source.components,
            "signed-by": source.signed_by, "insecure-options": source.insecure,
        });
        if !source.architectures.is_empty() {
            fact["architectures"] = json!(source.architectures);
        }
        if let Some(sha) = &source.line_sha256 {
            fact["line-sha256"] = json!(sha);
        }
        if !source.options.is_empty() {
            fact["options"] = Value::Object(source.options.clone());
        }
        let found: Vec<(&str, &Value)> =
            indexes[i].iter().filter_map(|name| lookup(name)).collect();
        let cached_name = |suite: &str| {
            source
                .uris
                .iter()
                .find_map(|u| lookup(&list_name(u, suite)))
                .and_then(|(_, f)| f["codename"].as_str())
        };
        let named = |suite: &'_ str| {
            if codename(suite).is_some() {
                Some(suite.to_owned())
            } else {
                cached_name(suite).map(str::to_owned)
            }
        };
        let codenames: Vec<Option<&str>> = source
            .suites
            .iter()
            .map(|suite| codename(suite).or_else(|| cached_name(suite).and_then(codename)))
            .collect();
        fact["codenames"] = json!(codenames.iter().flatten().collect::<BTreeSet<_>>());
        if !host.is_empty() {
            let stale: Vec<&String> = source
                .suites
                .iter()
                .zip(&codenames)
                .filter(|(_, c)| c.is_some_and(|c| !host.iter().any(|h| h == c)))
                .map(|(s, _)| s)
                .collect();
            fact["suggested-suites"] = json!(
                stale
                    .iter()
                    .filter_map(|s| named(s).and_then(|n| recode(&n, &host[0])))
                    .collect::<Vec<_>>()
            );
            fact["stale-suites"] = json!(stale);
        }
        let uris: Vec<String> = source.uris.iter().map(|u| mask(u)).collect();
        let releases: Vec<Option<(usize, usize)>> = uris
            .iter()
            .map(|u| distro.as_ref().and_then(|(id, _)| release_in(u, id)))
            .collect();
        fact["pinned-uris"] = json!(
            uris.iter()
                .zip(&releases)
                .filter(|(_, r)| r.is_none())
                .map(|(u, _)| u)
                .collect::<Vec<_>>()
        );
        if let Some((_, version)) = &distro {
            let stale: Vec<(&String, (usize, usize))> = uris
                .iter()
                .zip(&releases)
                .filter_map(|(u, r)| r.map(|r| (u, r)))
                .filter(|(u, (a, b))| u[*a..*b].replace('.', "") != version.replace('.', ""))
                .collect();
            let replace = |u: &str, (a, b): (usize, usize)| {
                format!(
                    "{}{}{}",
                    &u[..a],
                    if u[a..b].contains('.') {
                        version.clone()
                    } else {
                        version.replace('.', "")
                    },
                    &u[b..]
                )
            };
            fact["suggested-uris"] = json!(
                stale
                    .iter()
                    .map(|(u, r)| replace(u, *r))
                    .collect::<Vec<_>>()
            );
            fact["stale-uris"] = json!(stale.iter().map(|(u, _)| u).collect::<Vec<_>>());
        }
        fact["lists"] = json!(found.iter().map(|(p, _)| p).collect::<Vec<_>>());
        fact["fetched"] = Value::from(found.len() == indexes[i].len());
        fact["expired-lists"] = json!(
            found
                .iter()
                .filter(|(_, f)| f["expired"] == true)
                .map(|(p, _)| p)
                .collect::<Vec<_>>()
        );
        if let Some(age) = found
            .iter()
            .filter_map(|(_, f)| f["age-days"].as_i64())
            .max()
        {
            fact["release-age-days"] = json!(age);
        }
        let others = || {
            all.iter()
                .enumerate()
                .filter(move |(j, o)| *j != i && o.enabled && source.enabled)
        };
        fact["duplicates"] = json!(
            others()
                .filter(|(j, _)| !targets[*j].is_disjoint(&targets[i]))
                .map(|(_, o)| &o.key)
                .collect::<Vec<_>>()
        );
        let keys: BTreeSet<&String> = source.signed_by.iter().collect();
        fact["key-conflicts"] = json!(
            others()
                .filter(|(j, o)| !indexes[*j].is_disjoint(&indexes[i])
                    && o.signed_by.iter().collect::<BTreeSet<_>>() != keys)
                .map(|(_, o)| &o.key)
                .collect::<Vec<_>>()
        );
        reply.facts.insert(source.key.clone(), fact);
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::FileInput;

    fn file(path: &str, content: &str) -> Input {
        Input::File(FileInput {
            path: path.to_owned(),
            content: Some(content.to_owned()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        })
    }

    fn host(codename: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "os.release".to_owned(),
                json!({"VERSION_CODENAME": codename}),
            ),
            ("apt.lists".to_owned(), json!({})),
        ])
    }

    #[test]
    fn list_names_follow_apt() {
        assert_eq!(
            list_name("http://archive.ubuntu.com/ubuntu", "noble"),
            "archive.ubuntu.com_ubuntu_dists_noble_"
        );
        assert_eq!(
            list_name("https://deb.nodesource.com/node_26.x", "nodistro"),
            "deb.nodesource.com_node%5f26.x_dists_nodistro_"
        );
        assert_eq!(
            list_name("https://pkgs.k8s.io/core:/stable:/v1.34/deb/", "/"),
            "pkgs.k8s.io_core:_stable:_v1.34_deb_"
        );
        assert_eq!(
            list_name("https://u:p@h:8443/r/", "flat/"),
            "h:8443_r_flat_"
        );
        assert_eq!(list_name("file:/srv/repo", "x"), "_srv_repo_dists_x_");
    }

    #[test]
    fn passwords_never_reach_the_facts() {
        assert_eq!(
            mask("https://user:s3cret@host/p:a@b"),
            "https://user:[redacted]@host/p:a@b"
        );
        assert_eq!(mask("https://token@host/"), "https://token@host/");
        assert_eq!(mask("cdrom:[x]/"), "cdrom:[x]/");
    }

    #[test]
    fn codenames_are_found_inside_suites() {
        assert_eq!(codename("llvm-toolchain-questing-22"), Some("questing"));
        assert_eq!(codename("noble/mongodb-org/8.0"), Some("noble"));
        assert_eq!(
            (codename("stable"), codename("nodistro"), codename("/")),
            (None, None, None)
        );
    }

    #[test]
    fn a_codename_word_is_replaced_in_place() {
        assert_eq!(
            recode("llvm-toolchain-questing-22", "resolute").as_deref(),
            Some("llvm-toolchain-resolute-22")
        );
        assert_eq!(recode("xenial", "resolute").as_deref(), Some("resolute"));
        assert_eq!(
            recode("bookworm-updates", "trixie").as_deref(),
            Some("trixie-updates")
        );
        assert_eq!(
            (recode("stable", "trixie"), recode("nodistro", "resolute")),
            (None, None)
        );
    }

    #[test]
    fn a_release_number_is_found_after_the_distribution() {
        fn at<'a>(uri: &'a str, id: &str) -> Option<&'a str> {
            release_in(uri, id).map(|(a, b)| &uri[a..b])
        }
        assert_eq!(
            at("https://o.example/crystal/xUbuntu_26.04/", "ubuntu"),
            Some("26.04")
        );
        assert_eq!(
            at("https://n.example/repos/ubuntu2404/x86_64/", "ubuntu"),
            Some("2404")
        );
        assert_eq!(at("https://o.example/Debian_13/", "debian"), Some("13"));
        assert_eq!(at("http://archive.ubuntu.com/ubuntu", "ubuntu"), None);
        assert_eq!(at("https://deb.nodesource.com/node_26.x", "ubuntu"), None);
        assert_eq!(at("https://x.example/ubuntu-26.04beta/", "ubuntu"), None);
    }

    #[test]
    fn stale_suites_and_uris_carry_the_host_value() {
        let mut facts = host("resolute");
        facts.insert(
            "os.release".to_owned(),
            json!({"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION_CODENAME": "resolute"}),
        );
        let list = "deb https://s.example/ xenial main\ndeb https://o.example/xUbuntu_26.04/ /\ndeb https://o.example/xUbuntu_25.10/ /\ndeb https://n.example/ubuntu2204/ /\ndeb https://deb.nodesource.com/node_26.x nodistro main\n";
        let reply = sources(&[file("/e/v.list", list)], &facts);
        let at = |line: u32| &reply.facts[&format!("/e/v.list:{line}")];
        assert_eq!(
            (
                at(1)["stale-suites"].clone(),
                at(1)["suggested-suites"].clone()
            ),
            (json!(["xenial"]), json!(["resolute"]))
        );
        assert_eq!(
            (at(2)["stale-uris"].clone(), at(2)["pinned-uris"].clone()),
            (json!([]), json!([])),
            "the host’s own release is current"
        );
        assert_eq!(
            at(3)["suggested-uris"],
            json!(["https://o.example/xUbuntu_26.04/"])
        );
        assert_eq!(
            at(4)["suggested-uris"],
            json!(["https://n.example/ubuntu2604/"])
        );
        assert_eq!(
            (at(5)["stale-uris"].clone(), at(5)["pinned-uris"].clone()),
            (json!([]), json!(["https://deb.nodesource.com/node_26.x"])),
            "a vendor version stays for review"
        );
    }

    #[test]
    fn deb822_and_one_line_sources_become_subjects() {
        let deb822 = "Types: deb deb-src\nURIs: https://a.example/ubuntu\nSuites: resolute resolute-updates\nComponents: main\nSigned-By: /usr/share/keyrings/a.gpg\nX-Repolib-Name: a\n\nTypes: deb\nURIs: http://b.example/\nSuites: questing\nEnabled: no\nTrusted: yes\n";
        let list = "# off\ndeb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/c.asc allow-insecure=yes] https://c.example/v1.34/deb/ / # tail\n";
        let reply = sources(
            &[file("/e/a.sources", deb822), file("/e/c.list", list)],
            &host("resolute"),
        );
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        let a = &reply.facts["/e/a.sources:1"];
        assert_eq!(a["types"], json!(["deb", "deb-src"]));
        assert_eq!(a["stale-suites"], json!([]));
        assert_eq!(a["options"], json!({"x-repolib-name": "a"}));
        assert_eq!(a["fetched"], false);
        let b = &reply.facts["/e/a.sources:8"];
        assert_eq!(
            (
                b["enabled"].as_bool(),
                b["insecure-options"].clone(),
                b["stale-suites"].clone()
            ),
            (Some(false), json!(["trusted"]), json!(["questing"]))
        );
        let c = &reply.facts["/e/c.list:2"];
        assert_eq!(
            (
                c["format"].as_str(),
                c["suites"].clone(),
                c["components"].clone()
            ),
            (Some("one-line"), json!(["/"]), json!([]))
        );
        assert_eq!(
            (
                c["architectures"].clone(),
                c["signed-by"].clone(),
                c["insecure-options"].clone()
            ),
            (
                json!(["amd64", "arm64"]),
                json!(["/etc/apt/keyrings/c.asc"]),
                json!(["allow-insecure"])
            )
        );
    }

    #[test]
    fn only_a_one_line_source_without_userinfo_carries_its_line_hash() {
        let list = "deb [trusted=yes] https://c.example/ / \r\ndeb https://u:p@d.example/ /\ndeb https://token@e.example/ /\n";
        let reply = sources(
            &[
                file("/e/c.list", list),
                file(
                    "/e/a.sources",
                    "Types: deb\nURIs: https://a.example/\nSuites: /\n",
                ),
            ],
            &host("resolute"),
        );
        let sha = |line: &str| -> String {
            Sha256::digest(line.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        assert_eq!(
            reply.facts["/e/c.list:1"]["line-sha256"],
            json!(sha("deb [trusted=yes] https://c.example/ / ")),
            "the hash covers the line as fix reads it, CR stripped"
        );
        for key in ["/e/c.list:2", "/e/c.list:3", "/e/a.sources:1"] {
            assert!(reply.facts[key].get("line-sha256").is_none(), "{key}");
        }
    }

    #[test]
    fn duplicates_and_key_conflicts_name_the_other_source() {
        let a = "deb [signed-by=/k/a.gpg] https://r.example/ubuntu resolute main\ndeb [signed-by=/k/a.gpg] https://r.example/ubuntu/ resolute main universe\ndeb [signed-by=/k/b.gpg] https://r.example/ubuntu resolute universe\n";
        let off = "Types: deb\nURIs: https://r.example/ubuntu\nSuites: resolute\nComponents: main\nEnabled: no\n";
        let reply = sources(
            &[file("/e/a.list", a), file("/e/off.sources", off)],
            &host("resolute"),
        );
        assert_eq!(
            reply.facts["/e/a.list:1"]["duplicates"],
            json!(["/e/a.list:2"])
        );
        assert_eq!(
            reply.facts["/e/a.list:2"]["duplicates"],
            json!(["/e/a.list:1", "/e/a.list:3"])
        );
        assert_eq!(
            reply.facts["/e/a.list:1"]["key-conflicts"],
            json!(["/e/a.list:3"])
        );
        assert_eq!(reply.facts["/e/off.sources:1"]["duplicates"], json!([]));
    }

    #[test]
    fn cached_lists_give_codename_fetch_state_expiry_and_age() {
        let mut facts = host("trixie");
        facts.insert("apt.lists".to_owned(), json!({
            "/var/lib/apt/lists/deb.debian.org_debian_dists_stable_InRelease": {"codename": "bookworm", "expired": false, "age-days": 3},
            "/var/lib/apt/lists/deb.debian.org_debian_dists_stable-updates_Release": {"codename": "bookworm-updates", "expired": true, "age-days": 40},
        }));
        let reply = sources(
            &[file(
                "/e/d.sources",
                "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: stable stable-updates stable-backports\n",
            )],
            &facts,
        );
        let d = &reply.facts["/e/d.sources:1"];
        assert_eq!(d["codenames"], json!(["bookworm"]));
        assert_eq!(d["stale-suites"], json!(["stable", "stable-updates"]));
        assert_eq!(
            (d["fetched"].as_bool(), d["release-age-days"].as_i64()),
            (Some(false), Some(40))
        );
        assert_eq!(
            d["expired-lists"],
            json!(["/var/lib/apt/lists/deb.debian.org_debian_dists_stable-updates_Release"])
        );
    }

    #[test]
    fn bad_input_is_diagnosed_and_skipped() {
        let reply = sources(
            &[
                file(
                    "/e/x.list",
                    "rpm http://x/ a\ndeb [arch=amd64 http://x/ a\ndeb http://x/\n",
                ),
                file(
                    "/e/y.sources",
                    "Types: deb\nURIs: http://y/\nEnabled: maybe\n\nTypes: deb\nURIs: http://y/\nSuites: a\nEnabled: maybe\n",
                ),
            ],
            &BTreeMap::new(),
        );
        let lines: Vec<_> = reply
            .diagnostics
            .iter()
            .map(|d| (d.path.as_str(), d.line))
            .collect();
        assert_eq!(
            lines,
            [
                ("/e/x.list", Some(1)),
                ("/e/x.list", Some(2)),
                ("/e/x.list", Some(3)),
                ("/e/y.sources", Some(1)),
                ("/e/y.sources", Some(5)),
                ("os.release", None)
            ]
        );
        assert_eq!(reply.facts.len(), 1);
        assert!(reply.facts["/e/y.sources:5"].get("stale-suites").is_none());
    }
}
