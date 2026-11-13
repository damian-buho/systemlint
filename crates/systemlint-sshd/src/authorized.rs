// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `AuthorizedKeysFile` paths sshd may read for each local account, `Match` blocks and `%` tokens resolved.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::config::{Block, Raw};

/// The keyword whose paths this module resolves.
const KEYWORD: &str = "authorizedkeysfile";

/// Whether a `Match` line applies to every connection of one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    Always,
    Sometimes,
    Never,
}

/// One local account as sshd sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u64,
    pub home: String,
    pub groups: Vec<String>,
}

/// `ssh.authorized-key-files`: per account, every absolute path sshd may read keys from, in its order.
pub fn files(
    inputs: &[Input],
    facts: &BTreeMap<String, Value>,
) -> std::result::Result<Reply, String> {
    let loaded = crate::load(inputs, facts)?;
    let mut reply = loaded.reply;
    if loaded.source == "none" {
        return Ok(reply);
    }
    for account in accounts(facts)? {
        let mut paths: Vec<String> = Vec::new();
        for value in values(&loaded.global, &loaded.blocks, &account) {
            for word in value.split_whitespace().filter(|w| *w != "none") {
                match expand(word, &account) {
                    Ok(path) if !paths.contains(&path) => paths.push(path),
                    Ok(_) => {}
                    Err(message) => reply.diagnostics.push(Diagnostic {
                        path: format!("{KEYWORD} {word}"),
                        line: None,
                        message,
                    }),
                }
            }
        }
        reply.facts.insert(account.name, Value::from(paths));
    }
    Ok(reply)
}

/// The `AuthorizedKeysFile` values a connection of `account` may get: each block that may apply up to one that always does, else the global one too.
pub fn values<'a>(global: &'a Raw, blocks: &'a [Block], account: &Account) -> Vec<&'a str> {
    let mut out = Vec::new();
    for block in blocks {
        let Some(value) = block.raw.get(KEYWORD).and_then(|v| v.first()) else {
            continue;
        };
        match applies(&block.criteria, account) {
            Applies::Never => {}
            Applies::Sometimes => out.push(value.as_str()),
            Applies::Always => {
                out.push(value.as_str());
                return out;
            }
        }
    }
    out.extend(
        global
            .get(KEYWORD)
            .and_then(|v| v.first())
            .map(String::as_str),
    );
    out
}

/// Judges one `Match` line for `account`: `User` and `Group` decide, any criterion about the connection leaves it open.
pub fn applies(criteria: &str, account: &Account) -> Applies {
    let mut words = criteria
        .split_whitespace()
        .flat_map(|w| match w.split_once('=') {
            Some((k, v)) => vec![k, v],
            None => vec![w],
        });
    let mut verdict = Applies::Always;
    while let Some(word) = words.next() {
        let one = match word.to_ascii_lowercase().as_str() {
            "all" => Applies::Always,
            "invalid-user" => Applies::Never,
            "user" => decided(words.next().is_some_and(|p| listed(&account.name, p))),
            "group" => decided(
                words
                    .next()
                    .is_some_and(|p| account.groups.iter().any(|g| listed(g, p))),
            ),
            _ => {
                words.next();
                Applies::Sometimes
            }
        };
        verdict = match (verdict, one) {
            (Applies::Never, _) | (_, Applies::Never) => Applies::Never,
            (Applies::Sometimes, _) | (_, Applies::Sometimes) => Applies::Sometimes,
            _ => Applies::Always,
        };
    }
    verdict
}

// A decided criterion.
fn decided(yes: bool) -> Applies {
    match yes {
        true => Applies::Always,
        false => Applies::Never,
    }
}

/// sshd’s `match_pattern_list`: a negated pattern matching refuses, else any plain one matching accepts.
pub fn listed(name: &str, list: &str) -> bool {
    let mut positive = false;
    for pattern in list.split(',') {
        match pattern.strip_prefix('!') {
            Some(negated) if wildcard(name.as_bytes(), negated.as_bytes()) => return false,
            Some(_) => {}
            None => positive |= wildcard(name.as_bytes(), pattern.as_bytes()),
        }
    }
    positive
}

// `*` any run, `?` one byte, the rest literal.
fn wildcard(name: &[u8], pattern: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|i| wildcard(&name[i..], rest)),
        Some((b'?', rest)) => !name.is_empty() && wildcard(&name[1..], rest),
        Some((c, rest)) => name.first() == Some(c) && wildcard(&name[1..], rest),
    }
}

/// One `AuthorizedKeysFile` word as sshd expands it: `%%`, `%h`, `%u`, `%U`, then a relative path below the home directory.
pub fn expand(word: &str, account: &Account) -> std::result::Result<String, String> {
    let mut out = String::new();
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(&account.home),
            Some('u') => out.push_str(&account.name),
            Some('U') => out.push_str(&account.uid.to_string()),
            other => {
                return Err(format!(
                    "%{} is a token sshd does not expand here, so it refuses the path",
                    other.map(String::from).unwrap_or_default()
                ));
            }
        }
    }
    match out.starts_with('/') {
        true => Ok(out),
        false => Ok(format!("{}/{out}", account.home.trim_end_matches('/'))),
    }
}

/// The accounts of `accounts.passwd`, each with its primary group and the groups listing it from `accounts.group`.
pub fn accounts(facts: &BTreeMap<String, Value>) -> std::result::Result<Vec<Account>, String> {
    let passwd = facts
        .get("accounts.passwd")
        .and_then(Value::as_object)
        .ok_or("accounts.passwd is not a map")?;
    let empty = Map::new();
    let group = facts
        .get("accounts.group")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    Ok(passwd
        .iter()
        .map(|(name, entry)| {
            let gid = entry["gid"].as_u64();
            let groups = group
                .iter()
                .filter(|(_, g)| {
                    g["gid"].as_u64() == gid
                        || g["members"]
                            .as_array()
                            .is_some_and(|m| m.iter().any(|n| n.as_str() == Some(name)))
                })
                .map(|(g, _)| g.clone())
                .collect();
            Account {
                name: name.clone(),
                uid: entry["uid"].as_u64().unwrap_or_default(),
                home: entry["home"].as_str().unwrap_or_default().to_owned(),
                groups,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Account {
        Account {
            name: "alice".into(),
            uid: 1000,
            home: "/home/alice".into(),
            groups: vec!["alice".into(), "sftp".into()],
        }
    }

    fn block(criteria: &str, value: &str) -> Block {
        Block {
            key: format!("/etc/ssh/sshd_config:{}", criteria.len()),
            criteria: criteria.into(),
            raw: Raw::from([(KEYWORD.to_owned(), vec![value.to_owned()])]),
        }
    }

    #[test]
    fn tokens_expand_and_a_relative_path_lands_below_home() {
        let alice = alice();
        assert_eq!(
            expand(".ssh/authorized_keys", &alice).unwrap(),
            "/home/alice/.ssh/authorized_keys"
        );
        assert_eq!(
            expand("/etc/ssh/keys/%u.%U.100%%", &alice).unwrap(),
            "/etc/ssh/keys/alice.1000.100%"
        );
        assert_eq!(expand("%h/k", &alice).unwrap(), "/home/alice/k");
        assert!(expand("%C/k", &alice).is_err());
        assert!(expand("k%", &alice).is_err());
    }

    #[test]
    fn user_and_group_decide_and_a_connection_criterion_leaves_it_open() {
        let alice = alice();
        assert_eq!(applies("User alice", &alice), Applies::Always);
        assert_eq!(applies("User=al*", &alice), Applies::Always);
        assert_eq!(applies("User bob,a?ice", &alice), Applies::Always);
        assert_eq!(applies("User *,!alice", &alice), Applies::Never);
        assert_eq!(applies("User bob", &alice), Applies::Never);
        assert_eq!(applies("Group sftp", &alice), Applies::Always);
        assert_eq!(applies("Group wheel", &alice), Applies::Never);
        assert_eq!(
            applies("User alice Address 192.0.2.0/24", &alice),
            Applies::Sometimes
        );
        assert_eq!(
            applies("User bob Address 192.0.2.0/24", &alice),
            Applies::Never
        );
        assert_eq!(applies("All", &alice), Applies::Always);
        assert_eq!(applies("Invalid-User", &alice), Applies::Never);
    }

    #[test]
    fn the_first_block_that_always_applies_ends_the_list() {
        let alice = alice();
        let global = Raw::from([(KEYWORD.to_owned(), vec![".ssh/authorized_keys".to_owned()])]);
        let blocks = [
            block("User bob", "/bob"),
            block("Address 10.0.0.0/8", "/lan/%u"),
            block("Group sftp", "/sftp/%u"),
            block("User alice", "/never"),
        ];
        assert_eq!(values(&global, &blocks, &alice), ["/lan/%u", "/sftp/%u"]);
        assert_eq!(
            values(&global, &blocks[..2], &alice),
            ["/lan/%u", ".ssh/authorized_keys"]
        );
    }

    #[test]
    fn accounts_take_their_primary_and_listed_groups() {
        let facts = BTreeMap::from([
            (
                "accounts.passwd".to_owned(),
                serde_json::json!({"alice": {"uid": 1000, "gid": 1000, "home": "/home/alice"}}),
            ),
            (
                "accounts.group".to_owned(),
                serde_json::json!({"alice": {"gid": 1000, "members": []}, "sftp": {"gid": 2000, "members": ["alice"]}, "wheel": {"gid": 10, "members": ["bob"]}}),
            ),
        ]);
        assert_eq!(accounts(&facts).unwrap(), [alice()]);
    }
}
