// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `AuthorizedKeysFile` paths sshd may read for each account its own `sshd -T -C` run settled, `%` tokens resolved.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Reply};

/// The keyword whose paths this module resolves.
const KEYWORD: &str = "authorizedkeysfile";

/// The fact holding each account’s effective settings, which this op needs.
pub const ACCOUNTS: &str = "sshd.accounts";

/// One local account as sshd expands tokens for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u64,
    pub home: String,
}

/// `ssh.authorized-key-files`: per account in `sshd.accounts`, every absolute path sshd may read keys from, in its order.
pub fn files(facts: &BTreeMap<String, Value>) -> std::result::Result<Reply, String> {
    let settings = map(facts, ACCOUNTS)?;
    let passwd = map(facts, "accounts.passwd")?;
    let mut reply = Reply::default();
    for (name, set) in settings {
        let Some(entry) = passwd.get(name) else {
            reply.diagnostics.push(Diagnostic {
                path: format!("{ACCOUNTS}.{name}"),
                line: None,
                message: "not in accounts.passwd, so its paths can’t be expanded".to_owned(),
            });
            continue;
        };
        let account = Account {
            name: name.clone(),
            uid: entry["uid"].as_u64().unwrap_or_default(),
            home: entry["home"].as_str().unwrap_or_default().to_owned(),
        };
        let mut paths: Vec<String> = Vec::new();
        let words = set[KEYWORD]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        for word in words.filter(|w| *w != "none") {
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
        reply.facts.insert(account.name, Value::from(paths));
    }
    Ok(reply)
}

// The map at fact `key`.
fn map<'a>(
    facts: &'a BTreeMap<String, Value>,
    key: &str,
) -> std::result::Result<&'a Map<String, Value>, String> {
    facts
        .get(key)
        .and_then(Value::as_object)
        .ok_or(format!("{key} is not a map"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alice() -> Account {
        Account {
            name: "alice".into(),
            uid: 1000,
            home: "/home/alice".into(),
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
    fn each_settled_account_gets_its_own_paths() {
        let facts = BTreeMap::from([
            (
                ACCOUNTS.to_owned(),
                json!({
                    "alice": {KEYWORD: [".ssh/authorized_keys", "/etc/ssh/keys/%u", ".ssh/authorized_keys"]},
                    "sftp": {KEYWORD: ["none"]},
                    "ghost": {KEYWORD: [".ssh/authorized_keys"]},
                    "bad": {KEYWORD: ["%C"]}
                }),
            ),
            (
                "accounts.passwd".to_owned(),
                json!({
                    "alice": {"uid": 1000, "home": "/home/alice"},
                    "sftp": {"uid": 1001, "home": "/srv/sftp"},
                    "bad": {"uid": 1002, "home": "/home/bad"}
                }),
            ),
        ]);
        let reply = files(&facts).unwrap();
        assert_eq!(
            Value::Object(reply.facts.into_iter().collect()),
            json!({"alice": ["/home/alice/.ssh/authorized_keys", "/etc/ssh/keys/alice"], "sftp": [], "bad": []})
        );
        let paths: Vec<_> = reply.diagnostics.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["authorizedkeysfile %C", "sshd.accounts.ghost"]);
        assert!(files(&BTreeMap::new()).unwrap_err().contains(ACCOUNTS));
    }
}
