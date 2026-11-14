// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! `sshd -T` output: raw values per keyword, shaped as facts.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The key `sshd.global` files the plain `sshd -T` settings under.
pub const MAIN: &str = "/etc/ssh/sshd_config";

/// Keywords whose every line adds one value.
const LINES: &[&str] = &[
    "port",
    "listenaddress",
    "hostkey",
    "hostcertificate",
    "subsystem",
];

/// Keywords whose value is a list of words.
const WORDS: &[&str] = &[
    "acceptenv",
    "allowusers",
    "denyusers",
    "allowgroups",
    "denygroups",
    "setenv",
    "permitopen",
    "permitlisten",
    "channeltimeout",
    "authorizedkeysfile",
    "logverbose",
];

/// Comma lists that take `+`, `-` and `^` against the default list.
const ALGORITHMS: &[&str] = &[
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "hostbasedacceptedalgorithms",
    "casignaturealgorithms",
    "gssapikexalgorithms",
];

/// Keywords whose value sshd compares without case, lowercased on both sources.
const CASELESS: &[&str] = &[
    "addressfamily",
    "allowagentforwarding",
    "allowstreamlocalforwarding",
    "allowtcpforwarding",
    "compression",
    "debianbanner",
    "disableforwarding",
    "exposeauthinfo",
    "fingerprinthash",
    "gatewayports",
    "gssapiauthentication",
    "gssapicleanupcredentials",
    "gssapikeyexchange",
    "gssapistrictacceptorcheck",
    "gssapistorecredentialsonrekey",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "ignorerhosts",
    "ignoreuserknownhosts",
    "kbdinteractiveauthentication",
    "kerberosauthentication",
    "kerberosorlocalpasswd",
    "kerberosticketcleanup",
    "loglevel",
    "passwordauthentication",
    "permitemptypasswords",
    "permitrootlogin",
    "permittty",
    "permittunnel",
    "permituserenvironment",
    "permituserrc",
    "printlastlog",
    "printmotd",
    "pubkeyauthentication",
    "refuseconnection",
    "streamlocalbindunlink",
    "strictmodes",
    "syslogfacility",
    "tcpkeepalive",
    "usedns",
    "usepam",
    "x11forwarding",
    "x11uselocalhost",
];

/// Keywords a `Match` block accepts (OpenSSH 10.2p1 `servconf.c`, `SSHCFG_ALL`), by the name `sshd -T` prints.
pub const MATCH: &[&str] = &[
    "acceptenv",
    "allowagentforwarding",
    "allowgroups",
    "allowstreamlocalforwarding",
    "allowtcpforwarding",
    "allowusers",
    "authenticationmethods",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "authorizedkeysfile",
    "authorizedprincipalscommand",
    "authorizedprincipalscommanduser",
    "authorizedprincipalsfile",
    "banner",
    "casignaturealgorithms",
    "channeltimeout",
    "chrootdirectory",
    "clientalivecountmax",
    "clientaliveinterval",
    "denygroups",
    "denyusers",
    "disableforwarding",
    "exposeauthinfo",
    "forcecommand",
    "gatewayports",
    "gssapiauthentication",
    "hostbasedacceptedalgorithms",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "ignorerhosts",
    "ipqos",
    "kbdinteractiveauthentication",
    "kerberosauthentication",
    "loglevel",
    "logverbose",
    "maxauthtries",
    "maxsessions",
    "pamservicename",
    "passwordauthentication",
    "permitemptypasswords",
    "permitlisten",
    "permitopen",
    "permitrootlogin",
    "permittty",
    "permittunnel",
    "permituserrc",
    "pubkeyacceptedalgorithms",
    "pubkeyauthentication",
    "pubkeyauthoptions",
    "rdomain",
    "refuseconnection",
    "rekeylimit",
    "requiredrsasize",
    "revokedkeys",
    "setenv",
    "streamlocalbindmask",
    "streamlocalbindunlink",
    "subsystem",
    "trustedusercakeys",
    "unusedconnectiontimeout",
    "x11displayoffset",
    "x11forwarding",
    "x11uselocalhost",
];

/// Raw values per keyword, one string per line, in the order sshd keeps them.
pub type Raw = BTreeMap<String, Vec<String>>;

/// `sshd -T` output as raw values per keyword.
pub fn dump(text: &str) -> Raw {
    let mut raw = Raw::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (keyword, value) = line.split_once(' ').unwrap_or((line, ""));
        raw.entry(keyword.to_ascii_lowercase())
            .or_default()
            .push(value.to_owned());
    }
    raw
}

/// Raw values shaped as facts: lists as arrays, caseless values lowercased, whole numbers as numbers.
pub fn facts(raw: &Raw) -> Map<String, Value> {
    raw.iter()
        .map(|(keyword, values)| (keyword.clone(), value(keyword, values)))
        .collect()
}

fn value(keyword: &str, values: &[String]) -> Value {
    if LINES.contains(&keyword) {
        return values.iter().map(|v| number(v)).collect();
    }
    if WORDS.contains(&keyword) {
        return values
            .iter()
            .flat_map(|v| v.split_whitespace())
            .map(Value::from)
            .collect();
    }
    let first = values.first().map_or("", String::as_str);
    if ALGORITHMS.contains(&keyword) {
        return first
            .split(',')
            .filter(|s| !s.is_empty())
            .map(Value::from)
            .collect();
    }
    let lowered = if CASELESS.contains(&keyword) {
        first.to_ascii_lowercase()
    } else {
        first.to_owned()
    };
    number(if lowered == "without-password" {
        "prohibit-password"
    } else {
        &lowered
    })
}

// A whole number without a leading zero as a JSON number, anything else as a string.
fn number(text: &str) -> Value {
    let plain = text == "0"
        || !text.starts_with('0') && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    match text.parse::<u64>() {
        Ok(n) if plain => Value::from(n),
        _ => Value::from(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_shape_values_like_sshd_t() {
        let raw = dump(
            "permitrootlogin without-password\nloglevel VERBOSE\nport 22\nport 2222\nacceptenv LANG\nacceptenv LC_*\nauthorizedkeysfile .ssh/a .ssh/b\nciphers x,y\nmaxauthtries 0\nstreamlocalbindmask 0177\nbanner none\nsubsystem sftp /usr/lib/openssh/sftp-server\n",
        );
        let facts = Value::Object(facts(&raw));
        assert_eq!(facts["permitrootlogin"], "prohibit-password");
        assert_eq!(facts["loglevel"], "verbose");
        assert_eq!(facts["port"], serde_json::json!([22, 2222]));
        assert_eq!(facts["acceptenv"], serde_json::json!(["LANG", "LC_*"]));
        assert_eq!(
            facts["authorizedkeysfile"],
            serde_json::json!([".ssh/a", ".ssh/b"])
        );
        assert_eq!(facts["ciphers"], serde_json::json!(["x", "y"]));
        assert_eq!(facts["maxauthtries"], 0);
        assert_eq!(facts["streamlocalbindmask"], "0177");
        assert_eq!(facts["banner"], "none");
        assert_eq!(
            facts["subsystem"],
            serde_json::json!(["sftp /usr/lib/openssh/sftp-server"])
        );
    }
}
