// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! sshd_config parsing: `Include` expansion, first-value-wins, `Match` blocks, and values shaped as `sshd -T` prints them.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The main configuration file, where `Include` expansion starts.
pub const MAIN: &str = "/etc/ssh/sshd_config";

/// The drop-in directory the shipped collector reads whole.
pub const DROP_INS: &str = "/etc/ssh/sshd_config.d/";

/// How deep sshd lets `Include` nest.
pub const DEPTH: usize = 16;

/// Keywords whose every line adds one value.
const LINES: &[&str] = &["port", "listenaddress", "hostkey", "hostcertificate", "subsystem"];

/// Keywords whose value is a list of words.
const WORDS: &[&str] = &["acceptenv", "allowusers", "denyusers", "allowgroups", "denygroups", "setenv", "permitopen", "permitlisten", "channeltimeout", "authorizedkeysfile", "logverbose"];

/// Keywords whose lines accumulate instead of the first one winning.
const ACCUMULATE: &[&str] = &["port", "listenaddress", "hostkey", "hostcertificate", "subsystem", "acceptenv", "allowusers", "denyusers", "allowgroups", "denygroups"];

/// Comma lists that take `+`, `-` and `^` against the default list.
const ALGORITHMS: &[&str] = &["ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "hostbasedacceptedalgorithms", "casignaturealgorithms", "gssapikexalgorithms"];

/// Keywords whose value sshd compares without case, lowercased on both sources.
const CASELESS: &[&str] = &[
    "addressfamily", "allowagentforwarding", "allowstreamlocalforwarding", "allowtcpforwarding", "compression", "debianbanner", "disableforwarding", "exposeauthinfo",
    "fingerprinthash", "gatewayports", "gssapiauthentication", "gssapicleanupcredentials", "gssapikeyexchange", "gssapistrictacceptorcheck", "gssapistorecredentialsonrekey",
    "hostbasedauthentication", "hostbasedusesnamefrompacketonly", "ignorerhosts", "ignoreuserknownhosts", "kbdinteractiveauthentication", "kerberosauthentication",
    "kerberosorlocalpasswd", "kerberosticketcleanup", "loglevel", "passwordauthentication", "permitemptypasswords", "permitrootlogin", "permittty", "permittunnel",
    "permituserenvironment", "permituserrc", "printlastlog", "printmotd", "pubkeyauthentication", "refuseconnection", "streamlocalbindunlink", "strictmodes",
    "syslogfacility", "tcpkeepalive", "usedns", "usepam", "x11forwarding", "x11uselocalhost",
];

/// Keywords a `Match` block accepts (OpenSSH 10.2p1 `servconf.c`, `SSHCFG_ALL`), by the name `sshd -T` prints.
pub const MATCH: &[&str] = &[
    "acceptenv", "allowagentforwarding", "allowgroups", "allowstreamlocalforwarding", "allowtcpforwarding", "allowusers", "authenticationmethods", "authorizedkeyscommand",
    "authorizedkeyscommanduser", "authorizedkeysfile", "authorizedprincipalscommand", "authorizedprincipalscommanduser", "authorizedprincipalsfile", "banner", "casignaturealgorithms",
    "channeltimeout", "chrootdirectory", "clientalivecountmax", "clientaliveinterval", "denygroups", "denyusers", "disableforwarding", "exposeauthinfo", "forcecommand", "gatewayports",
    "gssapiauthentication", "hostbasedacceptedalgorithms", "hostbasedauthentication", "hostbasedusesnamefrompacketonly", "ignorerhosts", "ipqos", "kbdinteractiveauthentication",
    "kerberosauthentication", "loglevel", "logverbose", "maxauthtries", "maxsessions", "pamservicename", "passwordauthentication", "permitemptypasswords", "permitlisten", "permitopen",
    "permitrootlogin", "permittty", "permittunnel", "permituserrc", "pubkeyacceptedalgorithms", "pubkeyauthentication", "pubkeyauthoptions", "rdomain", "refuseconnection", "rekeylimit",
    "requiredrsasize", "revokedkeys", "setenv", "streamlocalbindmask", "streamlocalbindunlink", "subsystem", "trustedusercakeys", "unusedconnectiontimeout", "x11displayoffset",
    "x11forwarding", "x11uselocalhost",
];

/// Keywords holding a time, which `sshd -T` prints in seconds.
const TIMES: &[&str] = &["logingracetime", "clientaliveinterval", "unusedconnectiontimeout"];

/// Old keyword names sshd still accepts, and the name it prints.
const ALIASES: &[(&str, &str)] = &[("challengeresponseauthentication", "kbdinteractiveauthentication"), ("pubkeyacceptedkeytypes", "pubkeyacceptedalgorithms"), ("hostbasedacceptedkeytypes", "hostbasedacceptedalgorithms")];

/// Raw values per keyword, one string per line, in the order sshd keeps them.
pub type Raw = BTreeMap<String, Vec<String>>;

/// One configuration line after `Include` expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub path: String,
    pub number: u64,
    pub keyword: String,
    pub args: Vec<String>,
}

/// A `Match` block: where it starts, its criteria and what it sets.
#[derive(Debug, Default)]
pub struct Block {
    pub key: String,
    pub criteria: String,
    pub raw: Raw,
}

/// The parsed files: the global settings, the `Match` blocks, and problems by path and line.
#[derive(Debug, Default)]
pub struct Parsed {
    pub global: Raw,
    pub blocks: Vec<Block>,
    pub problems: Vec<(String, Option<u64>, String)>,
}

/// `sshd -T` output as raw values per keyword.
pub fn dump(text: &str) -> Raw {
    let mut raw = Raw::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (keyword, value) = line.split_once(' ').unwrap_or((line, ""));
        raw.entry(keyword.to_ascii_lowercase()).or_default().push(value.to_owned());
    }
    raw
}

/// The keyword and arguments of one line as sshd splits it, or `None` for a blank or comment line.
pub fn words(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let keyword = line[..end].to_ascii_lowercase();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let keyword = ALIASES.iter().find(|(old, _)| *old == keyword).map_or(keyword, |(_, new)| (*new).to_owned());
    Some((keyword, arguments(rest)))
}

// Words split on blanks, double quotes grouping, and an unquoted `#` at a word start ending the line.
fn arguments(text: &str) -> Vec<String> {
    let (mut args, mut word, mut quoted, mut started) = (Vec::new(), String::new(), false, false);
    for c in text.chars() {
        match c {
            '"' => (quoted, started) = (!quoted, true),
            '#' if !quoted && !started => break,
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut word));
                }
                started = false;
            }
            c => (word, started) = (word + &c.to_string(), true),
        }
    }
    if started {
        args.push(word);
    }
    args
}

/// Whether `text` matches the `*` and `?` wildcards of `pattern`, which stop at `/` when `paths` is set.
pub fn wildcard(pattern: &str, text: &str, paths: bool) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star) = (0, 0, None);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?' && !(paths && t[ti] == '/')) {
            (pi, ti) = (pi + 1, ti + 1);
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star.filter(|&(_, st)| !(paths && t[st] == '/')) {
            star = Some((sp, st + 1));
            (pi, ti) = (sp + 1, st + 1);
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The lines of `path` with every `Include` replaced by the files it names, in sshd’s order.
pub fn expand(path: &str, files: &BTreeMap<String, String>, depth: usize, out: &mut Vec<Line>) -> Result<(), String> {
    let Some(text) = files.get(path) else { return Ok(()) };
    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let Some((keyword, args)) = words(line) else { continue };
        if keyword != "include" {
            out.push(Line { path: path.to_owned(), number, keyword, args });
            continue;
        }
        for arg in args {
            let pattern = if arg.starts_with('/') { arg } else { format!("/etc/ssh/{arg}") };
            let matched: Vec<&String> = files.keys().filter(|p| wildcard(&pattern, p, true)).collect();
            if matched.is_empty() && !pattern.starts_with(DROP_INS) {
                return Err(format!("Include {pattern} at {path}:{number} names files outside {DROP_INS}, which the collector does not read"));
            }
            if depth >= DEPTH && !matched.is_empty() {
                return Err(format!("Include {pattern} at {path}:{number} nests deeper than {DEPTH} files"));
            }
            for file in matched {
                expand(file, files, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

/// The global settings and `Match` blocks of `lines`, first value winning, algorithm edits resolved against `defaults`.
pub fn settle(lines: &[Line], defaults: &Raw) -> Parsed {
    let mut parsed = Parsed::default();
    for line in lines {
        if line.keyword == "match" {
            parsed.blocks.push(Block { key: format!("{}:{}", line.path, line.number), criteria: line.args.join(" "), raw: Raw::new() });
            continue;
        }
        if !defaults.contains_key(&line.keyword) && !LINES.contains(&line.keyword.as_str()) && !WORDS.contains(&line.keyword.as_str()) {
            parsed.problems.push((line.path.clone(), Some(line.number), format!("{} is not a keyword this sshd prints; deprecated or unknown", line.keyword)));
        }
        let raw = match parsed.blocks.last_mut() {
            Some(_) if !MATCH.contains(&line.keyword.as_str()) => {
                parsed.problems.push((line.path.clone(), Some(line.number), format!("{} is not allowed in a Match block, so sshd refuses to start", line.keyword)));
                continue;
            }
            Some(block) => &mut block.raw,
            None => &mut parsed.global,
        };
        if let Err(message) = apply(raw, line, defaults) {
            parsed.problems.push((line.path.clone(), Some(line.number), message));
        }
    }
    parsed
}

// Adds one line to `raw`: accumulated, or kept only when the keyword is still unset.
fn apply(raw: &mut Raw, line: &Line, defaults: &Raw) -> Result<(), String> {
    let keyword = line.keyword.as_str();
    if line.args.is_empty() {
        return Err(format!("{keyword} has no value"));
    }
    if ACCUMULATE.contains(&keyword) {
        let slot = raw.entry(keyword.to_owned()).or_default();
        match LINES.contains(&keyword) {
            true => slot.push(line.args.join(" ")),
            false => slot.extend(line.args.iter().cloned()),
        }
        return Ok(());
    }
    if raw.contains_key(keyword) {
        return Ok(());
    }
    let mut value = line.args.join(" ");
    if TIMES.contains(&keyword) && value != "none" {
        value = seconds(&value).ok_or_else(|| format!("{keyword} {value} is not a time"))?.to_string();
    }
    if ALGORITHMS.contains(&keyword) {
        let default: Vec<&str> = defaults.get(keyword).and_then(|v| v.first()).map(|v| v.split(',').collect()).unwrap_or_default();
        value = algorithms(&value, &default);
    }
    raw.insert(keyword.to_owned(), vec![value]);
    Ok(())
}

/// A time in sshd’s format (`90`, `1m30s`, `2h`) as seconds.
pub fn seconds(text: &str) -> Option<u64> {
    let (mut total, mut number) = (0u64, None::<u64>);
    for c in text.chars() {
        if let Some(digit) = c.to_digit(10) {
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(u64::from(digit))?);
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    match number {
        Some(n) => total.checked_add(n),
        None if text.is_empty() => None,
        None => Some(total),
    }
}

/// An algorithm list after sshd’s `+` (append), `-` (remove by pattern) and `^` (prepend) against `default`.
pub fn algorithms(value: &str, default: &[&str]) -> String {
    let items = |text: &str| text.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect::<Vec<_>>();
    let default: Vec<String> = default.iter().map(|s| (*s).to_owned()).collect();
    let list = match value.chars().next() {
        Some('+') => default.iter().cloned().chain(items(&value[1..]).into_iter().filter(|i| !default.contains(i))).collect(),
        Some('-') => {
            let patterns = items(&value[1..]);
            default.into_iter().filter(|d| !patterns.iter().any(|p| wildcard(p, d, false))).collect()
        }
        Some('^') => {
            let first = items(&value[1..]);
            first.iter().cloned().chain(default.into_iter().filter(|d| !first.contains(d))).collect()
        }
        _ => items(value),
    };
    list.join(",")
}

/// Raw values shaped as facts: lists as arrays, caseless values lowercased, whole numbers as numbers.
pub fn facts(raw: &Raw) -> Map<String, Value> {
    raw.iter().map(|(keyword, values)| (keyword.clone(), value(keyword, values))).collect()
}

fn value(keyword: &str, values: &[String]) -> Value {
    if LINES.contains(&keyword) {
        return values.iter().map(|v| number(v)).collect();
    }
    if WORDS.contains(&keyword) {
        return values.iter().flat_map(|v| v.split_whitespace()).map(Value::from).collect();
    }
    let first = values.first().map_or("", String::as_str);
    if ALGORITHMS.contains(&keyword) {
        return first.split(',').filter(|s| !s.is_empty()).map(Value::from).collect();
    }
    let lowered = if CASELESS.contains(&keyword) { first.to_ascii_lowercase() } else { first.to_owned() };
    number(if lowered == "without-password" { "prohibit-password" } else { &lowered })
}

// A whole number without a leading zero as a JSON number, anything else as a string.
fn number(text: &str) -> Value {
    let plain = text == "0" || !text.starts_with('0') && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    match text.parse::<u64>() {
        Ok(n) if plain => Value::from(n),
        _ => Value::from(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(p, t)| ((*p).to_owned(), (*t).to_owned())).collect()
    }

    fn lines(pairs: &[(&str, &str)]) -> Result<Vec<Line>, String> {
        let mut out = Vec::new();
        expand(MAIN, &files(pairs), 0, &mut out).map(|()| out)
    }

    #[test]
    fn words_split_like_sshd() {
        assert_eq!(words("  # comment"), None);
        assert_eq!(words(""), None);
        assert_eq!(words("PermitRootLogin no"), Some(("permitrootlogin".into(), vec!["no".into()])));
        assert_eq!(words("MACs=-hmac-sha1*"), Some(("macs".into(), vec!["-hmac-sha1*".into()])));
        assert_eq!(words("Port = 22"), Some(("port".into(), vec!["22".into()])));
        assert_eq!(words("Banner \"/etc/my banner\" # trailing"), Some(("banner".into(), vec!["/etc/my banner".into()])));
        assert_eq!(words("AcceptEnv LANG a#b"), Some(("acceptenv".into(), vec!["LANG".into(), "a#b".into()])));
        assert_eq!(words("ChallengeResponseAuthentication yes").unwrap().0, "kbdinteractiveauthentication");
    }

    #[test]
    fn wildcards_stop_at_slashes_only_for_paths() {
        assert!(wildcard("/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/10-a.conf", true));
        assert!(!wildcard("/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/sub/a.conf", true));
        assert!(!wildcard("/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/notes.txt", true));
        assert!(wildcard("/etc/ssh/a?.conf", "/etc/ssh/ab.conf", true));
        assert!(wildcard("hmac-sha1*", "hmac-sha1-etm@openssh.com", false));
        assert!(wildcard("*", "a/b", false));
        assert!(!wildcard("umac-64*", "umac-128@openssh.com", false));
    }

    #[test]
    fn include_expands_in_place_in_name_order() {
        let found = lines(&[(MAIN, "Port 1\nInclude sshd_config.d/*.conf\nPort 4\n"), ("/etc/ssh/sshd_config.d/b.conf", "Port 3\n"), ("/etc/ssh/sshd_config.d/a.conf", "Port 2\n")]).unwrap();
        let order: Vec<_> = found.iter().map(|l| (l.path.as_str(), l.args[0].as_str())).collect();
        assert_eq!(order, [(MAIN, "1"), ("/etc/ssh/sshd_config.d/a.conf", "2"), ("/etc/ssh/sshd_config.d/b.conf", "3"), (MAIN, "4")]);
        assert_eq!(found[3].number, 3);
    }

    #[test]
    fn include_outside_the_read_set_fails_and_an_empty_drop_in_does_not() {
        assert!(lines(&[(MAIN, "Include /etc/ssh/sshd_config.d/*.conf\n")]).unwrap().is_empty());
        let error = lines(&[(MAIN, "Include /etc/crypto-policies/back-ends/opensshserver.config\n")]).unwrap_err();
        assert!(error.contains("/etc/crypto-policies/back-ends/opensshserver.config at /etc/ssh/sshd_config:1"), "{error}");
    }

    #[test]
    fn include_nesting_stops_at_sshd_depth() {
        let drop = "/etc/ssh/sshd_config.d/loop.conf";
        let error = lines(&[(MAIN, &format!("Include {drop}\n")), (drop, &format!("Include {drop}\n"))]).unwrap_err();
        assert!(error.contains(&format!("deeper than {DEPTH}")), "{error}");
    }

    #[test]
    fn first_value_wins_lists_accumulate_and_match_opens_a_block() {
        let defaults = dump("port 22\nmacs a,b-sha1,c\npermitrootlogin prohibit-password\nx11forwarding no\n");
        let found = lines(&[(MAIN, "PermitRootLogin no\nPermitRootLogin yes\nPort 2222\nPort 22\nMACs -*sha1\nProtocol 2\nX11Forwarding\nMatch User x\nPermitRootLogin yes\nPermitRootLogin no\n")]).unwrap();
        let parsed = settle(&found, &defaults);
        assert_eq!(parsed.global["permitrootlogin"], ["no"]);
        assert_eq!(parsed.global["port"], ["2222", "22"]);
        assert_eq!(parsed.global["macs"], ["a,c"]);
        assert_eq!(parsed.blocks.len(), 1);
        assert_eq!((parsed.blocks[0].key.as_str(), parsed.blocks[0].criteria.as_str()), ("/etc/ssh/sshd_config:8", "User x"));
        assert_eq!(parsed.blocks[0].raw["permitrootlogin"], ["yes"]);
        let problems: Vec<_> = parsed.problems.iter().map(|(_, line, m)| (*line, m.split(' ').next().unwrap())).collect();
        assert_eq!(problems, [(Some(6), "protocol"), (Some(7), "x11forwarding")]);
    }

    #[test]
    fn seconds_read_every_unit_and_refuse_the_rest() {
        for (text, expected) in [("0", Some(0)), ("90", Some(90)), ("1m30s", Some(90)), ("2M", Some(120)), ("1h", Some(3600)), ("1d", Some(86_400)), ("1w", Some(604_800)), ("5s10", Some(15))] {
            assert_eq!(seconds(text), expected, "{text}");
        }
        for text in ["", "m", "2x", "1.5m", "99999999999999999999"] {
            assert_eq!(seconds(text), None, "{text}");
        }
    }

    #[test]
    fn algorithm_edits_apply_to_the_default_list() {
        let default = ["a", "b", "c"];
        assert_eq!(algorithms("+d,a", &default), "a,b,c,d");
        assert_eq!(algorithms("-b*", &default), "a,c");
        assert_eq!(algorithms("^c,z", &default), "c,z,a,b");
        assert_eq!(algorithms("x,y", &default), "x,y");
    }

    #[test]
    fn facts_shape_values_like_sshd_t() {
        let raw = dump("permitrootlogin without-password\nloglevel VERBOSE\nport 22\nport 2222\nacceptenv LANG\nacceptenv LC_*\nauthorizedkeysfile .ssh/a .ssh/b\nciphers x,y\nmaxauthtries 0\nstreamlocalbindmask 0177\nbanner none\nsubsystem sftp /usr/lib/openssh/sftp-server\n");
        let facts = Value::Object(facts(&raw));
        assert_eq!(facts["permitrootlogin"], "prohibit-password");
        assert_eq!(facts["loglevel"], "verbose");
        assert_eq!(facts["port"], serde_json::json!([22, 2222]));
        assert_eq!(facts["acceptenv"], serde_json::json!(["LANG", "LC_*"]));
        assert_eq!(facts["authorizedkeysfile"], serde_json::json!([".ssh/a", ".ssh/b"]));
        assert_eq!(facts["ciphers"], serde_json::json!(["x", "y"]));
        assert_eq!(facts["maxauthtries"], 0);
        assert_eq!(facts["streamlocalbindmask"], "0177");
        assert_eq!(facts["banner"], "none");
        assert_eq!(facts["subsystem"], serde_json::json!(["sftp /usr/lib/openssh/sftp-server"]));
    }
}
