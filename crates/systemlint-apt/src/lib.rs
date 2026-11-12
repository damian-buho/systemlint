// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! apt: sources, cached lists and installed packages, judged against the host release.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

pub mod deb822;
pub mod lists;
pub mod sources;

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("apt", &[("installed", &[]), ("lists", &[]), ("sources", &["os.release", "apt.lists"])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    let now = match request.now.as_deref() {
        Some(text) => Some(lists::parse_now(text).ok_or_else(|| format!("now {text:?} is not RFC 3339 UTC"))?),
        None => None,
    };
    match request.op.as_str() {
        "installed" => Ok(installed(&request.inputs)),
        "lists" => Ok(lists::lists(&request.inputs, now)),
        "sources" => Ok(sources::sources(&request.inputs, &request.facts)),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// Every package in a dpkg `status` file with its version, architecture and state, keyed `name`, or `name:arch` when installed for several.
pub fn installed(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut packages: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for input in inputs {
        let Input::File(file) = input else { continue };
        let Some(text) = file.content.as_deref() else {
            reply.diagnostics.push(Diagnostic { path: file.path.clone(), line: None, message: "not UTF-8 text, skipped".to_owned() });
            continue;
        };
        let (stanzas, problems) = deb822::parse(text);
        reply.diagnostics.extend(problems.into_iter().map(|(line, message)| Diagnostic { path: file.path.clone(), line: Some(line), message }));
        for stanza in stanzas {
            let (Some(name), Some(status)) = (stanza.get("Package"), stanza.get("Status")) else {
                reply.diagnostics.push(Diagnostic { path: file.path.clone(), line: Some(stanza.line), message: "a paragraph with no Package or Status".to_owned() });
                continue;
            };
            let mut package = json!({"architecture": stanza.get("Architecture").unwrap_or_default(), "status": status.split_whitespace().last().unwrap_or_default()});
            if let Some(version) = stanza.get("Version") {
                package["version"] = Value::from(version);
            }
            packages.entry(name.to_owned()).or_default().push(package);
        }
    }
    for (name, entries) in packages {
        if let [only] = &entries[..] {
            reply.facts.insert(name, only.clone());
            continue;
        }
        for entry in entries {
            reply.facts.insert(format!("{name}:{}", entry["architecture"].as_str().unwrap_or_default()), entry);
        }
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::FileInput;

    fn request(op: &str, now: Option<&str>) -> Request {
        Request { protocol: 1, op: op.into(), root: "/".into(), now: now.map(str::to_owned), inputs: vec![], facts: Default::default() }
    }

    #[test]
    fn sources_needs_the_host_release_and_the_lists() {
        let describe = describe();
        assert_eq!(describe.name, "apt");
        let sources = describe.ops.iter().find(|o| o.op == "sources").unwrap();
        assert_eq!(sources.needs, ["os.release", "apt.lists"]);
    }

    #[test]
    fn a_bad_clock_fails_the_op() {
        assert!(op(request("lists", Some("yesterday"))).unwrap_err().to_string().contains("yesterday"));
        assert!(op(request("lists", Some("2026-11-11T12:00:00Z"))).is_ok());
        assert!(op(request("nope", None)).is_err());
    }

    #[test]
    fn installed_keys_by_name_and_by_arch_when_multiarch() {
        let status = "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.42-0ubuntu3\n\nPackage: libc6\nStatus: install ok installed\nArchitecture: i386\nVersion: 2.42-0ubuntu3\n\nPackage: openssh-server\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1:10.0p1-5ubuntu5\nDescription: x\n continued\n\nStatus: install ok installed\n";
        let reply = installed(&[Input::File(FileInput { path: "/var/lib/dpkg/status".into(), content: Some(status.into()), content_base64: None, stat: None })]);
        assert_eq!(reply.facts.keys().collect::<Vec<_>>(), ["libc6:amd64", "libc6:i386", "openssh-server"]);
        assert_eq!(reply.facts["openssh-server"], json!({"architecture": "amd64", "status": "config-files", "version": "1:10.0p1-5ubuntu5"}));
        assert_eq!(reply.diagnostics.iter().map(|d| d.line).collect::<Vec<_>>(), [Some(18)]);
    }
}
