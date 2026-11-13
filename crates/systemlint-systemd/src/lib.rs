// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! systemd: each unit merged from its file and drop-ins, and the sandbox systemd runs a service in.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use systemlint_formats::{Sections, parse_ini, text, unit_files};
use systemlint_protocol::{Describe, Diagnostic, FileInput, Input, Reply, Request, Result, Stat};

/// The capabilities systemd knows, in `systemd-analyze capability` order.
pub const CAPABILITIES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// The service types `Type=` takes.
pub const TYPES: [&str; 8] = [
    "simple",
    "exec",
    "forking",
    "oneshot",
    "dbus",
    "notify",
    "notify-reload",
    "idle",
];

/// The credential settings that make `exec` the default type.
pub const CREDENTIALS: [&str; 5] = [
    "LoadCredential",
    "LoadCredentialEncrypted",
    "ImportCredential",
    "SetCredential",
    "SetCredentialEncrypted",
];

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("systemd", &[("units", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "units" => Ok(units(&request.inputs)),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// Each unit with a unit file: its path, the file a link leads to, drop-ins, merged sections and, for a service, its type and sandbox.
pub fn units(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let links: BTreeMap<&str, String> = inputs
        .iter()
        .filter_map(|i| match i {
            Input::File(FileInput {
                path,
                stat:
                    Some(Stat {
                        linked_to: Some(to),
                        ..
                    }),
                ..
            }) => Some((path.as_str(), resolve(path, to))),
            _ => None,
        })
        .collect();
    let files: Vec<(&str, &str)> = inputs
        .iter()
        .filter(|i| {
            !matches!(
                i,
                Input::File(FileInput {
                    content: None,
                    content_base64: None,
                    ..
                })
            )
        })
        .filter_map(|i| text(i, &mut reply.diagnostics))
        .collect();
    for (unit, parts) in unit_files(&files) {
        let Some(((main, _), _)) = parts.split_first().filter(|((p, _), _)| !dropin(p)) else {
            continue;
        };
        let file = links.get(main).map_or(*main, String::as_str);
        let target = file.rsplit_once('/').map_or(file, |(_, name)| name);
        let alias = (target != unit).then_some(target);
        let mut sections = Sections::new();
        for (path, text) in &parts {
            merge(
                &mut sections,
                parse_ini(text, |line, message| {
                    reply.diagnostics.push(Diagnostic {
                        path: (*path).to_owned(),
                        line: Some(line),
                        message,
                    })
                }),
            );
        }
        let mut entry = Map::from_iter([
            ("path".to_owned(), json!(main)),
            ("file".to_owned(), json!(file)),
            ("alias-of".to_owned(), json!(alias)),
            (
                "drop-ins".to_owned(),
                json!(parts[1..].iter().map(|(p, _)| p).collect::<Vec<_>>()),
            ),
        ]);
        if unit.ends_with(".service") {
            let mut diagnose = |message| {
                reply.diagnostics.push(Diagnostic {
                    path: unit.clone(),
                    line: None,
                    message,
                })
            };
            let service = sections.get("Service");
            entry.insert("type".to_owned(), json!(kind(service, &mut diagnose)));
            let sandbox = sandbox(&unit, service, diagnose);
            entry.insert("sandbox".to_owned(), Value::Object(sandbox));
        }
        entry.insert("sections".to_owned(), json!(sections));
        reply.facts.insert(unit, Value::Object(entry));
    }
    reply
}

/// Where a unit-file link leads, a relative target read from the link’s directory with `.` and `..` folded.
pub fn resolve(path: &str, to: &str) -> String {
    let base = if to.starts_with('/') {
        ""
    } else {
        path.rsplit_once('/').map_or("", |(dir, _)| dir)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in base.split('/').chain(to.split('/')) {
        match part {
            "" | "." => {}
            ".." => drop(parts.pop()),
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// A service’s `Type=`: the last valid value, else the default `systemd.service(5)` names.
fn kind(
    service: Option<&BTreeMap<String, Vec<String>>>,
    diagnose: &mut impl FnMut(String),
) -> String {
    let set = |key: &str| {
        service
            .and_then(|s| s.get(key))
            .and_then(|v| v.last())
            .is_some_and(|v| !v.is_empty())
    };
    let values = service
        .and_then(|s| s.get("Type"))
        .map_or(&[][..], Vec::as_slice);
    let known = |v: &str| TYPES.contains(&v).then(|| v.to_owned());
    last(values, "Type", known, diagnose).unwrap_or_else(|| {
        match () {
            () if set("BusName") => "dbus",
            () if !set("ExecStart") => "oneshot",
            () if CREDENTIALS.iter().any(|key| set(key)) => "exec",
            () => "simple",
        }
        .to_owned()
    })
}

/// Whether `path` is a drop-in: a `.conf` in a `<unit>.d` directory.
fn dropin(path: &str) -> bool {
    path.rsplit_once('/')
        .is_some_and(|(dir, _)| dir.ends_with(".d"))
}

/// Adds `next` over `merged`: values append in reading order, and an empty one drops every value before it.
pub fn merge(merged: &mut Sections, next: Sections) {
    for (name, keys) in next {
        let section = merged.entry(name).or_default();
        for (key, values) in keys {
            let list = section.entry(key).or_default();
            for value in values {
                if value.is_empty() {
                    list.clear();
                }
                list.push(value);
            }
        }
    }
}

/// The sandbox settings systemd applies to a service, with its defaults and what `DynamicUser=` implies.
pub fn sandbox(
    unit: &str,
    service: Option<&BTreeMap<String, Vec<String>>>,
    mut diagnose: impl FnMut(String),
) -> Map<String, Value> {
    let values = |key: &str| {
        service
            .and_then(|s| s.get(key))
            .map_or(&[][..], Vec::as_slice)
    };
    let dynamic =
        last(values("DynamicUser"), "DynamicUser", boolean, &mut diagnose).unwrap_or(false);
    let user = last(
        values("User"),
        "User",
        |v| Some(v.to_owned()),
        &mut diagnose,
    );
    let protect = last(
        values("ProtectSystem"),
        "ProtectSystem",
        protect_system,
        &mut diagnose,
    )
    .unwrap_or("no");
    let nnp = last(
        values("NoNewPrivileges"),
        "NoNewPrivileges",
        boolean,
        &mut diagnose,
    )
    .unwrap_or(false);
    let mut sandbox = Map::new();
    match (user, dynamic) {
        (Some(user), _) => drop(sandbox.insert("user".to_owned(), json!(user))),
        (None, false) => drop(sandbox.insert("user".to_owned(), json!("root"))),
        (None, true) => {
            let stem = unit.trim_end_matches(".service");
            if user_name(stem) {
                sandbox.insert("user".to_owned(), json!(stem));
            }
        }
    }
    sandbox.insert("dynamic-user".to_owned(), json!(dynamic));
    sandbox.insert("no-new-privileges".to_owned(), json!(nnp || dynamic));
    let protect = if dynamic && protect == "no" {
        "strict"
    } else {
        protect
    };
    sandbox.insert("protect-system".to_owned(), json!(protect));
    let bounding = bounding(values("CapabilityBoundingSet"), &mut diagnose)
        .filter(|set| set.len() < CAPABILITIES.len())
        .map_or(json!("all"), |set| json!(set));
    sandbox.insert("capability-bounding-set".to_owned(), bounding);
    sandbox
}

/// The last value of `key` that `read` accepts, or `None` when unset or reset; a refused value is named and skipped, as systemd ignores it.
fn last<T>(
    values: &[String],
    key: &str,
    read: impl Fn(&str) -> Option<T>,
    diagnose: &mut impl FnMut(String),
) -> Option<T> {
    let mut found = None;
    for value in values {
        if value.is_empty() {
            found = None;
            continue;
        }
        match read(value) {
            Some(read) => found = Some(read),
            None => diagnose(format!(
                "{key}={value} is not valid, ignored as systemd ignores it"
            )),
        }
    }
    found
}

/// A systemd boolean, read as `parse_boolean` does.
pub fn boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

/// A `ProtectSystem=` value as `no`, `yes`, `full` or `strict`.
fn protect_system(value: &str) -> Option<&'static str> {
    match value {
        "full" => Some("full"),
        "strict" => Some("strict"),
        _ => boolean(value).map(|on| if on { "yes" } else { "no" }),
    }
}

/// Whether systemd takes `name` as a user name as it is, so `DynamicUser=` names the user after the unit.
fn user_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 31
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The bounding set `CapabilityBoundingSet=` lines leave, `None` when untouched: the first line sets it, later ones add, `~` lines remove, empty empties it, a bare `~` restores it.
pub fn bounding(
    values: &[String],
    diagnose: &mut impl FnMut(String),
) -> Option<BTreeSet<&'static str>> {
    let mut set: Option<BTreeSet<&'static str>> = None;
    for value in values {
        match value.as_str() {
            "" => set = Some(BTreeSet::new()),
            "~" => set = None,
            _ => {
                let (invert, list) = value
                    .strip_prefix('~')
                    .map_or((false, value.as_str()), |rest| (true, rest));
                let mut named = BTreeSet::new();
                for word in list.split_whitespace() {
                    match CAPABILITIES.iter().find(|c| c.eq_ignore_ascii_case(word)) {
                        Some(cap) => drop(named.insert(*cap)),
                        None => diagnose(format!(
                            "CapabilityBoundingSet names {word}, which systemd does not know, ignored"
                        )),
                    }
                }
                let line: BTreeSet<&'static str> = if invert {
                    CAPABILITIES
                        .into_iter()
                        .filter(|c| !named.contains(c))
                        .collect()
                } else {
                    named
                };
                set = Some(match set {
                    None => line,
                    Some(set) if invert => set.intersection(&line).copied().collect(),
                    Some(set) => set.union(&line).copied().collect(),
                });
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn service(lines: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        lines
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
            .collect()
    }

    fn quiet(unit: &str, lines: &[(&str, &[&str])]) -> Value {
        let mut said = Vec::new();
        let sandbox = sandbox(unit, Some(&service(lines)), |m| said.push(m));
        assert!(said.is_empty(), "{said:?}");
        Value::Object(sandbox)
    }

    #[test]
    fn describe_lists_units() {
        assert_eq!(
            describe()
                .ops
                .iter()
                .map(|o| o.op.as_str())
                .collect::<Vec<_>>(),
            ["units"]
        );
    }

    #[test]
    fn units_merge_drop_ins_over_the_highest_file_and_reset_on_an_empty_value() {
        let reply = units(&[
            file(
                "/usr/lib/systemd/system/a.service",
                "[Service]\nExecStart=/old\nUser=a\n",
            ),
            file(
                "/etc/systemd/system/a.service",
                "[Service]\nExecStart=/bin/a\nUser=root\n",
            ),
            file(
                "/usr/lib/systemd/system/a.service.d/10-x.conf",
                "[Service]\nUser=svc\n",
            ),
            file(
                "/etc/systemd/system/a.service.d/20-y.conf",
                "[Service]\nExecStart=\nExecStart=/bin/b\n",
            ),
            file(
                "/etc/systemd/system/orphan.service.d/x.conf",
                "[Service]\nUser=x\n",
            ),
        ]);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(
            reply.facts.keys().collect::<Vec<_>>(),
            ["a.service"],
            "a drop-in without a unit file loads nothing"
        );
        let a = &reply.facts["a.service"];
        assert_eq!(a["path"], "/etc/systemd/system/a.service");
        assert_eq!(
            a["drop-ins"],
            json!([
                "/usr/lib/systemd/system/a.service.d/10-x.conf",
                "/etc/systemd/system/a.service.d/20-y.conf"
            ])
        );
        assert_eq!(a["sections"]["Service"]["ExecStart"], json!(["", "/bin/b"]));
        assert_eq!(a["sandbox"]["user"], "svc");
    }

    #[test]
    fn an_unset_service_runs_as_root_with_every_capability_and_no_sandbox() {
        assert_eq!(
            quiet("a.service", &[]),
            json!({"user": "root", "dynamic-user": false, "no-new-privileges": false, "protect-system": "no", "capability-bounding-set": "all"})
        );
        assert!(
            units(&[file(
                "/etc/systemd/system/t.timer",
                "[Timer]\nOnCalendar=daily\n"
            )])
            .facts["t.timer"]
                .get("sandbox")
                .is_none()
        );
    }

    #[test]
    fn dynamic_user_names_the_user_after_the_unit_and_implies_the_rest() {
        assert_eq!(
            quiet("web.service", &[("DynamicUser", &["yes"])]),
            json!({"user": "web", "dynamic-user": true, "no-new-privileges": true, "protect-system": "strict", "capability-bounding-set": "all"})
        );
        assert_eq!(
            quiet(
                "web.service",
                &[("DynamicUser", &["yes"]), ("ProtectSystem", &["full"])]
            )["protect-system"],
            "full"
        );
        assert_eq!(
            quiet(
                "web.service",
                &[("DynamicUser", &["yes"]), ("NoNewPrivileges", &["no"])]
            )["no-new-privileges"],
            true
        );
        assert!(
            quiet("1web.service", &[("DynamicUser", &["on"])])
                .get("user")
                .is_none(),
            "systemd hashes a name it refuses"
        );
        assert_eq!(
            quiet(
                "web.service",
                &[("DynamicUser", &["1"]), ("User", &["www"])]
            )["user"],
            "www"
        );
    }

    #[test]
    fn the_last_valid_value_wins_an_empty_one_resets_and_a_bad_one_is_named() {
        assert_eq!(
            quiet("a.service", &[("ProtectSystem", &["strict", "true"])])["protect-system"],
            "yes"
        );
        assert_eq!(
            quiet("a.service", &[("ProtectSystem", &["strict", ""])])["protect-system"],
            "no"
        );
        assert_eq!(
            quiet("a.service", &[("User", &["svc", ""])])["user"],
            "root"
        );
        let mut said = Vec::new();
        let got = sandbox(
            "a.service",
            Some(&service(&[("NoNewPrivileges", &["yes", "maybe"])])),
            |m| said.push(m),
        );
        assert_eq!(got["no-new-privileges"], true);
        assert_eq!(
            said,
            ["NoNewPrivileges=maybe is not valid, ignored as systemd ignores it"]
        );
    }

    #[test]
    fn bounding_lines_or_together_and_tilde_lines_and_out() {
        let set = |lines: &[&str]| {
            let lines: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
            bounding(&lines, &mut |m| panic!("{m}")).map(|s| s.into_iter().collect::<Vec<_>>())
        };
        assert_eq!(set(&[]), None);
        assert_eq!(
            set(&["cap_chown", "CAP_KILL"]),
            Some(vec!["CAP_CHOWN", "CAP_KILL"])
        );
        assert_eq!(
            set(&["CAP_CHOWN CAP_KILL", "~CAP_KILL"]),
            Some(vec!["CAP_CHOWN"])
        );
        assert_eq!(set(&["~CAP_SYS_ADMIN"]).unwrap().len(), 40);
        assert_eq!(set(&["CAP_CHOWN", ""]), Some(vec![]));
        assert_eq!(set(&["CAP_CHOWN", "~"]), None);
        assert_eq!(
            quiet(
                "a.service",
                &[(
                    "CapabilityBoundingSet",
                    &["~CAP_SYS_ADMIN", "CAP_SYS_ADMIN"]
                )]
            )["capability-bounding-set"],
            "all",
            "a set holding every capability is no limit"
        );
        let mut said = Vec::new();
        assert_eq!(
            bounding(&["CAP_NOPE CAP_KILL".to_owned()], &mut |m| said.push(m)).map(|s| s.len()),
            Some(1)
        );
        assert_eq!(said.len(), 1);
    }

    fn link(path: &str, to: &str, content: Option<&str>) -> Input {
        Input::File(FileInput {
            path: path.to_owned(),
            content: content.map(str::to_owned),
            content_base64: None,
            stat: Some(Stat {
                kind: systemlint_protocol::FileKind::Symlink,
                mode: "0777".to_owned(),
                uid: 0,
                gid: 0,
                size: 0,
                world_writable: false,
                group_writable: false,
                setuid: false,
                setgid: false,
                linked_to: Some(to.to_owned()),
                sha256: None,
                sha512: None,
            }),
            statfs: None,
            absent: false,
        })
    }

    #[test]
    fn a_link_names_the_file_it_leads_to_and_an_alias_its_unit() {
        let reply = units(&[
            link(
                "/etc/systemd/system/dm.service",
                "/usr/lib/systemd/system/sddm.service",
                Some("[Service]\nExecStart=/bin/sddm\n"),
            ),
            link(
                "/etc/systemd/system/app.service",
                "../../../opt/app/app.service",
                Some("[Service]\nExecStart=/opt/app/run\n"),
            ),
            link("/etc/systemd/system/off.service", "/dev/null", None),
        ]);
        assert!(
            reply.diagnostics.is_empty(),
            "a masked link is no text to complain about: {:?}",
            reply.diagnostics
        );
        assert_eq!(
            reply.facts.keys().collect::<Vec<_>>(),
            ["app.service", "dm.service"]
        );
        assert_eq!(
            reply.facts["dm.service"]["file"],
            "/usr/lib/systemd/system/sddm.service"
        );
        assert_eq!(reply.facts["dm.service"]["alias-of"], "sddm.service");
        assert_eq!(reply.facts["app.service"]["file"], "/opt/app/app.service");
        assert_eq!(reply.facts["app.service"]["alias-of"], Value::Null);
    }

    #[test]
    fn resolve_folds_dots_against_the_link_directory() {
        assert_eq!(
            resolve("/etc/systemd/system/a.service", "/lib/x/a.service"),
            "/lib/x/a.service"
        );
        assert_eq!(
            resolve("/etc/systemd/system/a.service", "./b/../a2.service"),
            "/etc/systemd/system/a2.service"
        );
        assert_eq!(
            resolve("/etc/a.service", "../../../../x.service"),
            "/x.service"
        );
    }

    #[test]
    fn type_defaults_follow_busname_execstart_and_credentials() {
        let kind_of =
            |lines: &[(&str, &[&str])]| kind(Some(&service(lines)), &mut |m| panic!("{m}"));
        assert_eq!(kind_of(&[("ExecStart", &["/x"])]), "simple");
        assert_eq!(kind_of(&[]), "oneshot");
        assert_eq!(
            kind_of(&[("ExecStart", &["/x", ""])]),
            "oneshot",
            "a reset ExecStart= is none"
        );
        assert_eq!(
            kind_of(&[("ExecStart", &["/x"]), ("BusName", &["org.x"])]),
            "dbus"
        );
        assert_eq!(
            kind_of(&[("ExecStart", &["/x"]), ("LoadCredential", &["k:/p"])]),
            "exec"
        );
        assert_eq!(
            kind_of(&[("ExecStart", &["/x"]), ("Type", &["notify", "idle"])]),
            "idle"
        );
        let mut said = Vec::new();
        assert_eq!(
            kind(
                Some(&service(&[("ExecStart", &["/x"]), ("Type", &["daemon"])])),
                &mut |m| said.push(m)
            ),
            "simple"
        );
        assert_eq!(said.len(), 1);
    }
}
