// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Kernel modules: the modprobe.d configuration, the modules each installed kernel ships, and the ones loaded.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::{conf_order, text};

/// The modprobe.d directories kmod reads, highest precedence first.
pub const MODPROBE_DIRS: [&str; 5] = [
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/local/lib/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
];

/// The kmod commands that name no module this op judges.
const OTHER_COMMANDS: [&str; 6] = ["alias", "options", "remove", "softdep", "weakdep", "config"];

/// One module as modprobe would treat it.
#[derive(Default)]
struct Module {
    loadable: bool,
    builtin: bool,
    blacklist: bool,
    install: Option<String>,
}

/// A diagnostic for one line of one file.
fn note(reply: &mut Reply, path: &str, line: usize, message: String) {
    reply.diagnostics.push(Diagnostic {
        path: path.to_owned(),
        line: Some(line as u64),
        message,
    });
}

/// A module name as kmod compares it: `-` read as `_`.
pub fn module_name(name: &str) -> String {
    name.replace('-', "_")
}

/// The module a `modules.order` or `modules.builtin` line names: its file name up to `.ko`.
fn listed_name(line: &str) -> Option<String> {
    let file = line.trim().rsplit('/').next()?;
    let stem = file.split_once(".ko").map_or(file, |(stem, _)| stem);
    (!stem.is_empty()).then(|| module_name(stem))
}

/// Every module by name: `loadable` or `builtin` in some installed kernel’s `modules.order` or `modules.builtin`, kmod’s `blacklist`, and the first `install` command matching it in kmod’s file order.
pub fn modprobe(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut modules: BTreeMap<String, Module> = BTreeMap::new();
    let files: Vec<(&str, &str)> = inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
        .collect();
    for (path, content) in &files {
        let builtin = path.ends_with("/modules.builtin");
        if !builtin && !path.ends_with("/modules.order") {
            continue;
        }
        for name in content.lines().filter_map(listed_name) {
            let module = modules.entry(name).or_default();
            if builtin {
                module.builtin = true;
            } else {
                module.loadable = true;
            }
        }
    }
    let mut installs: Vec<(String, String)> = Vec::new();
    for (path, content) in conf_order(&MODPROBE_DIRS, &files) {
        for (number, line) in joined(content) {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (None, _) => {}
                (Some(c), _) if c.starts_with('#') => {}
                (Some("blacklist"), Some(name)) => {
                    modules.entry(module_name(name)).or_default().blacklist = true
                }
                (Some("install"), Some(name)) => {
                    let command = words.collect::<Vec<_>>().join(" ");
                    installs.push((module_name(name), command));
                }
                (Some(c), Some(_)) if OTHER_COMMANDS.contains(&c) => {}
                (Some(c), _) => note(
                    &mut reply,
                    path,
                    number,
                    format!(
                        "{c:?} is not a modprobe.d command kmod reads with a module name, ignored"
                    ),
                ),
            }
        }
    }
    for (pattern, _) in &installs {
        if !pattern.contains(['*', '?', '[']) {
            modules.entry(pattern.clone()).or_default();
        }
    }
    for (name, module) in &mut modules {
        module.install = installs
            .iter()
            .find(|(pattern, _)| wildcard(pattern, name))
            .map(|(_, command)| command.clone());
    }
    for (name, module) in modules {
        reply.facts.insert(
            name,
            json!({"loadable": module.loadable, "builtin": module.builtin, "blacklist": module.blacklist, "install": module.install}),
        );
    }
    reply
}

/// The logical lines of a modprobe.d file with their first line number, a trailing `\` joining the next.
fn joined(content: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut open = false;
    for (index, raw) in content.lines().enumerate() {
        let (body, continues) = raw.strip_suffix('\\').map_or((raw, false), |b| (b, true));
        match out.last_mut() {
            Some((_, line)) if open => line.push_str(body),
            _ => out.push((index + 1, body.to_owned())),
        }
        open = continues;
    }
    out
}

/// Whether the fnmatch(3) `pattern` kmod applies to `install` names matches `name`: `*`, `?` and `[…]` classes.
pub fn wildcard(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star) = (0, 0, None);
    while ni < n.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some((pi, ni));
                pi += 1;
                continue;
            }
            Some('?') => Some(pi + 1),
            Some('[') => class(&p[pi..], n[ni]).map(|len| pi + len),
            Some(c) if *c == n[ni] => Some(pi + 1),
            _ => None,
        };
        match (step, star) {
            (Some(next), _) => (pi, ni) = (next, ni + 1),
            (None, Some((sp, sn))) => (pi, ni, star) = (sp + 1, sn + 1, Some((sp, sn + 1))),
            (None, None) => return false,
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The length of the `[…]` class opening `pattern` when it matches `c`, `None` when it does not or never closes.
fn class(pattern: &[char], c: char) -> Option<usize> {
    let negated = matches!(pattern.get(1), Some('!' | '^'));
    let start = if negated { 2 } else { 1 };
    let end = start + 1 + pattern.get(start + 1..)?.iter().position(|x| *x == ']')?;
    let set = &pattern[start..end];
    let mut hit = false;
    let mut i = 0;
    while i < set.len() {
        if set.get(i + 1) == Some(&'-') && i + 2 < set.len() {
            hit |= (set[i]..=set[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= set[i] == c;
            i += 1;
        }
    }
    (hit != negated).then_some(end + 1)
}

/// Every module in `/proc/modules` by name: `size` in bytes, `instances` loaded, `used-by` and `state`.
pub fn proc_modules(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let files: Vec<(&str, &str)> = inputs
        .iter()
        .filter_map(|i| text(i, &mut reply.diagnostics))
        .collect();
    for (path, content) in files {
        for (index, line) in content.lines().enumerate() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [name, size, instances, used, state, ..] = fields[..] else {
                note(
                    &mut reply,
                    path,
                    index + 1,
                    format!("{} fields where at least 5 are expected", fields.len()),
                );
                continue;
            };
            let number = |s: &str| {
                s.parse::<u64>()
                    .map_or_else(|_| Value::from(s), Value::from)
            };
            let used_by: Vec<&str> = used
                .split(',')
                .filter(|u| !u.is_empty() && *u != "-")
                .collect();
            reply.facts.insert(
                module_name(name),
                json!({"size": number(size), "instances": number(instances), "used-by": used_by, "state": state.to_lowercase()}),
            );
        }
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::FileInput;

    fn object(facts: impl IntoIterator<Item = (String, Value)>) -> Value {
        Value::Object(facts.into_iter().collect())
    }

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

    #[test]
    fn modprobe_takes_the_first_install_in_kmod_order_and_any_blacklist() {
        let reply = modprobe(&[
            file(
                "/lib/modules/7.0.0-1-generic/modules.order",
                "kernel/fs/cramfs/cramfs.ko\nkernel/drivers/usb/storage/usb-storage.ko\nkernel/net/dccp/dccp.ko\n",
            ),
            file(
                "/lib/modules/7.0.0-1-generic/modules.builtin",
                "kernel/fs/squashfs/squashfs.ko\n",
            ),
            file("/usr/lib/modprobe.d/a.conf", "install cramfs /bin/true\n"),
            file(
                "/etc/modprobe.d/a.conf",
                "install cramfs /bin/false\nblacklist usb-storage\n",
            ),
            file(
                "/etc/modprobe.d/b.conf",
                "# off\ninstall cramfs /sbin/modprobe --ignore-install cramfs\ninstall usb_storage \\\n  /bin/false\nbogus\n",
            ),
            file(
                "/run/modprobe.d/c.conf",
                "install dcc? /usr/bin/false\ninstall tipc /bin/false\n",
            ),
        ]);
        assert_eq!(
            object(reply.facts),
            json!({
                "cramfs": {"loadable": true, "builtin": false, "blacklist": false, "install": "/bin/false"},
                "dccp": {"loadable": true, "builtin": false, "blacklist": false, "install": "/usr/bin/false"},
                "squashfs": {"loadable": false, "builtin": true, "blacklist": false, "install": null},
                "tipc": {"loadable": false, "builtin": false, "blacklist": false, "install": "/bin/false"},
                "usb_storage": {"loadable": true, "builtin": false, "blacklist": true, "install": "/bin/false"}})
        );
        assert_eq!(
            (
                reply.diagnostics[0].path.as_str(),
                reply.diagnostics[0].line
            ),
            ("/etc/modprobe.d/b.conf", Some(5))
        );
    }

    #[test]
    fn wildcard_edges() {
        assert!(wildcard("*", "cramfs"));
        assert!(wildcard("cram*", "cramfs"));
        assert!(wildcard("c?amfs", "cramfs"));
        assert!(wildcard("[a-c]ramfs", "cramfs"));
        assert!(!wildcard("[!c]ramfs", "cramfs"));
        assert!(!wildcard("[c", "c"));
        assert!(!wildcard("cramfs?", "cramfs"));
        assert!(!wildcard("cram", "cramfs"));
    }

    #[test]
    fn proc_modules_keys_each_loaded_module_by_name() {
        let reply = proc_modules(&[file(
            "/proc/modules",
            "inet_diag 24576 2 tcp_diag,udp_diag, Live 0x0000000000000000\nusb-storage 86016 1 - Loading 0x0\nshort 1\n",
        )]);
        assert_eq!(
            object(reply.facts),
            json!({
                "inet_diag": {"size": 24576, "instances": 2, "used-by": ["tcp_diag", "udp_diag"], "state": "live"},
                "usb_storage": {"size": 86016, "instances": 1, "used-by": [], "state": "loading"}})
        );
        assert_eq!(reply.diagnostics[0].line, Some(3));
    }
}
