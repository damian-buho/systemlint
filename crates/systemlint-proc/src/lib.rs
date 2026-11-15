// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! proc: what running processes hold, grouped by the system service that owns them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use systemlint_formats::proc::{CONTAINER, cgroup, owner, pid_file};
use systemlint_formats::text;
use systemlint_protocol::{Describe, Input, Reply, Request, Result};

/// Directories only a package manager or an administrator writes, so a deleted file mapped from them is code replaced under a running process.
pub const SYSTEM_DIRS: [&str; 8] = [
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/opt/",
];

/// What the kernel appends to a mapped file’s path once it is unlinked.
pub const DELETED: &str = " (deleted)";

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("proc", &[("services", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "services" => Ok(services(&request.inputs)),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// The path of an executable mapping of a deleted file under [`SYSTEM_DIRS`], from one `/proc/<pid>/maps` line.
pub fn replaced(line: &str) -> Option<&str> {
    let mut rest = line;
    let mut fields = [""; 5];
    for field in &mut fields {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        (*field, rest) = rest.split_at(end);
    }
    let path = rest.trim_start().strip_suffix(DELETED)?;
    let executable = fields[1].as_bytes().get(2) == Some(&b'x');
    (executable && SYSTEM_DIRS.iter().any(|d| path.starts_with(d))).then_some(path)
}

/// Per system service, from `/proc/<pid>/{cgroup,maps}`: its `pids` and the deleted system files they still run as `replaced`; containers are left out.
pub fn services(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut procs: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    for input in inputs {
        let Some((path, body)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        if let Some((pid, file)) = pid_file(path) {
            procs.entry(pid).or_default().insert(file, body);
        }
    }
    let mut units: BTreeMap<String, (Vec<u32>, BTreeSet<&str>)> = BTreeMap::new();
    for (pid, files) in &procs {
        let (Some(group), Some(maps)) = (
            files.get("cgroup").and_then(|c| cgroup(c)),
            files.get("maps"),
        ) else {
            continue;
        };
        let Some(unit) = owner(group).filter(|o| !o.starts_with(CONTAINER)) else {
            continue;
        };
        let (pids, paths) = units.entry(unit).or_default();
        pids.push(*pid);
        paths.extend(maps.lines().filter_map(replaced));
    }
    for (unit, (pids, paths)) in units {
        reply
            .facts
            .insert(unit, json!({"pids": pids, "replaced": paths}));
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

    #[test]
    fn replaced_takes_only_executable_deleted_system_files() {
        let line =
            |perms: &str, path: &str| format!("7f00-7f10 {perms} 00000000 08:01 1234    {path}");
        assert_eq!(
            replaced(&line("r-xp", "/usr/lib/libssl.so.3 (deleted)")),
            Some("/usr/lib/libssl.so.3")
        );
        assert_eq!(
            replaced(&line("r-xp", "/opt/app/lib a b.so (deleted)")),
            Some("/opt/app/lib a b.so"),
            "a path keeps its blanks"
        );
        assert_eq!(
            replaced(&line("r--p", "/usr/lib/libssl.so.3 (deleted)")),
            None,
            "data, not code"
        );
        assert_eq!(
            replaced(&line("r-xp", "/usr/lib/libssl.so.3")),
            None,
            "still on disk"
        );
        assert_eq!(
            replaced(&line("r-xs", "/memfd:jit (deleted)")),
            None,
            "anonymous memory"
        );
        assert_eq!(replaced(&line("r-xp", "/dev/shm/x (deleted)")), None);
        assert_eq!(
            replaced(&line("r-xp", "/home/u/a.out (deleted)")),
            None,
            "a user’s own build"
        );
        assert_eq!(
            replaced(&line("r-xp", "/usr2/x (deleted)")),
            None,
            "a prefix is a whole directory"
        );
        assert_eq!(
            replaced("7f00-7f10 r-xp 00000000 00:00 0"),
            None,
            "anonymous mapping"
        );
        assert_eq!(replaced(""), None);
    }

    #[test]
    fn services_group_every_process_by_its_unit_and_leave_containers_out() {
        let maps =
            "1-2 r-xp 0 08:01 1 /usr/lib/libc.so.6 (deleted)\n1-2 r-xp 0 08:01 2 /usr/bin/app\n";
        let reply = services(&[
            file("/proc/10/cgroup", "0::/system.slice/app.service\n"),
            file("/proc/10/maps", "1-2 r-xp 0 08:01 2 /usr/bin/app\n"),
            file("/proc/11/cgroup", "0::/system.slice/app.service\n"),
            file("/proc/11/maps", maps),
            file(
                "/proc/12/cgroup",
                "0::/system.slice/docker-feedfacecafe.scope\n",
            ),
            file("/proc/12/maps", maps),
            file(
                "/proc/13/cgroup",
                "0::/user.slice/user-1000.slice/session-1.scope\n",
            ),
            file("/proc/13/maps", maps),
            file("/proc/14/cgroup", "0::/system.slice/gone.service\n"),
        ]);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(
            serde_json::Value::Object(reply.facts.into_iter().collect()),
            json!({"app.service": {"pids": [10, 11], "replaced": ["/usr/lib/libc.so.6"]}}),
            "a process with no maps left is no subject"
        );
    }
}
