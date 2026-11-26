// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! What `/proc/<pid>` files say about a process: its cgroup, owner and parent.

/// What a container’s facts are keyed by, before its name or short ID.
pub const CONTAINER: &str = "container:";

/// Leaf prefixes of the cgroup scopes container engines create, before the container ID.
pub const CONTAINER_SCOPES: [&str; 4] = ["docker-", "libpod-", "cri-containerd-", "crio-"];

/// Whether `segment` looks like a container ID (at least 12 ASCII hex characters).
fn hex_id(segment: &str) -> bool {
    segment.len() >= 12 && segment.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `parent` names a Kubernetes pod cgroup directory (`pod<uid>` or `kubepods-…-pod<uid>.slice`).
pub fn is_pod_cgroup(parent: &str) -> bool {
    parent.starts_with("pod") || parent.contains("-pod")
}

/// What owns a cgroup: a system service by its unit name, or a container by `container:` and the first 12 characters of its ID.
pub fn owner(cgroup: &str) -> Option<String> {
    let mut rev = cgroup.rsplit('/');
    let leaf = rev.next()?;
    let parent = rev.next().unwrap_or_default();
    if let Some(id) = CONTAINER_SCOPES
        .iter()
        .find_map(|p| leaf.strip_prefix(p))
        .and_then(|rest| rest.strip_suffix(".scope"))
    {
        return Some(format!("{CONTAINER}{}", &id[..id.len().min(12)]));
    }
    if hex_id(leaf)
        && (matches!(parent, "docker" | "containerd" | "crio" | "podman") || is_pod_cgroup(parent))
    {
        return Some(format!("{CONTAINER}{}", &leaf[..12]));
    }
    (cgroup.starts_with("/system.slice/") && leaf.ends_with(".service")).then(|| leaf.to_owned())
}

/// The unified (or systemd v1) cgroup path in a `/proc/<pid>/cgroup` text.
pub fn cgroup(text: &str) -> Option<&str> {
    let lines: Vec<(&str, &str)> = text
        .lines()
        .filter_map(|l| l.split_once(':').and_then(|(_, rest)| rest.split_once(':')))
        .collect();
    lines
        .iter()
        .find(|(c, _)| c.is_empty())
        .or_else(|| lines.iter().find(|(c, _)| *c == "name=systemd"))
        .map(|(_, path)| *path)
}

/// The parent PID in a `/proc/<pid>/stat` text, read after the command name’s closing parenthesis.
pub fn parent(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The PID and file name of a `/proc/<pid>/<file>` path.
pub fn pid_file(path: &str) -> Option<(u32, &str)> {
    let mut parts = path.trim_start_matches('/').split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("proc"), Some(pid), Some(file), None) => Some((pid.parse().ok()?, file)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_names_system_services_and_containers_only() {
        assert_eq!(
            owner("/system.slice/nginx.service").as_deref(),
            Some("nginx.service")
        );
        assert_eq!(
            owner("/system.slice/docker-0123456789abcdef0123.scope").as_deref(),
            Some("container:0123456789ab")
        );
        assert_eq!(
            owner("/kubepods.slice/kubepods-pod1.slice/cri-containerd-abc.scope").as_deref(),
            Some("container:abc")
        );
        assert_eq!(
            owner("/kubepods/burstable/pod1234/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").as_deref(),
            Some("container:0123456789ab")
        );
        assert_eq!(
            owner("/containerd/fedcba9876543210fedcba9876543210").as_deref(),
            Some("container:fedcba987654")
        );
        assert_eq!(
            owner("/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service"),
            None
        );
        assert_eq!(owner("/init.scope"), None);
        assert_eq!(
            cgroup("0::/system.slice/a.service\n"),
            Some("/system.slice/a.service")
        );
        assert_eq!(
            cgroup("12:cpu:/x\n1:name=systemd:/system.slice/b.service\n"),
            Some("/system.slice/b.service")
        );
        assert_eq!(parent("42 (a b) c) S 7 42 42"), Some(7));
    }

    #[test]
    fn pid_file_takes_only_a_file_directly_under_a_pid() {
        assert_eq!(pid_file("/proc/42/maps"), Some((42, "maps")));
        assert_eq!(pid_file("/proc/self/maps"), None);
        assert_eq!(pid_file("/proc/42/task/43/maps"), None);
        assert_eq!(pid_file("/etc/42/maps"), None);
    }
}
