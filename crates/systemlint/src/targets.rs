// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Finds every running container on this host, nested ones included, each by its init process.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Value, json};
use systemlint_formats::proc;

use crate::source::Root;

/// One running container: its engine, ID, init process here and in its own PID namespace, and the key it is reported under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub key: String,
    pub name: String,
    pub engine: &'static str,
    pub id: String,
    pub pid: u32,
    pub inner: u32,
    pub parent: Option<String>,
    pub image: Option<String>,
    pub upper: Option<String>,
}

impl Found {
    /// The `meta.subject` of the container’s facts document.
    pub fn subject(&self) -> Value {
        json!({"kind": "container", "engine": self.engine, "name": self.name, "id": self.id, "parent": self.parent, "image": self.image})
    }

    /// Whether the glob `pattern` matches its key (`ci/runner`), its name or its short ID.
    pub fn named(&self, pattern: &str) -> bool {
        [&self.key, &self.name, &self.id]
            .iter()
            .any(|text| crate::rules::glob(pattern, text))
    }
}

/// The engine of each cgroup scope prefix in [`proc::CONTAINER_SCOPES`].
const ENGINES: [&str; 4] = ["docker", "podman", "containerd", "cri-o"];

/// Where Docker keeps each container’s `config.v2.json`, one directory per full ID.
const DOCKER_CONTAINERS: &str = "/var/lib/docker/containers/";

/// Every container a cgroup path sits in, outermost first, as engine and full ID.
pub fn chain(cgroup: &str) -> Vec<(&'static str, &str)> {
    let hex = |id: &str| id.len() >= 12 && id.bytes().all(|b| b.is_ascii_hexdigit());
    let mut found = Vec::new();
    let mut previous = "";
    for segment in cgroup.split('/') {
        let scoped = proc::CONTAINER_SCOPES
            .iter()
            .zip(ENGINES)
            .find_map(|(prefix, engine)| {
                Some((
                    engine,
                    segment.strip_prefix(prefix)?.strip_suffix(".scope")?,
                ))
            });
        match scoped {
            Some((engine, id)) if hex(id) => found.push((engine, id)),
            _ if previous == "docker" && hex(segment) => found.push(("docker", segment)),
            _ => {}
        }
        previous = segment;
    }
    found
}

/// The last `NSpid` of a `/proc/<pid>/status` text: the process’s PID in its own namespace.
pub fn inner_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))?
        .split_whitespace()
        .last()?
        .parse()
        .ok()
}

/// The image a Docker `config.v2.json` text says the container runs, as it was named.
pub fn docker_image(config: &str) -> Option<String> {
    let config: Value = serde_json::from_str(config).ok()?;
    Some(config["Config"]["Image"].as_str()?.to_owned())
}

/// The host directory of an overlay root’s writable layer, from the `upperdir` of the `/` line of a `mountinfo` text.
pub fn upper_dir(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (mount, fs) = line.split_once(" - ")?;
        let mut fields = fs.split(' ');
        let (kind, options) = (fields.next()?, fields.nth(1)?);
        (mount.split(' ').nth(4)? == "/" && kind == "overlay")
            .then(|| options.split(',').find_map(|o| o.strip_prefix("upperdir=")))
            .flatten()
            .map(str::to_owned)
    })
}

/// Paths a container’s writable layer may hold before [`changed`] gives up naming them.
pub const CHANGED_CAP: usize = 100_000;

/// Every path below the writable layer at `upper`, as the container sees it, or none when it holds more than [`CHANGED_CAP`] or can’t be read.
pub fn changed(upper: &str) -> Option<Vec<String>> {
    let root = Root::open(std::path::Path::new(upper))
        .inspect_err(|e| log::debug!("writable layer {upper} not opened: {e}"))
        .ok()?;
    let mut paths = Vec::new();
    if let Err(e) = root.walk("", CHANGED_CAP, &mut paths) {
        log::debug!("writable layer {upper} not listed: {}", String::from(e));
        return None;
    }
    paths.retain(|p| p != "/");
    paths.sort();
    log::debug!("writable layer {upper}: {} paths", paths.len());
    Some(paths)
}

/// The container name in a Docker `config.v2.json` text, without its leading `/`.
pub fn docker_name(config: &str) -> Option<String> {
    let config: Value = serde_json::from_str(config).ok()?;
    Some(config["Name"].as_str()?.trim_start_matches('/').to_owned())
}

/// A container while its processes are gathered.
struct Group {
    engine: &'static str,
    outer: Option<String>,
    pids: Vec<u32>,
}

/// Every running container `host`’s `/proc` shows, by key, one per mount namespace `namespace` tells apart, the host’s own left out.
pub fn discover(host: &Root, namespace: &dyn Fn(u32) -> Option<(u64, u64)>) -> Vec<Found> {
    let read = |path: String| {
        host.read(&path, crate::runner::OUTPUT_CAP)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut parents = BTreeMap::new();
    for path in host.glob("/proc/*/cgroup").unwrap_or_default() {
        let Some((pid, _)) = proc::pid_file(&path) else {
            continue;
        };
        let Some(text) = read(path.clone()) else {
            log::debug!("process {pid} exited before its cgroup was read");
            continue;
        };
        let ids = proc::cgroup(&text).map(chain).unwrap_or_default();
        let Some(&(engine, id)) = ids.last() else {
            continue;
        };
        let outer = ids.len().checked_sub(2).map(|i| ids[i].1.to_owned());
        if let Some(ppid) = read(format!("/proc/{pid}/stat"))
            .as_deref()
            .and_then(proc::parent)
        {
            parents.insert(pid, ppid);
        }
        groups
            .entry(id.to_owned())
            .or_insert(Group {
                engine,
                outer,
                pids: Vec::new(),
            })
            .pids
            .push(pid);
    }
    log::debug!("{} container scopes among the processes", groups.len());
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    let mut seen: HashSet<(u64, u64)> = namespace(std::process::id()).into_iter().collect();
    let mut order: Vec<(&String, &Group)> = groups.iter().collect();
    order.sort_by_key(|(id, g)| (depth(&groups, g), (*id).clone()));
    for (id, group) in order {
        let members: HashSet<u32> = group.pids.iter().copied().collect();
        let Some(&pid) = group
            .pids
            .iter()
            .filter(|p| parents.get(p).is_none_or(|pp| !members.contains(pp)))
            .min()
        else {
            continue;
        };
        if let Some(ns) = namespace(pid).filter(|ns| !seen.insert(*ns)) {
            log::debug!("container {id} shares mount namespace {ns:?} with one already found");
            continue;
        }
        let Some(inner) = read(format!("/proc/{pid}/status"))
            .as_deref()
            .and_then(inner_pid)
        else {
            log::debug!("container {id} init {pid} exited before its status was read");
            continue;
        };
        let parent = group.outer.as_ref().and_then(|o| found.get(o));
        let short = id[..12].to_owned();
        let config = match (group.engine, parent) {
            ("docker", None) => read(format!("{DOCKER_CONTAINERS}{id}/config.v2.json")),
            ("docker", Some(p)) => Root::process(p.pid, p.inner).ok().and_then(|r| {
                r.read(
                    &format!("{DOCKER_CONTAINERS}{id}/config.v2.json"),
                    crate::runner::OUTPUT_CAP,
                )
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
            }),
            _ => None,
        };
        let name = config
            .as_deref()
            .and_then(docker_name)
            .unwrap_or_else(|| short.clone());
        let image = config.as_deref().and_then(docker_image);
        let upper = read(format!("/proc/{pid}/mountinfo"))
            .as_deref()
            .and_then(upper_dir)
            .filter(|_| parent.is_none());
        let key = parent.map_or_else(|| name.clone(), |p| format!("{}/{name}", p.key));
        log::debug!(
            "container {key}: {} {short}, init {pid} ({inner} inside)",
            group.engine
        );
        found.insert(
            id.clone(),
            Found {
                parent: parent.map(|p| p.key.clone()),
                key,
                name,
                engine: group.engine,
                id: short,
                pid,
                inner,
                image,
                upper,
            },
        );
    }
    let mut found: Vec<Found> = found.into_values().collect();
    found.sort_by(|a, b| a.key.cmp(&b.key));
    found
}

/// How many containers `group` sits inside.
fn depth(groups: &BTreeMap<String, Group>, group: &Group) -> usize {
    let mut depth = 0;
    let mut outer = group.outer.as_ref();
    while let Some(next) = outer
        .and_then(|o| groups.get(o))
        .filter(|_| depth < groups.len())
    {
        depth += 1;
        outer = next.outer.as_ref();
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn chain_reads_each_engine_scope_and_nested_docker() {
        assert_eq!(
            chain(&format!("/system.slice/docker-{A}.scope")),
            [("docker", A)]
        );
        assert_eq!(
            chain(&format!("/system.slice/docker-{A}.scope/docker/{B}")),
            [("docker", A), ("docker", B)]
        );
        assert_eq!(
            chain(&format!("/machine.slice/libpod-{A}.scope/container")),
            [("podman", A)]
        );
        assert_eq!(
            chain(&format!("/kubepods.slice/x.slice/crio-{A}.scope")),
            [("cri-o", A)]
        );
        assert_eq!(
            chain(&format!("/kubepods.slice/x.slice/crio-conmon-{A}.scope")),
            []
        );
        assert_eq!(chain("/system.slice/docker.service"), []);
        assert_eq!(chain("/system.slice/docker-0123456789a.scope"), []);
    }

    #[test]
    fn inner_pid_is_the_last_nspid() {
        assert_eq!(inner_pid("Name:\tsh\nNSpid:\t4242\t17\t1\n"), Some(1));
        assert_eq!(inner_pid("NSpid:\t4242\n"), Some(4242));
        assert_eq!(inner_pid("Name:\tsh\n"), None);
    }

    #[test]
    fn upper_dir_reads_the_overlay_root_and_nothing_else() {
        let line = |point: &str, kind: &str| {
            format!(
                "1 0 0:1 / {point} rw - {kind} overlay rw,lowerdir=/l,upperdir=/var/lib/docker/overlay2/x/diff,workdir=/w\n"
            )
        };
        let info = line("/proc", "proc") + &line("/", "overlay");
        assert_eq!(
            upper_dir(&info).as_deref(),
            Some("/var/lib/docker/overlay2/x/diff")
        );
        assert_eq!(
            upper_dir(&line("/", "ext4")),
            None,
            "a root on a disk has no layer"
        );
        assert_eq!(upper_dir(&line("/data", "overlay")), None);
    }

    #[test]
    fn docker_image_names_the_image_as_run() {
        let config = r#"{"Name": "/web", "Config": {"Image": "kiota.ch/b19/ubuntu:latest"}}"#;
        assert_eq!(
            docker_image(config).as_deref(),
            Some("kiota.ch/b19/ubuntu:latest")
        );
        assert_eq!(docker_image(r#"{"Name": "/web"}"#), None);
    }

    #[test]
    fn docker_name_drops_the_slash() {
        assert_eq!(docker_name(r#"{"Name": "/web"}"#).as_deref(), Some("web"));
        assert_eq!(docker_name("{}"), None);
    }
}
