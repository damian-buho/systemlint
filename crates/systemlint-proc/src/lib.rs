// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! proc: what running processes hold, grouped by the system service that owns them.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    Describe::new("proc", &[("services", &[]), ("sockets", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "services" => Ok(services(&request.inputs)),
        "sockets" => Ok(sockets(&request.inputs)),
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

/// The kernel’s `st` for a listening TCP socket.
const LISTEN: &str = "0A";
/// The kernel’s `st` for an unconnected UDP socket, which takes datagrams from anyone.
const UNCONNECTED: &str = "07";

/// An address the kernel prints as native-endian 32-bit hex words, IPv4-mapped IPv6 shown as IPv4.
pub fn address(hex: &str) -> Option<IpAddr> {
    let words = (0..hex.len() / 8)
        .map(|i| {
            hex.get(i * 8..i * 8 + 8)
                .and_then(|w| u32::from_str_radix(w, 16).ok())
        })
        .collect::<Option<Vec<u32>>>()?;
    match words[..] {
        [v4] if hex.len() == 8 => Some(IpAddr::V4(Ipv4Addr::from(v4.to_ne_bytes()))),
        [a, b, c, d] if hex.len() == 32 => {
            let mut bytes = [0u8; 16];
            for (chunk, word) in bytes.chunks_exact_mut(4).zip([a, b, c, d]) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            let v6 = Ipv6Addr::from(bytes);
            Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
        }
        _ => None,
    }
}

/// The bound address and port of one `/proc/net/{tcp,udp}[6]` line, when it listens.
pub fn listening(proto: &str, line: &str) -> Option<(IpAddr, u16)> {
    let mut fields = line.split_whitespace();
    let (_, local, _, state) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    (state == if proto == "tcp" { LISTEN } else { UNCONNECTED }).then_some(())?;
    let (host, port) = local.split_once(':')?;
    Some((address(host)?, u16::from_str_radix(port, 16).ok()?))
}

/// Per `<proto>:<port>`, from `/proc/net/{tcp,tcp6,udp,udp6}`: the `addresses` a socket listens on there, IPv4 and IPv6 together.
pub fn sockets(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut ports: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    for input in inputs {
        let Some((path, body)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let file = path.rsplit('/').next().unwrap_or_default();
        let proto = file.trim_end_matches('6');
        if !matches!(proto, "tcp" | "udp") {
            continue;
        }
        for (ip, port) in body.lines().skip(1).filter_map(|l| listening(proto, l)) {
            ports
                .entry(format!("{proto}:{port}"))
                .or_default()
                .insert(ip);
        }
    }
    for (key, ips) in ports {
        let addresses: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
        reply.facts.insert(key, json!({"addresses": addresses}));
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

    // An IPv4 address as the kernel prints it on this host’s byte order.
    fn v4(a: [u8; 4]) -> String {
        format!("{:08X}", u32::from_ne_bytes(a))
    }

    // An IPv6 address as the kernel prints it, four native-endian words.
    fn v6(a: Ipv6Addr) -> String {
        a.octets()
            .chunks_exact(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]])))
            .collect()
    }

    #[test]
    fn address_reads_both_families_and_shows_a_mapped_one_as_ipv4() {
        assert_eq!(
            address(&v4([127, 0, 0, 53])),
            Some("127.0.0.53".parse().unwrap())
        );
        assert_eq!(
            address(&v6(Ipv6Addr::UNSPECIFIED)),
            Some("::".parse().unwrap())
        );
        let lan: Ipv6Addr = "fe80::1:2".parse().unwrap();
        assert_eq!(address(&v6(lan)), Some(IpAddr::V6(lan)));
        let mapped = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
        assert_eq!(address(&v6(mapped)), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(address("0100007"), None, "seven digits");
        assert_eq!(address("0100007G"), None);
        assert_eq!(address(""), None);
    }

    #[test]
    fn sockets_keep_tcp_listeners_and_unconnected_udp_keyed_by_port() {
        let line = |local: &str, st: &str| {
            format!(
                "   0: {local} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
            )
        };
        let header = "  sl  local_address rem_address   st tx_queue\n";
        let any4 = v4([0, 0, 0, 0]);
        let tcp = [
            header.to_owned(),
            line(&format!("{}:0016", v4([127, 0, 0, 1])), "0A"),
            line(&format!("{any4}:0016"), "0A"),
            line(&format!("{any4}:0050"), "01"),
            line(&format!("{any4}:FFFF"), "0A"),
        ]
        .concat();
        let tcp6 = [
            header.to_owned(),
            line(&format!("{}:0016", v6(Ipv6Addr::UNSPECIFIED)), "0A"),
            line(
                &format!("{}:0016", v6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped())),
                "0A",
            ),
        ]
        .concat();
        let udp = [
            header.to_owned(),
            line(&format!("{any4}:0277"), "07"),
            line(&format!("{any4}:0035"), "01"),
        ]
        .concat();
        let reply = sockets(&[
            file("/proc/net/tcp", &tcp),
            file("/proc/net/tcp6", &tcp6),
            file("/proc/net/udp", &udp),
            file("/proc/net/udp6", header),
            file("/proc/net/raw", &tcp),
        ]);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        assert_eq!(
            serde_json::Value::Object(reply.facts.into_iter().collect()),
            json!({
                "tcp:22": {"addresses": ["0.0.0.0", "127.0.0.1", "::"]},
                "tcp:65535": {"addresses": ["0.0.0.0"]},
                "udp:631": {"addresses": ["0.0.0.0"]},
            }),
            "an established socket is no listener, a mapped one merges with IPv4, raw is not read"
        );
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
