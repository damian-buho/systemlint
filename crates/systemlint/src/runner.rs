// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Runs a plugin or a collector command with an empty environment, a timeout and an output cap.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use systemlint_protocol::{Describe, PROTOCOL};
use wait_timeout::ChildExt;

/// How long a plugin may take to answer `--describe`.
pub const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes read from a plugin’s stdout or stderr.
pub const OUTPUT_CAP: u64 = 16 * 1024 * 1024;

/// How many children can run at once and still be stopped by a signal handler.
pub const MAX_CHILDREN: usize = 64;

/// The pids of the children running now, a process group negated, 0 in a free slot, so a Ctrl-C can stop them.
static CHILDREN: [AtomicI32; MAX_CHILDREN] = [const { AtomicI32::new(0) }; 64];

/// Records `pid` in a free slot, or in none when all [`MAX_CHILDREN`] are taken.
fn track(pid: i32) -> Option<&'static AtomicI32> {
    let slot = CHILDREN.iter().find(|s| {
        s.compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    });
    if slot.is_none() {
        log::debug!("no free slot to track child {pid}, a Ctrl-C leaves it running");
    }
    slot
}

/// Kills a tracked child with SIGKILL, its whole process group when `pid` is negated.
fn kill(pid: i32) -> bool {
    let signal = rustix::process::Signal::KILL;
    match rustix::process::Pid::from_raw(pid.saturating_abs()) {
        Some(group) if pid < 0 => rustix::process::kill_process_group(group, signal).is_ok(),
        Some(one) => rustix::process::kill_process(one, signal).is_ok(),
        None => false,
    }
}

/// Kills every child running now with SIGKILL and returns how many.
pub fn stop_children() -> usize {
    let stop = |pid: i32| pid != 0 && kill(pid);
    CHILDREN
        .iter()
        .filter(|s| stop(s.swap(0, Ordering::SeqCst)))
        .count()
}

/// The pids of the children running now.
pub fn running() -> Vec<i32> {
    CHILDREN
        .iter()
        .map(|s| s.load(Ordering::SeqCst).saturating_abs())
        .filter(|&p| p > 0)
        .collect()
}

/// What a finished program printed, and how it exited.
#[derive(Debug)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
}

impl Output {
    /// The exit code, or 128 plus the signal that killed it.
    pub fn code(&self) -> i32 {
        self.status
            .code()
            .or_else(|| self.status.signal().map(|s| 128 + s))
            .unwrap_or(-1)
    }
}

/// The namespaces of a running process a command joins, and the capabilities it keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inside {
    /// The process, by its PID in this core’s namespace.
    pub pid: u32,
    /// The `CLONE_NEW*` namespaces it holds that differ from this core’s.
    pub namespaces: i32,
    /// Its capability bounding set, which the command is cut down to.
    pub bounding: u64,
    /// Its AppArmor label, the command’s on its exec, `None` when unconfined.
    pub apparmor: Option<String>,
    /// Whether it runs under a seccomp filter, which the command does not get.
    pub seccomp: bool,
    /// The core binary, run as the helper that enters the namespaces.
    pub helper: std::path::PathBuf,
}

/// One namespace a container can hold apart: its `/proc/<pid>/ns` name and `CLONE_NEW*` flag, the user namespace first so the rest join under it.
const NAMESPACES: [(&str, i32); 8] = [
    ("user", libc::CLONE_NEWUSER),
    ("mnt", libc::CLONE_NEWNS),
    ("pid", libc::CLONE_NEWPID),
    ("net", libc::CLONE_NEWNET),
    ("ipc", libc::CLONE_NEWIPC),
    ("uts", libc::CLONE_NEWUTS),
    ("cgroup", libc::CLONE_NEWCGROUP),
    ("time", libc::CLONE_NEWTIME),
];

impl Inside {
    /// The namespaces of `pid` that differ from this core’s, compared by inode, and its bounding set from `status`.
    pub fn of(pid: u32, status: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let mut namespaces = 0;
        for (name, flag) in NAMESPACES {
            let theirs = std::fs::metadata(format!("/proc/{pid}/ns/{name}"));
            let ours = std::fs::metadata(format!("/proc/self/ns/{name}"));
            match (theirs, ours) {
                (Ok(t), Ok(o)) if (t.dev(), t.ino()) != (o.dev(), o.ino()) => namespaces |= flag,
                (Err(e), _) if name != "time" => return Err(e),
                _ => {}
            }
        }
        let bounding = bounding(status).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no CapBnd line")
        })?;
        let apparmor = match std::fs::read_to_string(format!("/proc/{pid}/attr/apparmor/current")) {
            Ok(text) => apparmor_label(&text).map(str::to_owned),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::EINVAL) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        let seccomp = filtered(status);
        let helper = std::env::current_exe()?;
        log::debug!(
            "process {pid} holds namespaces {namespaces:#x}, bounding {bounding:#x}, apparmor {apparmor:?}, seccomp filter {seccomp}"
        );
        Ok(Self {
            pid,
            namespaces,
            bounding,
            apparmor,
            seccomp,
            helper,
        })
    }
}

/// The confining label of an AppArmor `attr/current` text, its ` (mode)` cut, or `None` for `unconfined`.
pub fn apparmor_label(text: &str) -> Option<&str> {
    let text = text.trim_end_matches(['\n', '\0']);
    let label = text
        .strip_suffix(')')
        .and_then(|t| t.rsplit_once(" ("))
        .map_or(text, |(label, _)| label);
    Some(label).filter(|l| !l.is_empty() && *l != "unconfined")
}

/// Whether a `/proc/<pid>/status` text says the process runs under a seccomp filter (`Seccomp: 2`).
pub fn filtered(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .is_some_and(|mode| mode.trim() == "2")
}

/// The `CapBnd` mask of a `/proc/<pid>/status` text.
pub fn bounding(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapBnd:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// The hidden first argument that turns the core into the helper entering a container’s namespaces.
const ENTER: &str = "__enter";

/// Where a task asks AppArmor for the label its next exec takes.
const ONEXEC: &str = "/proc/thread-self/attr/apparmor/exec";

/// Runs as the namespace helper when the first argument is [`ENTER`], returning its exit code, else `None`.
pub fn helper() -> Option<std::process::ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.strip_prefix(&[ENTER.to_owned()])?;
    let code = enter(rest).unwrap_or_else(|error| {
        let report = std::io::stdin();
        let _ = rustix::io::write(report.as_fd(), error.as_bytes());
        1
    });
    Some(std::process::ExitCode::from(code))
}

/// As the helper, `PID NAMESPACES BOUNDING LABEL PATH ARG…`: asks AppArmor for `LABEL` on exec, joins the namespaces of `PID`, keeps only `BOUNDING` capabilities, then runs `PATH` so it lands in the PID namespace, exiting as it did.
fn enter(args: &[String]) -> Result<u8, String> {
    let [pid, namespaces, bounding, label, path, rest @ ..] = args else {
        return Err(format!(
            "{ENTER} takes PID NAMESPACES BOUNDING LABEL PATH ARG…, got {args:?}"
        ));
    };
    let number = |text: &str| text.parse::<u64>().map_err(|e| format!("{text}: {e}"));
    let (bounding, namespaces) = (number(bounding)?, number(namespaces)?);
    let pid = i32::try_from(number(pid)?)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| format!("{pid} is no process"))?;
    let null =
        std::fs::File::open("/dev/null").map_err(|e| format!("can’t open /dev/null: {e}"))?;
    let own = std::fs::read_to_string("/proc/self/attr/apparmor/current").unwrap_or_default();
    if !label.is_empty() && apparmor_label(&own) != Some(label.as_str()) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(ONEXEC)
            .and_then(|mut f| f.write_all(format!("exec {label}").as_bytes()))
            .map_err(|e| format!("can’t ask AppArmor for {label}: {e}"))?;
    }
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        .map_err(|e| format!("can’t reach process {}: {e}", pid.as_raw_nonzero()))?;
    let flags = rustix::thread::ThreadNameSpaceType::from_bits_retain(namespaces as u32);
    if !flags.is_empty() {
        rustix::thread::move_into_thread_name_spaces(pidfd.as_fd(), flags)
            .map_err(|e| format!("can’t join namespaces {namespaces:#x}: {e}"))?;
    }
    drop(pidfd);
    let _ = rustix::thread::clear_ambient_capability_set();
    for cap in (0..64).filter(|c| bounding & (1 << c) == 0) {
        let _ = rustix::thread::remove_capability_from_bounding_set(
            rustix::thread::CapabilitySet::from_bits_retain(1 << cap),
        );
    }
    let keep = rustix::thread::CapabilitySet::from_bits_retain(bounding);
    let mut sets = rustix::thread::capabilities(None).map_err(|e| format!("capget: {e}"))?;
    sets.effective &= keep;
    sets.permitted &= keep;
    sets.inheritable &= keep;
    rustix::thread::set_capabilities(None, sets).map_err(|e| format!("capset: {e}"))?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no-new-privs: {e}"))?;
    let status = Command::new(path)
        .args(rest)
        .stdin(null)
        .status()
        .map_err(|e| format!("can’t start it: {e}"))?;
    let code = status.code().or_else(|| status.signal().map(|s| 128 + s));
    Ok(code.and_then(|c| u8::try_from(c).ok()).unwrap_or(255))
}

/// Runs `path` with `args` and `stdin`, inside another process’s namespaces when `inside` names one, failing on a timeout or an output over `cap` bytes; any exit code is returned.
pub fn run(
    path: &Path,
    args: &[&str],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cap: u64,
    inside: Option<&Inside>,
) -> Result<Output, String> {
    log::debug!(
        "running {} {} with {} bytes on stdin, inside {inside:?}",
        path.display(),
        args.join(" "),
        stdin.as_ref().map_or(0, Vec::len)
    );
    let (mut command, report) = match inside {
        Some(_) if stdin.is_some() => return Err("can’t pass stdin into a container".to_owned()),
        Some(inside) => {
            let (reader, writer) =
                std::io::pipe().map_err(|e| format!("can’t open a pipe: {e}"))?;
            let mut command = Command::new(&inside.helper);
            command
                .arg(ENTER)
                .args([inside.pid.to_string(), inside.namespaces.to_string()])
                .arg(inside.bounding.to_string())
                .arg(inside.apparmor.as_deref().unwrap_or_default())
                .arg(path)
                .stdin(writer)
                .process_group(0);
            (command, Some(reader))
        }
        None => {
            let mut command = Command::new(path);
            command.stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
            (command, None)
        }
    };
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let spawned = command.spawn();
    drop(command);
    let mut child = spawned.map_err(|e| format!("can’t start it: {e}"))?;
    let pid = i32::try_from(child.id()).unwrap_or_default();
    let tracked = if report.is_some() { -pid } else { pid };
    let slot = track(tracked);
    let feed = child
        .stdin
        .take()
        .zip(stdin)
        .map(|(mut pipe, bytes)| std::thread::spawn(move || pipe.write_all(&bytes)));
    let drain = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(stream) = stream {
                let _ = stream.take(cap + 1).read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let waited = child.wait_timeout(timeout);
    if let Some(slot) = slot {
        let _ = slot.compare_exchange(tracked, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    let status = match waited.map_err(|e| format!("can’t wait for it: {e}"))? {
        Some(status) => status,
        None => {
            log::debug!(
                "{} passed its {}s timeout, killing it",
                path.display(),
                timeout.as_secs()
            );
            kill(tracked);
            let _ = child.wait();
            return Err(format!("gave no answer within {}s", timeout.as_secs()));
        }
    };
    let mut refused = String::new();
    if let Some(mut reader) = report {
        let _ = reader.read_to_string(&mut refused);
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    if let Some(Ok(Err(error))) = feed.map(std::thread::JoinHandle::join) {
        log::debug!("{} closed stdin early: {error}", path.display());
    }
    let output = Output {
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
        status,
    };
    if output.stdout.len() as u64 > cap || output.stderr.len() as u64 > cap {
        return Err(format!("printed more than {cap} bytes"));
    }
    log::debug!(
        "{} exited {} with {} bytes on stdout",
        path.display(),
        output.code(),
        output.stdout.len()
    );
    Ok(output)
}

/// Runs `path` like [`run`], also failing on a non-zero exit.
pub fn call(
    path: &Path,
    args: &[&str],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cap: u64,
) -> Result<Output, String> {
    let output = run(path, args, stdin, timeout, cap, None)?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stderr);
        return Err(match said.trim() {
            "" => format!("exited with {}", output.status),
            said => said.to_owned(),
        });
    }
    Ok(output)
}

/// Reads the plugin’s `--describe`, refusing another protocol or a name that differs from its filename.
pub fn describe(name: &str, path: &Path, timeout: Duration) -> Result<Describe, String> {
    let output = call(path, &["--describe"], None, timeout, OUTPUT_CAP)?;
    let describe: Describe = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("--describe is not valid protocol JSON: {e}"))?;
    if describe.protocol != PROTOCOL {
        return Err(format!(
            "speaks protocol {}, this systemlint speaks {PROTOCOL}; install matching versions",
            describe.protocol
        ));
    }
    if describe.name != name {
        return Err(format!(
            "calls itself {}, its filename says {name}",
            describe.name
        ));
    }
    log::debug!(
        "plugin {name} {} offers {} ops",
        describe.version,
        describe.ops.len()
    );
    Ok(describe)
}
