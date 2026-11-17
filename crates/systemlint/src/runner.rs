// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Runs a plugin or a collector command with an empty environment, a timeout and an output cap.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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

/// The pids of the children running now, 0 in a free slot, so a signal handler can stop them.
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

/// Kills every child running now with SIGKILL and returns how many; async-signal-safe, for a signal handler.
pub fn stop_children() -> usize {
    let stop = |pid: i32| pid > 0 && unsafe { libc::kill(pid, libc::SIGKILL) } == 0;
    CHILDREN
        .iter()
        .filter(|s| stop(s.swap(0, Ordering::SeqCst)))
        .count()
}

/// The pids of the children running now.
pub fn running() -> Vec<i32> {
    CHILDREN
        .iter()
        .map(|s| s.load(Ordering::SeqCst))
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inside {
    /// The process, by its PID in this core’s namespace.
    pub pid: u32,
    /// The `CLONE_NEW*` namespaces it holds that differ from this core’s.
    pub namespaces: i32,
    /// Its capability bounding set, which the command is cut down to.
    pub bounding: u64,
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
        log::debug!("process {pid} holds namespaces {namespaces:#x}, bounding {bounding:#x}");
        Ok(Self {
            pid,
            namespaces,
            bounding,
        })
    }
}

/// The `CapBnd` mask of a `/proc/<pid>/status` text.
pub fn bounding(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapBnd:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// The kernel’s capability header and one 32-bit half of each set, as `capset(2)` takes them.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`, two [`CapData`] halves.
const CAP_VERSION_3: u32 = 0x2008_0522;

/// In a forked child: joins `inside`’s namespaces through `pidfd`, forks once more so the command lands in its PID namespace, and keeps only its capabilities; the middle process waits and exits as the command did.
///
/// # Safety
/// Runs between fork and exec, so it calls only async-signal-safe functions.
unsafe fn enter(pidfd: i32, inside: Inside) -> std::io::Result<()> {
    let last = std::io::Error::last_os_error;
    // SAFETY: signal, setns, fork, waitpid, close_range, prctl, capset and _exit are async-signal-safe syscalls on plain values.
    unsafe {
        // The inherited wait-timeout SIGCHLD handler writes to a pipe close_range shuts, and panics.
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        if inside.namespaces != 0 && libc::setns(pidfd, inside.namespaces) != 0 {
            return Err(last());
        }
        match libc::fork() {
            -1 => return Err(last()),
            0 => {}
            child => {
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
                let mut status = 0;
                while libc::waitpid(child, &raw mut status, 0) == -1 {}
                libc::_exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
        }
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        for cap in (0..64).filter(|c| inside.bounding & (1 << c) == 0) {
            libc::prctl(libc::PR_CAPBSET_DROP, cap);
        }
        let mut header = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) != 0 {
            return Err(last());
        }
        for (half, set) in data.iter_mut().enumerate() {
            let keep = (inside.bounding >> (32 * half)) as u32;
            set.effective &= keep;
            set.permitted &= keep;
            set.inheritable &= keep;
        }
        if libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) != 0 {
            return Err(last());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(last());
        }
    }
    Ok(())
}

/// Runs `path` with `args` and `stdin`, inside another process’s namespaces when `inside` names one, failing on a timeout or an output over `cap` bytes; any exit code is returned.
pub fn run(
    path: &Path,
    args: &[&str],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cap: u64,
    inside: Option<Inside>,
) -> Result<Output, String> {
    log::debug!(
        "running {} {} with {} bytes on stdin, inside {inside:?}",
        path.display(),
        args.join(" "),
        stdin.as_ref().map_or(0, Vec::len)
    );
    let mut command = Command::new(path);
    let pidfd = match inside {
        Some(inside) => {
            // SAFETY: pidfd_open takes a PID and flags and returns a new descriptor or -1.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, inside.pid, 0) };
            if fd < 0 {
                return Err(format!(
                    "can’t reach process {}: {}",
                    inside.pid,
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: the kernel just returned this descriptor, owned by nobody else.
            let fd = unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap_or(-1)) };
            let raw = fd.as_raw_fd();
            // SAFETY: enter calls only async-signal-safe functions, and the pidfd outlives the spawn.
            unsafe { command.pre_exec(move || enter(raw, inside)) };
            Some(fd)
        }
        None => None,
    };
    let mut child = command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("can’t start it: {e}"))?;
    drop(pidfd);
    let pid = i32::try_from(child.id()).unwrap_or_default();
    let slot = track(pid);
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
        let _ = slot.compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    let status = match waited.map_err(|e| format!("can’t wait for it: {e}"))? {
        Some(status) => status,
        None => {
            log::debug!(
                "{} passed its {}s timeout, killing it",
                path.display(),
                timeout.as_secs()
            );
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("gave no answer within {}s", timeout.as_secs()));
        }
    };
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
        return Err(format!("exited with {}: {}", output.status, said.trim()));
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
