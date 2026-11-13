// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Runs a plugin or a collector command with an empty environment, a timeout and an output cap.

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
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

/// Runs `path` with `args` and `stdin`, failing on a timeout or an output over `cap` bytes; any exit code is returned.
pub fn run(
    path: &Path,
    args: &[&str],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cap: u64,
) -> Result<Output, String> {
    log::debug!(
        "running {} {} with {} bytes on stdin",
        path.display(),
        args.join(" "),
        stdin.as_ref().map_or(0, Vec::len)
    );
    let mut child = Command::new(path)
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
    let output = run(path, args, stdin, timeout, cap)?;
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
