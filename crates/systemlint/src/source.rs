// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Reads files and file metadata with every path, symlinks included, resolved inside one root.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{Dir, FileType, Mode, OFlags, ResolveFlags, StatVfsMountFlags, openat2};
use sha2::{Digest as _, Sha256, Sha512};
use systemlint_protocol::{FileKind, Stat, Statfs};

use crate::collector::Digest;

/// How often an `openat2` that raced a rename (`EAGAIN`) is retried.
const RETRIES: u32 = 8;

/// The most paths one glob’s `**` may name before it fails.
pub const WALK_CAP: usize = 1_000_000;

/// Why a read failed: the kernel refused the action and path in `Denied`, anything else in `Other`.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Denied(String),
    Other(String),
}

impl Failure {
    /// `can’t {verb} {path}`, `Denied` when the error is a refusal.
    pub fn of(verb: &str, path: &str, error: impl Into<io::Error>) -> Self {
        let error = error.into();
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::Denied(format!("{verb} {path}")),
            _ => Self::Other(format!("can’t {verb} {path}: {error}")),
        }
    }

    /// `prefix: ` before an `Other` reason; a refusal keeps its own words.
    pub fn within(self, prefix: &str) -> Self {
        match self {
            Self::Other(reason) => Self::Other(format!("{prefix}: {reason}")),
            denied => denied,
        }
    }
}

impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self::Other(reason)
    }
}

impl From<Failure> for String {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Denied(what) => format!("can’t {what}: permission denied"),
            Failure::Other(reason) => reason,
        }
    }
}

/// A directory every path is resolved inside, `/` on a live host.
#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
    path: PathBuf,
}

impl Root {
    /// Opens `path` as the root; on a live host that is `/`.
    pub fn open(path: &Path) -> Result<Self, String> {
        let fixes = [
            (
                io::ErrorKind::NotFound,
                "Pass the directory an image is unpacked or mounted at.",
            ),
            (
                io::ErrorKind::NotADirectory,
                "Pass a directory, such as an unpacked image’s root.",
            ),
            (
                io::ErrorKind::PermissionDenied,
                "Run with sudo, or pick a root you can read.",
            ),
        ];
        let explain = |e: &io::Error| crate::explain::io("open root", path, e, &fixes);
        let path = path.canonicalize().map_err(|e| explain(&e))?;
        let fd = rustix::fs::open(
            &path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| explain(&e.into()))?;
        log::debug!("root {} opened", path.display());
        Ok(Self { fd, path })
    }

    /// The canonical path of the root on this host.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_at(&self, path: &str, flags: OFlags) -> io::Result<OwnedFd> {
        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS;
        let mut tries = 0;
        loop {
            match openat2(
                &self.fd,
                path,
                flags | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            ) {
                Err(rustix::io::Errno::AGAIN) if tries < RETRIES => {
                    tries += 1;
                    log::debug!("openat2 {path} raced a rename, try {tries} of {RETRIES}");
                }
                Err(rustix::io::Errno::NOSYS) => {
                    return Err(io::Error::other(
                        "openat2 is missing; systemlint needs Linux 5.6 or later",
                    ));
                }
                result => return result.map_err(io::Error::from),
            }
        }
    }

    /// Every path matching the absolute `pattern`, sorted; `*` and `?` match within one component and never a leading dot, `**` as the whole last component every path below, see [`Root::walk`].
    pub fn glob(&self, pattern: &str) -> Result<Vec<String>, Failure> {
        self.glob_under("", pattern)
    }

    /// Like [`Root::glob`], below the literal `base`, whose own `*` and `?` match nothing.
    pub fn glob_under(&self, base: &str, pattern: &str) -> Result<Vec<String>, Failure> {
        let parts: Vec<&str> = pattern.split('/').filter(|p| !p.is_empty()).collect();
        if parts.iter().rev().skip(1).any(|p| p.contains("**"))
            || parts.last().is_some_and(|p| p.contains("**") && *p != "**")
        {
            return Err(format!("glob {pattern}: ** is only a whole last component").into());
        }
        let mut found = vec![base.trim_end_matches('/').to_owned()];
        for part in parts {
            let mut next = Vec::new();
            for base in &found {
                if part == "**" {
                    self.walk(base, WALK_CAP, &mut next)
                        .map_err(|e| e.within(&format!("glob {pattern}")))?;
                    continue;
                }
                if !part.contains(['*', '?']) {
                    next.push(format!("{base}/{part}"));
                    continue;
                }
                let dir = if base.is_empty() { "/" } else { base };
                let fd = match self.open_at(dir, OFlags::RDONLY | OFlags::DIRECTORY) {
                    Ok(fd) => fd,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) =>
                    {
                        log::trace!("glob {pattern}: {dir} is absent, no match under it");
                        continue;
                    }
                    Err(e) => return Err(Failure::of("list", dir, e)),
                };
                for entry in Dir::new(fd).map_err(|e| Failure::of("list", dir, e))? {
                    let entry = entry.map_err(|e| Failure::of("list", dir, e))?;
                    let name = entry.file_name().to_string_lossy();
                    if name != "." && name != ".." && wildcard(part, &name) {
                        next.push(format!("{base}/{name}"));
                    }
                }
            }
            found = next;
        }
        found.sort();
        found.dedup();
        log::debug!("glob {base}{pattern} names {} paths", found.len());
        Ok(found)
    }

    /// Appends `base` and every path below it, dotted names included, never entering another filesystem or a symlinked directory; fails once `out` holds more than `cap` paths.
    pub fn walk(&self, base: &str, cap: usize, out: &mut Vec<String>) -> Result<(), Failure> {
        let skipped = |e: &io::Error| {
            matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) || e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
        };
        out.push(if base.is_empty() { "/" } else { base }.to_owned());
        let (mut pending, mut device) = (vec![base.to_owned()], None);
        while let Some(dir) = pending.pop() {
            let at = if dir.is_empty() { "/" } else { &dir };
            let fd = match self.open_at(at, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW) {
                Ok(fd) => fd,
                Err(e) if skipped(&e) => {
                    log::trace!("walk {base}: {at} is no directory to enter: {e}");
                    continue;
                }
                Err(e) => return Err(Failure::of("list", at, e)),
            };
            let here = rustix::fs::fstat(&fd)
                .map_err(|e| Failure::of("stat", at, e))?
                .st_dev;
            match device {
                Some(start) if start != here => {
                    log::debug!("walk {base}: {at} is another filesystem, not entered");
                    continue;
                }
                _ => device = Some(here),
            }
            for entry in Dir::new(fd).map_err(|e| Failure::of("list", at, e))? {
                let entry = entry.map_err(|e| Failure::of("list", at, e))?;
                let name = entry.file_name().to_string_lossy();
                if name == "." || name == ".." {
                    continue;
                }
                let path = format!("{dir}/{name}");
                if matches!(entry.file_type(), FileType::Directory | FileType::Unknown) {
                    pending.push(path.clone());
                }
                out.push(path);
                if out.len() > cap {
                    return Err(format!("names more than {cap} paths; narrow it").into());
                }
            }
        }
        log::debug!("walk {base}: {} paths so far", out.len());
        Ok(())
    }

    /// The bytes of the regular file at `path`, failing above `cap` bytes.
    pub fn read(&self, path: &str, cap: u64) -> io::Result<Vec<u8>> {
        let file =
            File::from(self.open_at(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(io::Error::other(format!("larger than {cap} bytes")));
        }
        log::trace!("read {path}: {} bytes", bytes.len());
        Ok(bytes)
    }

    /// The lowercase hex digests of the regular file at `path`, read in one pass.
    pub fn digests(
        &self,
        path: &str,
        digests: &[Digest],
    ) -> io::Result<(Option<String>, Option<String>)> {
        let mut file =
            File::from(self.open_at(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let (mut sha256, mut sha512) = (
            digests.contains(&Digest::Sha256).then(Sha256::new),
            digests.contains(&Digest::Sha512).then(Sha512::new),
        );
        let (mut buffer, mut total) = (vec![0u8; 64 * 1024], 0u64);
        loop {
            let n = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            total += n as u64;
            sha256.iter_mut().for_each(|h| h.update(&buffer[..n]));
            sha512.iter_mut().for_each(|h| h.update(&buffer[..n]));
        }
        log::trace!("digests {path}: {total} bytes");
        Ok((
            sha256.map(|h| hex(&h.finalize())),
            sha512.map(|h| hex(&h.finalize())),
        ))
    }

    /// `path` opened to change its mode or owner, refusing a final symlink, never blocking on a FIFO.
    pub fn open_for_change(&self, path: &str) -> io::Result<File> {
        self.open_at(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        )
        .map(File::from)
    }

    /// `path` opened to rewrite in place, refusing a final symlink, never blocking on a FIFO.
    pub fn open_for_edit(&self, path: &str) -> io::Result<File> {
        self.open_at(
            path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        )
        .map(File::from)
    }

    /// The metadata of `path` itself, a final symlink not followed.
    pub fn stat(&self, path: &str) -> io::Result<Stat> {
        let fd = self.open_at(path, OFlags::PATH | OFlags::NOFOLLOW)?;
        let mut stat = stat_of(&File::from(fd.try_clone()?).metadata()?);
        if stat.kind == FileKind::Symlink {
            let target = rustix::fs::readlinkat(&fd, "", Vec::new())?;
            stat.linked_to = Some(target.to_string_lossy().into_owned());
            log::trace!("stat {path}: links to {:?}", stat.linked_to);
        }
        Ok(stat)
    }

    /// The filesystem holding `path`, failing as `TimedOut` when it gives no answer within `timeout`, as a dead network mount does.
    pub fn statfs(&self, path: &str, timeout: Duration) -> io::Result<Statfs> {
        let root = Self {
            fd: self.fd.try_clone()?,
            path: self.path.clone(),
        };
        let (sender, answer) = std::sync::mpsc::channel();
        let owned = path.to_owned();
        std::thread::spawn(move || {
            let result = root
                .open_at(&owned, OFlags::PATH)
                .and_then(|fd| rustix::fs::fstatvfs(&fd).map_err(io::Error::from));
            sender.send(result).ok()
        });
        let vfs = answer.recv_timeout(timeout).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("statfs gave no answer within {} s", timeout.as_secs()),
            )
        })??;
        log::trace!(
            "statfs {path}: {} blocks, {} files",
            vfs.f_blocks,
            vfs.f_files
        );
        Ok(Statfs {
            blocks: vfs.f_blocks,
            blocks_free: vfs.f_bfree,
            blocks_available: vfs.f_bavail,
            files: vfs.f_files,
            files_free: vfs.f_ffree,
            read_only: vfs.f_flag.contains(StatVfsMountFlags::RDONLY),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The protocol [`Stat`] of `meta`; a symlink’s meaningless 0777 sets no writable boolean.
pub fn stat_of(meta: &std::fs::Metadata) -> Stat {
    let kind = match meta.file_type() {
        t if t.is_symlink() => FileKind::Symlink,
        t if t.is_dir() => FileKind::Directory,
        t if t.is_file() => FileKind::File,
        _ => FileKind::Other,
    };
    let mode = meta.mode() & 0o7777;
    let bits = if kind == FileKind::Symlink { 0 } else { mode };
    Stat {
        kind,
        mode: format!("{mode:04o}"),
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.size(),
        world_writable: bits & 0o002 != 0,
        group_writable: bits & 0o020 != 0,
        setuid: bits & 0o4000 != 0,
        setgid: bits & 0o2000 != 0,
        linked_to: None,
        sha256: None,
        sha512: None,
    }
}

/// Whether `name` matches the one-component `pattern` of `*` and `?`, a leading dot matching only a literal one.
pub fn wildcard(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let (pattern, name): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), name.chars().collect());
    matches(&pattern, &name)
}

fn matches(pattern: &[char], name: &[char]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            matches(&pattern[1..], name) || (!name.is_empty() && matches(pattern, &name[1..]))
        }
        (Some('?'), Some(_)) => matches(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => matches(&pattern[1..], &name[1..]),
        _ => false,
    }
}
