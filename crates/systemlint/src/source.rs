// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Reads files and file metadata with every path, symlinks included, resolved inside one root.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, openat2};
use systemlint_protocol::{FileKind, Stat};

/// How often an `openat2` that raced a rename (`EAGAIN`) is retried.
const RETRIES: u32 = 8;

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
            (io::ErrorKind::NotFound, "Pass the directory an image is unpacked or mounted at."),
            (io::ErrorKind::NotADirectory, "Pass a directory, such as an unpacked image’s root."),
            (io::ErrorKind::PermissionDenied, "Run with sudo, or pick a root you can read."),
        ];
        let explain = |e: &io::Error| crate::explain::io("open root", path, e, &fixes);
        let path = path.canonicalize().map_err(|e| explain(&e))?;
        let fd = rustix::fs::open(&path, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).map_err(|e| explain(&e.into()))?;
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
            match openat2(&self.fd, path, flags | OFlags::CLOEXEC, Mode::empty(), resolve) {
                Err(rustix::io::Errno::AGAIN) if tries < RETRIES => {
                    tries += 1;
                    log::debug!("openat2 {path} raced a rename, try {tries} of {RETRIES}");
                }
                Err(rustix::io::Errno::NOSYS) => return Err(io::Error::other("openat2 is missing; systemlint needs Linux 5.6 or later")),
                result => return result.map_err(io::Error::from),
            }
        }
    }

    /// Every path matching the absolute `pattern`, sorted; `*` and `?` match within one component and never a leading dot.
    pub fn glob(&self, pattern: &str) -> Result<Vec<String>, String> {
        let parts: Vec<&str> = pattern.split('/').filter(|p| !p.is_empty()).collect();
        let mut found = vec![String::new()];
        for part in parts {
            let mut next = Vec::new();
            for base in &found {
                if !part.contains(['*', '?']) {
                    next.push(format!("{base}/{part}"));
                    continue;
                }
                let dir = if base.is_empty() { "/" } else { base };
                let fd = match self.open_at(dir, OFlags::RDONLY | OFlags::DIRECTORY) {
                    Ok(fd) => fd,
                    Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => {
                        log::trace!("glob {pattern}: {dir} is absent, no match under it");
                        continue;
                    }
                    Err(e) => return Err(format!("can’t list {dir}: {e}")),
                };
                for entry in Dir::new(fd).map_err(|e| format!("can’t list {dir}: {e}"))? {
                    let entry = entry.map_err(|e| format!("can’t list {dir}: {e}"))?;
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
        log::debug!("glob {pattern} names {} paths", found.len());
        Ok(found)
    }

    /// The bytes of the regular file at `path`, failing above `cap` bytes.
    pub fn read(&self, path: &str, cap: u64) -> io::Result<Vec<u8>> {
        let file = File::from(self.open_at(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(io::Error::other(format!("larger than {cap} bytes")));
        }
        log::trace!("read {path}: {} bytes", bytes.len());
        Ok(bytes)
    }

    /// `path` opened to change its mode or owner, refusing a final symlink, never blocking on a FIFO.
    pub fn open_for_change(&self, path: &str) -> io::Result<File> {
        self.open_at(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).map(File::from)
    }

    /// The metadata of `path` itself, a final symlink not followed.
    pub fn stat(&self, path: &str) -> io::Result<Stat> {
        let meta = File::from(self.open_at(path, OFlags::PATH | OFlags::NOFOLLOW)?).metadata()?;
        Ok(stat_of(&meta))
    }
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
    }
}

/// Whether `name` matches the one-component `pattern` of `*` and `?`, a leading dot matching only a literal one.
pub fn wildcard(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let (pattern, name): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    matches(&pattern, &name)
}

fn matches(pattern: &[char], name: &[char]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some('*'), _) => matches(&pattern[1..], name) || (!name.is_empty() && matches(pattern, &name[1..])),
        (Some('?'), Some(_)) => matches(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => matches(&pattern[1..], &name[1..]),
        _ => false,
    }
}
