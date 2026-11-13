// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Reads and writes facts documents, YAML or JSON.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde_json::Value;

use crate::collect::SCHEMA;

/// The document as YAML, or as indented JSON when `json`.
pub fn render(document: &Value, json: bool) -> Result<String, String> {
    if json {
        return serde_json::to_string_pretty(document).map(|s| s + "\n").map_err(|e| format!("can’t encode the facts as JSON: {e}"));
    }
    serde_saphyr::to_string(document).map_err(|e| format!("can’t encode the facts as YAML: {e}"))
}

/// Writes `document` to `path` atomically with mode 0600, as JSON when the name ends in `.json`, else YAML.
pub fn save(document: &Value, path: &Path) -> Result<(), String> {
    let text = render(document, path.extension().is_some_and(|x| x == "json"))?;
    write(path, &text, 0o600)
}

/// Writes `text` to stdout for `-`, else to `path` with `mode` through a temporary sibling and a rename, so a reader never sees half of it.
pub fn write(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    if path == Path::new("-") {
        log::debug!("writing {} bytes to stdout", text.len());
        let mut out = std::io::stdout().lock();
        return out.write_all(text.as_bytes()).and_then(|()| out.flush()).map_err(|e| format!("can’t write to stdout: {e}"));
    }
    let name = path.file_name().ok_or_else(|| format!("{} names no file", path.display()))?.to_string_lossy();
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()))
        .and_then(|()| std::fs::rename(&temporary, path));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        if let Some(kind) = pseudo(dir) {
            return Err(format!("Can’t write {name} into {}: it is on {kind}, a kernel file system that holds no ordinary files. Pick a directory on a regular file system.", dir.display()));
        }
        let error =if error.kind() == ErrorKind::NotFound && dir.is_dir() { std::io::Error::other(error) } else { error };
        let mkdir = format!("Run mkdir -p {}, or pick another path.", dir.display());
        let fixes = [(ErrorKind::NotFound, mkdir.as_str()), (ErrorKind::PermissionDenied, "Pick a directory you can write, or run with sudo."), (ErrorKind::ReadOnlyFilesystem, "Pick a path on a writable file system.")];
        return Err(crate::explain::io(&format!("write {name} into"), dir, &error, &fixes));
    }
    log::debug!("saved {} bytes to {} with mode {mode:o}", text.len(), path.display());
    Ok(())
}

/// The kernel file system `dir` sits on, by its `statfs` magic, when it is `/proc` or `/sys`.
fn pseudo(dir: &Path) -> Option<&'static str> {
    let magic = i128::from(rustix::fs::statfs(dir).ok()?.f_type);
    let kind = [(0x9fa0, "proc"), (0x6265_6572, "sysfs")].into_iter().find(|(m, _)| *m == magic).map(|(_, kind)| kind);
    log::debug!("{} has file system magic {magic:#x}, pseudo {kind:?}", dir.display());
    kind
}

/// Reads a facts document from `path`, or stdin for `-`, refusing another schema.
pub fn load(path: &Path) -> Result<Value, String> {
    let mut text = String::new();
    let read = if path == Path::new("-") { std::io::stdin().read_to_string(&mut text).map(drop) } else { std::fs::read_to_string(path).map(|t| text = t) };
    read.map_err(|e| {
        let first = format!("Run systemlint facts --output {} first, or pass - to read stdin.", path.display());
        let owner = format!("A saved document is mode 0600: run sudo chown \"$(id -un)\" {}, or lint as the user who saved it.", path.display());
        crate::explain::io("read facts", path, &e, &[(ErrorKind::NotFound, &first), (ErrorKind::PermissionDenied, &owner), (ErrorKind::IsADirectory, "Name a facts file, or pass - to read stdin.")])
    })?;
    log::debug!("read {} bytes of facts from {}", text.len(), path.display());
    parse(&text).map_err(|e| format!("{} is not a facts document: {e}", path.display()))
}

/// Parses a facts document from YAML or JSON text, refusing another schema.
pub fn parse(text: &str) -> Result<Value, String> {
    let document: Value = crate::yaml::from_str(text).map_err(|e| e.to_string())?;
    match document.pointer("/meta/schema").and_then(Value::as_u64) {
        Some(schema) if schema == u64::from(SCHEMA) => Ok(document),
        Some(schema) => Err(format!("schema {schema}, this systemlint reads schema {SCHEMA}")),
        None => Err("no meta.schema".to_owned()),
    }
}
