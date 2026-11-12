// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Turns an I/O error into a sentence naming what failed and, for the common kinds, how to fix it.

use std::io::{self, ErrorKind};
use std::path::Path;

/// `Can’t {action} {path}: {what}.`, plain words for a common kind, else the OS text, then the `fixes` entry for that kind.
pub fn io(action: &str, path: &Path, error: &io::Error, fixes: &[(ErrorKind, &str)]) -> String {
    let what = match error.kind() {
        ErrorKind::NotFound => "it does not exist".to_owned(),
        ErrorKind::PermissionDenied => "permission denied".to_owned(),
        ErrorKind::IsADirectory => "it is a directory".to_owned(),
        ErrorKind::NotADirectory => "it is not a directory".to_owned(),
        ErrorKind::ReadOnlyFilesystem => "the file system is read-only".to_owned(),
        ErrorKind::StorageFull => "the disk is full".to_owned(),
        _ => error.to_string(),
    };
    let fix = fixes.iter().find(|(kind, _)| *kind == error.kind()).map_or(String::new(), |(_, fix)| format!(" {fix}"));
    log::debug!("explaining {:?} on {action} {}", error.kind(), path.display());
    format!("Can’t {action} {}: {what}.{fix}", path.display())
}
