// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

// Numbers each temporary file, so two test threads of one process never share a name.
static NEXT: AtomicU64 = AtomicU64::new(0);

// One fixture entry: a path under the root, its content (`None` for a directory) and its mode.
pub type Entry<'a> = (&'a str, Option<&'a str>, u32);

// Builds `entries` under `root` so a concurrent test only ever sees a complete file at its final mode.
pub fn build(root: &Path, entries: &[Entry]) {
    for &(path, content, mode) in entries {
        let full = root.join(path);
        match content {
            Some(text) => {
                let temporary = full.with_file_name(format!(
                    ".{}.{}.{}",
                    full.file_name().unwrap().to_string_lossy(),
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                fs::write(&temporary, text).unwrap();
                fs::set_permissions(&temporary, fs::Permissions::from_mode(mode)).unwrap();
                fs::rename(&temporary, &full).unwrap();
            }
            None => {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(mode)
                    .create(&full)
                    .unwrap();
                fs::set_permissions(&full, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }
}
