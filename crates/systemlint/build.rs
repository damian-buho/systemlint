// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

// Writes `rulesets.rs`, every shipped `rulesets/*.yaml` by file stem, for the built-in rule catalog.
fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../rulesets");
    println!("cargo::rerun-if-changed={}", dir.display());
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    let entries: String = files
        .iter()
        .map(|path| {
            let path = path.canonicalize().unwrap();
            let stem = path.file_stem().unwrap().to_string_lossy();
            println!("cargo::rerun-if-changed={}", path.display());
            format!(
                "    ({stem:?}, include_str!({:?})),\n",
                path.display().to_string()
            )
        })
        .collect();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("rulesets.rs");
    std::fs::write(out, format!("&[\n{entries}]\n")).unwrap();
}
