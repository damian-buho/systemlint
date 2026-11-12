// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use systemlint::crash::{ISSUES, directory, issue_url, report, save};

#[test]
fn the_directory_prefers_an_absolute_xdg_state_home() {
    let env = |state: Option<&'static str>| move |name: &str| match name {
        "XDG_STATE_HOME" => state.map(str::to_owned),
        "HOME" => Some("/home/u".to_owned()),
        _ => None,
    };
    assert_eq!(directory(env(Some("/s"))), Some(PathBuf::from("/s/systemlint")));
    assert_eq!(directory(env(Some("relative"))), Some(PathBuf::from("/home/u/.local/state/systemlint")));
    assert_eq!(directory(env(None)), Some(PathBuf::from("/home/u/.local/state/systemlint")));
    assert_eq!(directory(|_| None), None);
}

#[test]
fn the_report_names_version_platform_args_and_panic() {
    let text = report("boom", "src/x.rs:1:2", &["systemlint".into(), "lint".into()], "trace");
    for part in [systemlint_protocol::VERSION, std::env::consts::ARCH, "[\"systemlint\", \"lint\"]", "panic: boom", "at: src/x.rs:1:2", "trace"] {
        assert!(text.contains(part), "{part}: {text}");
    }
}

#[test]
fn a_saved_report_is_private_in_a_private_directory() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("crash");
    let _ = std::fs::remove_dir_all(&dir);
    let path = save(&dir.join("systemlint"), "report").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "report");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(dir.join("systemlint")).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn the_issue_url_is_encoded_and_leaves_the_args_out() {
    let url = issue_url("a b/ü", "src/x.rs:1:2");
    assert!(url.starts_with(&format!("{ISSUES}?title=crash%3A%20a%20b%2F%C3%BC&body=")), "{url}");
    assert!(url.contains("src%2Fx.rs%3A1%3A2"), "{url}");
    assert!(!url.contains(' '), "{url}");
}
