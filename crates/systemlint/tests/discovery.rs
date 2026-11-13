// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use systemlint::discovery::{BESIDE, Plugin, Trust, directories, discover};

fn base() -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("discovery");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    base.canonicalize().unwrap()
}

fn fixture(name: &str) -> PathBuf {
    let dir = base().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn file(path: &Path, mode: u32) {
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mine() -> Trust {
    Trust {
        top: base(),
        ..Trust::invoking_user()
    }
}

#[test]
fn beside_is_lib_next_to_bin() {
    let dirs = directories(
        Path::new("/usr/local/bin/systemlint"),
        BESIDE,
        &[PathBuf::from("/opt/plugins")],
    );
    assert_eq!(
        dirs,
        [
            PathBuf::from("/usr/local/bin/../lib/systemlint/plugins"),
            PathBuf::from("/opt/plugins")
        ]
    );
}

#[test]
fn names_need_the_prefix_and_a_slug() {
    let dir = fixture("names");
    for name in [
        "systemlint-apt",
        "systemlint-dnf-repo2",
        "systemlint-",
        "systemlint-apt.d",
        "systemlint-Apt",
        "systemlint",
        "apt",
    ] {
        file(&dir.join(name), 0o755);
    }
    let (plugins, _) = discover(&[dir], &mine());
    assert_eq!(
        plugins.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        ["apt", "dnf-repo2"]
    );
}

#[test]
fn finds_executables_and_skips_the_rest() {
    let dir = fixture("finds");
    file(&dir.join("systemlint-apt"), 0o755);
    file(&dir.join("systemlint-notes"), 0o644);
    file(&dir.join("README"), 0o755);
    std::fs::create_dir(dir.join("systemlint-dir")).unwrap();
    let (plugins, refusals) = discover(std::slice::from_ref(&dir), &mine());
    assert_eq!(
        plugins,
        [Plugin {
            name: "apt".into(),
            path: dir.join("systemlint-apt")
        }]
    );
    assert!(refusals.is_empty(), "{refusals:?}");
}

#[test]
fn first_directory_wins_a_name() {
    let (first, second) = (fixture("first"), fixture("second"));
    file(&first.join("systemlint-apt"), 0o700);
    file(&second.join("systemlint-apt"), 0o700);
    file(&second.join("systemlint-sshd"), 0o700);
    let (plugins, _) = discover(&[first.clone(), second.clone()], &mine());
    assert_eq!(
        plugins.iter().map(|p| p.path.clone()).collect::<Vec<_>>(),
        [first.join("systemlint-apt"), second.join("systemlint-sshd")]
    );
}

#[test]
fn missing_directory_is_skipped_silently() {
    let (plugins, refusals) =
        discover(&[PathBuf::from("/nonexistent/systemlint/plugins")], &mine());
    assert!(plugins.is_empty() && refusals.is_empty());
}

#[test]
fn group_or_other_writable_is_refused() {
    for mode in [0o775, 0o757, 0o777] {
        let dir = fixture(&format!("writable-{mode:o}"));
        file(&dir.join("systemlint-apt"), mode);
        let (plugins, refusals) = discover(std::slice::from_ref(&dir), &mine());
        assert!(plugins.is_empty(), "{mode:o}");
        assert!(
            refusals[0].reason.contains("chmod go-w"),
            "{mode:o}: {refusals:?}"
        );
    }
}

#[test]
fn writable_directory_refuses_everything_in_it() {
    let dir = fixture("writable-dir");
    file(&dir.join("systemlint-apt"), 0o755);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let (plugins, refusals) = discover(std::slice::from_ref(&dir), &mine());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(plugins.is_empty());
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].path, dir);
}

#[test]
fn production_walk_reaches_the_filesystem_root() {
    assert_eq!(Trust::invoking_user().top, PathBuf::from("/"));
    assert!(Trust::invoking_user().check(Path::new("/")).is_ok());
}

#[test]
fn production_trust_holds_the_running_core_owner() {
    let owner = std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata(std::env::current_exe().unwrap()).unwrap(),
    );
    let uids = Trust::invoking_user().uids;
    assert!(uids.contains(&0) && uids.contains(&owner), "{uids:?}");
}

#[test]
fn stranger_owner_is_refused() {
    let dir = fixture("stranger");
    file(&dir.join("systemlint-apt"), 0o755);
    let (plugins, refusals) = discover(
        std::slice::from_ref(&dir),
        &Trust {
            uids: vec![u32::MAX - 1],
            top: base(),
        },
    );
    assert!(plugins.is_empty());
    assert!(
        refusals[0]
            .reason
            .contains("not root, you or the core’s owner"),
        "{refusals:?}"
    );
}

#[test]
fn symlink_is_judged_by_its_target() {
    let (dir, elsewhere) = (fixture("link"), fixture("link-target"));
    file(&elsewhere.join("real"), 0o755);
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("real"), dir.join("systemlint-apt")).unwrap();
    let (plugins, refusals) = discover(std::slice::from_ref(&dir), &mine());
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(plugins.is_empty());
    assert!(refusals[0].reason.contains("link-target"), "{refusals:?}");
}
