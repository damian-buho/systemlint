// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use systemlint::collector::{BESIDE, Collector, directories, load, overlaps};
use systemlint::discovery::Trust;

const GOOD: &str = "id: os-release\nread:\n  files: [/etc/os-release]\nparse: {plugin: formats, op: kv}\ninto: os.release\n";

fn dir(name: &str, files: &[(&str, &str)]) -> (PathBuf, Trust) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collector");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = base.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (file, text) in files {
        std::fs::write(dir.join(file), text).unwrap();
        std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    (
        dir,
        Trust {
            top: base.canonicalize().unwrap(),
            ..Trust::invoking_user()
        },
    )
}

#[test]
fn shipped_os_release_collector_is_valid() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../collectors/os-release.yaml"),
    )
    .unwrap();
    let collector = Collector::parse(&text).unwrap();
    assert_eq!(
        (
            collector.id.as_str(),
            collector.parse.plugin.as_str(),
            collector.into.as_str()
        ),
        ("os-release", "formats", "os.release")
    );
}

#[test]
fn beside_is_share_next_to_bin() {
    assert_eq!(
        directories(Path::new("/usr/local/bin/systemlint"), &[]),
        [Path::new("/usr/local/bin").join(BESIDE)]
    );
}

#[test]
fn invalid_collectors_are_refused_with_the_reason() {
    for (text, reason) in [
        (GOOD.replace("os-release\n", "Os_Release\n"), "not a slug"),
        (
            GOOD.replace("[/etc/os-release]", "[etc/os-release]"),
            "not absolute",
        ),
        (
            GOOD.replace("files: [/etc/os-release]", "stat: [relative]"),
            "not absolute",
        ),
        (
            GOOD.replace("files: [/etc/os-release]", "exec: []"),
            "read.exec is empty",
        ),
        (
            GOOD.replace("files: [/etc/os-release]", "exec: [sshd, -T]"),
            "PATH is never searched",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts.passwd, argv: []}",
            ),
            "read.exec-from argv is empty",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts.passwd, argv: [sshd]}",
            ),
            "PATH is never searched",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts.passwd, argv: ['/bin/{key}']}",
            ),
            "PATH is never searched",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts.*, argv: [/bin/id]}",
            ),
            "without wildcards",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: os, argv: [/bin/id]}",
            ),
            "does not write",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts..passwd, argv: [/bin/id]}",
            ),
            "without wildcards",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec-from: {each: accounts.passwd, keep: {type: 7}, argv: [/bin/id]}",
            ),
            "keep is no valid schema",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "stat: [/etc/os-release]\n  order: drop-in",
            ),
            "read.order drop-in orders files",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "files: [/etc/os-release]\n  prefer: exec",
            ),
            "give both read.exec and read.files",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "exec: [/bin/true]\n  prefer: exec",
            ),
            "give both read.exec and read.files",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "files: [/etc/os-release]\n  exec: [/bin/true]\n  unset-is-default: true",
            ),
            "set read.prefer exec",
        ),
        (
            GOOD.replace("into: os.release", "into: meta.x"),
            "reserved meta",
        ),
        (
            GOOD.replace("into: os.release", "into: collectors"),
            "reserved collectors",
        ),
        (
            GOOD.replace("into: os.release", "into: os..release"),
            "not a dotted fact path",
        ),
        (
            GOOD.replace("into: os.release", "into: ''"),
            "not a dotted fact path",
        ),
        (
            GOOD.replace("into:", "unknown: 1\ninto:"),
            "not a valid collector",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "files: [/etc/os-release]\n  hash: [sha256]",
            ),
            "list the files under read.stat",
        ),
        (
            GOOD.replace(
                "files: [/etc/os-release]",
                "stat: [/etc/os-release]\n  hash: [md5]",
            ),
            "not a valid collector",
        ),
    ] {
        assert!(
            Collector::parse(&text).unwrap_err().contains(reason),
            "{text}"
        );
    }
    assert!(
        Collector::parse(&GOOD.replace("files: [/etc/os-release]", "exec: [/usr/sbin/sshd, -T]"))
            .is_ok()
    );
    assert!(
        Collector::parse(&GOOD.replace(
            "files: [/etc/os-release]",
            "exec-from: {each: accounts.passwd, keep: {type: object}, argv: [/bin/id, '{key}']}"
        ))
        .is_ok()
    );
}

#[test]
fn overlap_is_by_whole_segment() {
    assert!(overlaps("os", "os.release"));
    assert!(overlaps("os.release", "os"));
    assert!(overlaps("os.release", "os.release"));
    assert!(!overlaps("os", "osx.release"));
    assert!(!overlaps("os.release", "os.kernel"));
}

#[test]
fn load_reads_yaml_in_order_and_refuses_clashes() {
    let other = GOOD
        .replace("into: os.release", "into: os.kernel")
        .replace("id: os-release", "id: kernel");
    let (dir, trust) = dir(
        "load",
        &[
            ("10-good.yaml", GOOD),
            ("20-kernel.yaml", &other),
            ("30-same-id.yaml", &GOOD.replace("os.release", "x")),
            ("40-overlap.yaml", &GOOD.replace("id: os-release", "id: os")),
            ("50-bad.yaml", "id: [\n"),
            ("README", "ignored"),
        ],
    );
    let (collectors, refusals) = load(&[dir.clone(), dir.join("absent")], &trust);
    assert_eq!(
        collectors.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        ["os-release", "kernel"]
    );
    let reasons: Vec<_> = refusals
        .iter()
        .map(|r| {
            (
                r.path.file_name().unwrap().to_str().unwrap(),
                r.reason.as_str(),
            )
        })
        .collect();
    assert_eq!(reasons.len(), 3, "{reasons:?}");
    assert!(
        reasons[0].0 == "30-same-id.yaml"
            && reasons[0].1.contains("id os-release is already taken"),
        "{reasons:?}"
    );
    assert!(
        reasons[1].0 == "40-overlap.yaml"
            && reasons[1]
                .1
                .contains("overlaps os.release of collector os-release"),
        "{reasons:?}"
    );
    assert!(
        reasons[2].0 == "50-bad.yaml" && reasons[2].1.contains("not a valid collector"),
        "{reasons:?}"
    );
}

#[test]
fn load_refuses_a_writable_directory_or_file() {
    let (dir, trust) = dir(
        "writable",
        &[
            ("good.yaml", GOOD),
            (
                "open.yaml",
                &GOOD
                    .replace("os-release", "open")
                    .replace("os.release", "open"),
            ),
        ],
    );
    std::fs::set_permissions(
        dir.join("open.yaml"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let (collectors, refusals) = load(std::slice::from_ref(&dir), &trust);
    assert_eq!((collectors.len(), refusals.len()), (1, 1));
    assert!(
        refusals[0].reason.contains("group or others can write"),
        "{refusals:?}"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (collectors, refusals) = load(std::slice::from_ref(&dir), &trust);
    assert!(
        collectors.is_empty() && refusals[0].path == dir,
        "{refusals:?}"
    );
}
