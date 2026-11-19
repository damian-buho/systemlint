// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::ErrorKind;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use systemlint::collector::Digest;
use systemlint::source::{Failure, Root, wildcard};
use systemlint_protocol::FileKind;

fn fixture(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("source")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("etc/apt")).unwrap();
    std::fs::write(dir.join("etc/passwd"), "inside\n").unwrap();
    dir
}

#[test]
fn symlinks_and_dotdot_stay_inside_the_root() {
    let dir = fixture("escape");
    symlink("/etc/passwd", dir.join("etc/absolute")).unwrap();
    symlink(
        "../../../../../../../../etc/passwd",
        dir.join("etc/relative"),
    )
    .unwrap();
    symlink("/", dir.join("etc/apt/top")).unwrap();
    let root = Root::open(&dir).unwrap();
    for path in [
        "/etc/absolute",
        "/etc/relative",
        "/../../../etc/passwd",
        "/etc/apt/top/etc/passwd",
    ] {
        assert_eq!(root.read(path, 1024).unwrap(), b"inside\n", "{path}");
    }
}

#[test]
fn live_root_reads_the_host() {
    let root = Root::open(Path::new("/")).unwrap();
    assert_eq!(
        root.read("/proc/self/stat", 1 << 20)
            .map(|b| !b.is_empty())
            .ok(),
        Some(true)
    );
}

#[test]
fn read_refuses_directories_absent_files_and_size_over_cap() {
    let root = Root::open(&fixture("read")).unwrap();
    assert!(
        root.read("/etc", 1024)
            .unwrap_err()
            .to_string()
            .contains("not a regular file")
    );
    assert_eq!(
        root.read("/etc/missing", 1024).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(root.read("/etc/passwd", 7).unwrap().len(), 7);
    assert!(
        root.read("/etc/passwd", 6)
            .unwrap_err()
            .to_string()
            .contains("larger than 6 bytes")
    );
}

#[test]
fn glob_matches_one_component_and_skips_dotfiles() {
    let dir = fixture("glob");
    for name in ["a.list", "b.list", "c.sources", ".hidden.list", "ab"] {
        std::fs::write(dir.join("etc/apt").join(name), "").unwrap();
    }
    let root = Root::open(&dir).unwrap();
    assert_eq!(
        root.glob("/etc/apt/*.list").unwrap(),
        ["/etc/apt/a.list", "/etc/apt/b.list"]
    );
    assert_eq!(
        root.glob("/etc/apt/.*.list").unwrap(),
        ["/etc/apt/.hidden.list"]
    );
    assert_eq!(root.glob("/e*/apt/a?").unwrap(), ["/etc/apt/ab"]);
    assert_eq!(root.glob("/etc/missing/*").unwrap(), Vec::<String>::new());
    assert_eq!(root.glob("/etc/passwd/*").unwrap(), Vec::<String>::new());
    assert_eq!(root.glob("/etc/literal").unwrap(), ["/etc/literal"]);
}

#[test]
fn a_star_lists_a_literal_symlinked_directory_where_it_resolves_never_a_wildcard_one() {
    let dir = fixture("glob-symlink");
    std::fs::create_dir_all(dir.join("usr/lib/x")).unwrap();
    std::fs::write(dir.join("usr/lib/x/ls"), "").unwrap();
    std::fs::create_dir_all(dir.join("data/audit")).unwrap();
    std::fs::write(dir.join("data/audit/audit.log"), "").unwrap();
    symlink("usr/lib", dir.join("lib")).unwrap();
    symlink("/data/audit", dir.join("etc/audit")).unwrap();
    symlink("/", dir.join("etc/top")).unwrap();
    let root = Root::open(&dir).unwrap();
    assert_eq!(root.glob("/usr/lib/*").unwrap(), ["/usr/lib/x"]);
    assert_eq!(root.glob("/lib/*").unwrap(), ["/usr/lib/x"]);
    assert_eq!(root.glob("/lib/x/*").unwrap(), ["/lib/x/ls"]);
    assert_eq!(
        root.glob("/etc/audit/*").unwrap(),
        ["/data/audit/audit.log"]
    );
    assert_eq!(root.glob("/etc/top/l*").unwrap(), ["/lib"]);
    assert_eq!(root.glob("/l*/*").unwrap(), Vec::<String>::new());
    assert_eq!(root.glob("/etc/missing/*").unwrap(), Vec::<String>::new());
    assert_eq!(
        root.glob("/etc/audit").unwrap(),
        ["/data/audit", "/etc/audit"],
        "a literal symlinked directory names the link and the directory it resolves to"
    );
    assert_eq!(root.glob("/etc/top").unwrap(), ["/", "/etc/top"]);
    assert_eq!(root.glob("/usr/lib").unwrap(), ["/usr/lib"]);
}

#[test]
fn wildcard_edges() {
    assert!(wildcard("*", "x"));
    assert!(wildcard("*", ""));
    assert!(!wildcard("*", ".x"));
    assert!(wildcard(".*", ".x"));
    assert!(wildcard("a*b*c", "aXXbYc"));
    assert!(!wildcard("a*b*c", "aXXbY"));
    assert!(wildcard("?", "é"));
    assert!(!wildcard("?", ""));
    assert!(!wildcard("??", "x"));
}

#[test]
fn stat_spells_out_the_mode_bits() {
    let dir = fixture("stat");
    let set = |name: &str, mode: u32| {
        std::fs::write(dir.join(name), "").unwrap();
        std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set("world", 0o666);
    set("group", 0o620);
    set("suid", 0o4755);
    set("sgid", 0o2755);
    set("plain", 0o644);
    symlink("/plain", dir.join("link")).unwrap();
    let root = Root::open(&dir).unwrap();
    let world = root.stat("/world").unwrap();
    assert_eq!(
        (
            world.kind,
            world.mode.as_str(),
            world.world_writable,
            world.group_writable
        ),
        (FileKind::File, "0666", true, true)
    );
    let group = root.stat("/group").unwrap();
    assert_eq!((group.world_writable, group.group_writable), (false, true));
    assert_eq!(
        (
            root.stat("/suid").unwrap().setuid,
            root.stat("/suid").unwrap().setgid
        ),
        (true, false)
    );
    assert_eq!(
        (
            root.stat("/sgid").unwrap().setuid,
            root.stat("/sgid").unwrap().setgid,
            root.stat("/sgid").unwrap().mode.as_str()
        ),
        (false, true, "2755")
    );
    let plain = root.stat("/plain").unwrap();
    assert!(!plain.world_writable && !plain.group_writable && !plain.setuid && !plain.setgid);
    let link = root.stat("/link").unwrap();
    assert_eq!(
        (link.kind, link.world_writable, link.group_writable),
        (FileKind::Symlink, false, false)
    );
    assert_eq!(link.linked_to.as_deref(), Some("/plain"));
    assert_eq!(plain.linked_to, None);
    assert_eq!(root.stat("/etc").unwrap().kind, FileKind::Directory);
    assert_eq!(
        root.stat("/missing").unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn digests_follow_fips_180_and_refuse_a_directory() {
    let dir = fixture("digests");
    std::fs::write(dir.join("abc"), "abc").unwrap();
    let root = Root::open(&dir).unwrap();
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(
        root.digests("/abc", &[Digest::Sha256, Digest::Sha512])
            .unwrap(),
        (Some(sha256.into()), Some(sha512.into()))
    );
    assert_eq!(
        root.digests("/abc", &[Digest::Sha512]).unwrap(),
        (None, Some(sha512.into()))
    );
    assert_eq!(
        root.digests("/etc", &[Digest::Sha256]).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn a_double_star_walks_every_path_below_dotted_ones_included_never_a_symlinked_directory_below() {
    let dir = fixture("walk");
    std::fs::create_dir_all(dir.join("usr/a/b")).unwrap();
    std::fs::create_dir_all(dir.join("usr/.hidden")).unwrap();
    std::fs::write(dir.join("usr/a/b/file"), "").unwrap();
    std::fs::write(dir.join("usr/.hidden/x"), "").unwrap();
    symlink("/etc", dir.join("usr/link")).unwrap();
    symlink("/usr/a", dir.join("bin")).unwrap();
    let root = Root::open(&dir).unwrap();
    assert_eq!(
        root.glob("/usr/**").unwrap(),
        [
            "/usr",
            "/usr/.hidden",
            "/usr/.hidden/x",
            "/usr/a",
            "/usr/a/b",
            "/usr/a/b/file",
            "/usr/link"
        ],
        "the link is listed, /etc behind it is not walked"
    );
    for pattern in ["/usr/**/file", "/usr/a**", "/**x"] {
        assert!(
            root.glob(pattern)
                .map_err(String::from)
                .unwrap_err()
                .contains("whole last component"),
            "{pattern}"
        );
    }
    assert_eq!(
        root.glob("/bin/**").unwrap(),
        ["/usr/a", "/usr/a/b", "/usr/a/b/file"],
        "a literal symlinked base is walked where it resolves"
    );
    assert_eq!(root.glob("/missing/**").unwrap(), ["/missing"]);
    let mut out = Vec::new();
    assert!(root.walk("/usr", 7, &mut out).is_ok(), "{out:?}");
    out.clear();
    assert_eq!(
        root.walk("/usr", 6, &mut out).unwrap_err(),
        Failure::Other("names more than 6 paths; narrow it".into())
    );
}

#[test]
fn a_refusal_is_denied_and_keeps_its_words_through_a_glob() {
    let denied = Failure::of(
        "list",
        "/etc/cron.hourly",
        std::io::Error::from_raw_os_error(libc::EACCES),
    );
    assert_eq!(denied, Failure::Denied("list /etc/cron.hourly".into()));
    assert_eq!(
        denied.within("glob /etc/**"),
        Failure::Denied("list /etc/cron.hourly".into())
    );
    assert_eq!(
        String::from(Failure::Denied("read /x".into())),
        "can’t read /x: permission denied"
    );
    let other = Failure::of("read", "/x", ErrorKind::InvalidData);
    assert!(
        matches!(&other, Failure::Other(r) if r.starts_with("can’t read /x: ")),
        "{other:?}"
    );
    assert!(
        matches!(other.within("glob /x"), Failure::Other(r) if r.starts_with("glob /x: can’t read /x: "))
    );
}

#[test]
fn stat_allocates_bytes_only_for_a_regular_file() {
    let dir = fixture("allocated");
    let sparse = std::fs::File::create(dir.join("etc/sparse")).unwrap();
    sparse.set_len(1 << 30).unwrap();
    let root = Root::open(&dir).unwrap();
    let file = root.stat("/etc/sparse").unwrap();
    assert_eq!(file.size, 1 << 30);
    assert!(file.allocated.unwrap() < 1 << 20, "{:?}", file.allocated);
    let small = root.stat("/etc/passwd").unwrap().allocated.unwrap();
    assert!((1..1 << 20).contains(&small), "{small}");
    assert_eq!(root.stat("/etc").unwrap().allocated, None);
}
