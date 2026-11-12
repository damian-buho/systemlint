// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use systemlint::runner::{DESCRIBE_TIMEOUT, OUTPUT_CAP, call, describe};

const GOOD: &str = r#"printf '%s\n' '{"name":"kv","version":"1.2.3","protocol":1,"ops":[{"op":"parse"}]}'"#;

const SCRIPTS: &[(&str, &str)] = &[
    ("good", GOOD),
    ("env", "env"),
    ("other", r#"printf '%s\n' '{"name":"kv","version":"1","protocol":2,"ops":[]}'"#),
    ("garbage", "echo hello"),
    ("fails", "echo broken >&2; exit 4"),
    ("chatty", "printf 1234567890"),
    ("hung", "exec sleep 600"),
];

// Writes every script before any test forks, so no child inherits a script still open for writing.
fn script(name: &str) -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("runner");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in SCRIPTS {
            let temporary = dir.join(format!("{name}.{}.tmp", std::process::id()));
            std::fs::write(&temporary, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&temporary, dir.join(name)).unwrap();
        }
        dir
    });
    dir.join(name)
}

#[test]
fn reads_a_valid_describe() {
    let describe = describe("kv", &script("good"), DESCRIBE_TIMEOUT).unwrap();
    assert_eq!((describe.version.as_str(), describe.ops[0].op.as_str()), ("1.2.3", "parse"));
}

#[test]
fn environment_is_empty_but_the_locale() {
    let output = call(&script("env"), &[], None, DESCRIBE_TIMEOUT, OUTPUT_CAP).unwrap();
    let env = String::from_utf8(output.stdout).unwrap();
    assert!(env.contains("LC_ALL=C"), "{env}");
    assert!(!env.contains("HOME="), "{env}");
}

#[test]
fn refuses_another_protocol_and_a_wrong_name() {
    let other = script("other");
    assert!(describe("kv", &other, DESCRIBE_TIMEOUT).unwrap_err().contains("protocol 2"));
    assert!(describe("apt", &script("good"), DESCRIBE_TIMEOUT).unwrap_err().contains("calls itself kv"));
}

#[test]
fn refuses_garbage_and_failure() {
    assert!(describe("kv", &script("garbage"), DESCRIBE_TIMEOUT).unwrap_err().contains("not valid protocol JSON"));
    let error = describe("kv", &script("fails"), DESCRIBE_TIMEOUT).unwrap_err();
    assert!(error.contains("exit status: 4") && error.contains("broken"), "{error}");
}

#[test]
fn output_cap_boundary() {
    let path = script("chatty");
    assert_eq!(call(&path, &[], None, DESCRIBE_TIMEOUT, 10).unwrap().stdout.len(), 10);
    assert!(call(&path, &[], None, DESCRIBE_TIMEOUT, 9).unwrap_err().contains("more than 9 bytes"));
}

#[test]
fn timeout_kills_a_hung_plugin() {
    let error = call(&script("hung"), &[], None, Duration::ZERO, OUTPUT_CAP).unwrap_err();
    assert!(error.contains("within 0s"), "{error}");
}
