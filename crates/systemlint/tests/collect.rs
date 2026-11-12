// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use systemlint::collect::{Options, REDACTED, SCHEMA, base64, collect, rfc3339};
use systemlint::collector::Collector;
use systemlint::discovery::Plugin;
use systemlint::source::Root;

// Each fake plugin: name, ops JSON, and the shell that answers a request after saving it.
const PLUGINS: &[(&str, &str, &str)] = &[
    ("echo", r#"[{"op":"parse"}]"#, r#"printf '%s\n' '{"facts":{"a":1,"nested":{"secret":"hunter2"}},"diagnostics":[{"path":"/etc/x","line":2,"message":"odd"}],"redact":["/nested/secret","/absent"]}'"#),
    ("dump", r#"[{"op":"parse"}]"#, r#"printf '%s\n' '{"facts":{"ok":true}}'"#),
    ("live", r#"[{"op":"parse"}]"#, r#"printf '%s\n' '{"facts":{"ok":true}}'"#),
    ("mixed", r#"[{"op":"parse"}]"#, r#"printf '%s\n' '{"facts":{"ok":true}}'"#),
    ("absent", r#"[{"op":"parse"}]"#, r#"printf '%s\n' '{"facts":{"ok":true}}'"#),
    ("derive", r#"[{"op":"codename","needs":["os.release"]}]"#, r#"printf '%s\n' '{"facts":{"seen":true}}'"#),
    ("loop", r#"[{"op":"release","needs":["apt.codename"]}]"#, r#"printf '%s\n' '{"facts":{}}'"#),
    ("base", r#"[{"op":"release"}]"#, r#"printf '%s\n' '{"facts":{"VERSION_CODENAME":"resolute"}}'"#),
    ("broken", r#"[{"op":"parse"}]"#, "echo crashed >&2; exit 1"),
    ("garbage", r#"[{"op":"parse"}]"#, "echo not json"),
];

fn plugins() -> Vec<Plugin> {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collect");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, ops, answer) in PLUGINS {
            let describe = format!(r#"{{"name":"{name}","version":"9.{}","protocol":1,"ops":{ops}}}"#, name.len());
            let request = dir.join(format!("{name}.request.json"));
            let body = format!("#!/bin/sh\nif [ \"$1\" = --describe ]; then printf '%s\\n' '{describe}'; exit 0; fi\ncat > '{}'\n{answer}\n", request.display());
            let temporary = dir.join(format!("{name}.{}.tmp", std::process::id()));
            std::fs::write(&temporary, body).unwrap();
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&temporary, dir.join(name)).unwrap();
        }
        dir
    });
    PLUGINS.iter().map(|(name, _, _)| Plugin { name: (*name).to_owned(), path: dir.join(name) }).collect()
}

fn request(name: &str) -> Value {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collect").join(format!("{name}.request.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ubuntu-26.04")
}

fn options(live: bool) -> Options {
    let root = if live { Path::new("/").to_path_buf() } else { fixture() };
    Options { root: Root::open(&root).unwrap(), live, now: UNIX_EPOCH + Duration::from_secs(1_794_398_400), timeout: Duration::from_secs(60) }
}

fn collector(yaml: &str) -> Collector {
    Collector::parse(yaml).unwrap()
}

#[test]
fn reply_lands_under_into_with_diagnostics_redaction_and_meta() {
    let c = collector("id: echo\nread:\n  files: [/etc/os-release]\nparse: {plugin: echo, op: parse}\ninto: deep.echo\n");
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["deep"]["echo"]["a"], 1);
    assert_eq!(doc["deep"]["echo"]["nested"]["secret"], REDACTED);
    assert!(!doc.to_string().contains("hunter2"));
    let outcome = &doc["collectors"]["echo"];
    assert_eq!((outcome["status"].as_str(), outcome["plugin"].as_str(), outcome["op"].as_str()), (Some("ok"), Some("echo"), Some("parse")));
    assert_eq!(outcome["redacted"], serde_json::json!(["/nested/secret"]));
    assert_eq!(outcome["diagnostics"][0]["line"], 2);
    let meta = &doc["meta"];
    assert_eq!((meta["schema"].as_u64(), meta["collected-at"].as_str()), (Some(u64::from(SCHEMA)), Some("2026-11-11T12:00:00Z")));
    assert_eq!(meta["subject"]["kind"], "root");
    assert_eq!(meta["subject"]["path"], fixture().canonicalize().unwrap().to_str().unwrap());
    assert_eq!(meta["plugins"]["echo"], "9.4");
    assert!(meta["privileged"].is_boolean());
    let sent = request("echo");
    assert_eq!((sent["protocol"].as_u64(), sent["op"].as_str(), sent["now"].as_str()), (Some(1), Some("parse"), Some("2026-11-11T12:00:00Z")));
    assert_eq!(sent["root"], meta["subject"]["path"]);
}

#[test]
fn files_resolve_in_the_root_and_merge_with_stat() {
    let c = collector("id: dump\nread:\n  files: [/etc/os-release, /etc/absent]\n  stat: [/etc/os-*, /usr/lib/os-release]\nparse: {plugin: dump, op: parse}\ninto: dump\n");
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["dump"]["status"], "ok", "{doc}");
    let inputs = request("dump")["inputs"].as_array().unwrap().clone();
    let paths: Vec<_> = inputs.iter().map(|i| i["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/etc/os-release", "/usr/lib/os-release"]);
    assert!(inputs[0]["content"].as_str().unwrap().contains("VERSION_CODENAME=resolute"));
    assert_eq!(inputs[0]["stat"]["kind"], "symlink");
    assert!(inputs[1].get("content").is_none());
    assert_eq!(inputs[1]["stat"]["kind"], "file");
}

#[test]
fn exec_is_skipped_under_root_and_runs_live() {
    let c = collector("id: exec\nread:\n  exec: [/bin/sh, -c, 'echo out; echo err >&2; exit 3']\nparse: {plugin: base, op: release}\ninto: exec\n");
    let skipped = collect(std::slice::from_ref(&c), &plugins(), &options(false));
    assert_eq!(skipped["collectors"]["exec"]["status"], "skipped");
    assert!(skipped["collectors"]["exec"]["reason"].as_str().unwrap().contains("/bin/sh on a live host only"), "{skipped}");
    assert!(skipped.get("exec").is_none());
    let c = Collector { parse: systemlint::collector::Parse { plugin: "live".into(), op: "parse".into() }, into: "exec2".into(), ..c };
    let live = collect(&[c], &plugins(), &options(true));
    assert_eq!(live["collectors"]["exec"]["status"], "ok", "{live}");
    assert_eq!(live["meta"]["subject"]["kind"], "host");
    let exec = request("live")["inputs"][0].clone();
    assert_eq!((exec["stdout"].as_str(), exec["stderr"].as_str(), exec["exit"].as_i64()), (Some("out\n"), Some("err\n"), Some(3)));
}

#[test]
fn a_collector_with_files_keeps_them_under_root_without_its_exec() {
    let c = collector("id: mixed\nread:\n  files: [/etc/os-release]\n  exec: [/bin/false]\nparse: {plugin: mixed, op: parse}\ninto: mixed\n");
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["mixed"]["status"], "ok", "{doc}");
    let inputs = request("mixed")["inputs"].as_array().unwrap().clone();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["path"], "/etc/os-release");
}

#[test]
fn an_absent_program_reaches_the_plugin_as_exit_127() {
    let c = collector("id: absent\nread:\n  exec: [/nonexistent/systemlint-test, -T]\nparse: {plugin: absent, op: parse}\ninto: absent\n");
    let doc = collect(&[c], &plugins(), &options(true));
    assert_eq!(doc["collectors"]["absent"]["status"], "ok", "{doc}");
    let exec = request("absent")["inputs"][0].clone();
    assert_eq!((exec["exit"].as_i64(), exec["stdout"].as_str()), (Some(127), Some("")));
    assert_eq!(exec["stderr"], "/nonexistent/systemlint-test: not found\n");
}

#[test]
fn needs_order_the_run_and_carry_the_facts() {
    let derive = collector("id: derive\nparse: {plugin: derive, op: codename}\ninto: apt.codename\n");
    let base = collector("id: base\nparse: {plugin: base, op: release}\ninto: os.release\n");
    let doc = collect(&[derive.clone(), base], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["derive"]["status"], "ok", "{doc}");
    assert_eq!(doc["apt"]["codename"]["seen"], true);
    assert_eq!(request("derive")["facts"]["os.release"]["VERSION_CODENAME"], "resolute");
    let lonely = collect(std::slice::from_ref(&derive), &plugins(), &options(false));
    assert!(lonely["collectors"]["derive"]["reason"].as_str().unwrap().contains("needs fact os.release, which no collector produces"), "{lonely}");
    let failing = collector("id: base\nparse: {plugin: broken, op: parse}\ninto: os.release\n");
    let doc = collect(&[derive, failing], &plugins(), &options(false));
    assert!(doc["collectors"]["derive"]["reason"].as_str().unwrap().contains("collector base finished error"), "{doc}");
}

#[test]
fn a_cycle_fails_every_member() {
    let derive = collector("id: derive\nparse: {plugin: derive, op: codename}\ninto: apt.codename\n");
    let looping = collector("id: loop\nparse: {plugin: loop, op: release}\ninto: os.release\n");
    let doc = collect(&[derive, looping], &plugins(), &options(false));
    for id in ["derive", "loop"] {
        assert!(doc["collectors"][id]["reason"].as_str().unwrap().contains("wait on this collector in turn"), "{doc}");
    }
}

#[test]
fn every_failure_is_an_error_outcome_with_its_reason() {
    for (plugin, op, reason) in [
        ("missing", "parse", "no trusted plugin systemlint-missing"),
        ("dump", "nope", "plugin dump has no op nope"),
        ("broken", "parse", "crashed"),
        ("garbage", "parse", "invalid protocol JSON"),
    ] {
        let c = collector(&format!("id: x\nparse: {{plugin: {plugin}, op: {op}}}\ninto: x\n"));
        let doc = collect(&[c], &plugins(), &options(false));
        assert_eq!(doc["collectors"]["x"]["status"], "error", "{doc}");
        assert!(doc["collectors"]["x"]["reason"].as_str().unwrap().contains(reason), "{doc}");
        assert!(doc.get("x").is_none());
    }
}

#[test]
fn rfc3339_edges() {
    let at = |secs: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(secs));
    assert_eq!(at(0), "1970-01-01T00:00:00Z");
    assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(at(1_709_251_199), "2024-02-29T23:59:59Z");
    assert_eq!(at(1_709_251_200), "2024-03-01T00:00:00Z");
    assert_eq!(at(4_102_444_800), "2100-01-01T00:00:00Z");
    assert_eq!(rfc3339(UNIX_EPOCH - Duration::from_secs(1)), "1970-01-01T00:00:00Z");
    assert!(rfc3339(SystemTime::now()).starts_with("20"));
}

#[test]
fn base64_matches_rfc_4648() {
    for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
        assert_eq!(base64(plain.as_bytes()), encoded);
    }
    assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
}
