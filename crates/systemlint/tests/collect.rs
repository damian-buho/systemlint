// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use systemlint::collect::{
    HashKey, Named, Options, REDACTED, SCHEMA, base64, collect, collect_reporting, read_partial,
    rfc3339,
};
use systemlint::collector::Collector;
use systemlint::discovery::Plugin;
use systemlint::source::Root;

// Each fake plugin, one per test since its request file is shared: name, ops JSON, and the shell that answers a request after saving it.
const PLUGINS: &[(&str, &str, &str)] = &[
    (
        "echo",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"a":1,"nested":{"secret":"hunter2"}},"diagnostics":[{"path":"/etc/x","line":2,"message":"odd"}],"redact":["/nested/secret","/absent"]}'"#,
    ),
    (
        "dump",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "live",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "mixed",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "absent",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "derive",
        r#"[{"op":"codename","needs":["os.release"]}]"#,
        r#"printf '%s\n' '{"facts":{"seen":true}}'"#,
    ),
    (
        "ordered",
        r#"[{"op":"codename","needs":["os.release"]}]"#,
        r#"printf '%s\n' '{"facts":{"seen":true}}'"#,
    ),
    (
        "loop",
        r#"[{"op":"release","needs":["apt.codename"]}]"#,
        r#"printf '%s\n' '{"facts":{}}'"#,
    ),
    (
        "base",
        r#"[{"op":"release"}]"#,
        r#"printf '%s\n' '{"facts":{"VERSION_CODENAME":"resolute"}}'"#,
    ),
    ("broken", r#"[{"op":"parse"}]"#, "echo crashed >&2; exit 1"),
    ("garbage", r#"[{"op":"parse"}]"#, "echo not json"),
    (
        "hasher",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"env":{"TOKEN":"s3cret","EMPTY":"","N":1,"BOTH":"x"}},"hash":["/env/TOKEN","/env/EMPTY","/env/N","/env/BOTH","/absent"],"redact":["/env/BOTH"]}'"#,
    ),
    (
        "spiller",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"exit-status":0,"stdout":"pw","stdout-lines":["pw",""],"a/b":{"c~d":"x"}},"hash":["/stdout"]}'"#,
    ),
    (
        "image",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "proc",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "dirs",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "notdir",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "secret",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    ("traced", r#"[{"op":"parse"}]"#, "exit 3"),
    (
        "untraced",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "lister",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"a.service":{"files":["/etc/os-release","/etc/*","relative","/etc/absent"]},"b.service":{"files":"/etc/os-release"},"path":["/usr","/etc/apt"]}}'"#,
    ),
    (
        "reader",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "templater",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "literal",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "mounter",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"/etc":{"filesystem":"ext4"},"/etc/absent":{},"relative":{}}}'"#,
    ),
    (
        "sizer",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "keeper",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "orphan",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"ok":true}}'"#,
    ),
    (
        "meet-a",
        r#"[{"op":"parse"}]"#,
        r#"d=$(dirname "$0"); touch "$d/meet-a.here"; i=0; while [ ! -e "$d/meet-b.here" ] && [ $i -lt 3000 ]; do sleep 0.01; i=$((i+1)); done; [ -e "$d/meet-b.here" ] && printf '%s\n' '{"facts":{"met":true}}'"#,
    ),
    (
        "meet-b",
        r#"[{"op":"parse"}]"#,
        r#"d=$(dirname "$0"); touch "$d/meet-b.here"; i=0; while [ ! -e "$d/meet-a.here" ] && [ $i -lt 3000 ]; do sleep 0.01; i=$((i+1)); done; [ -e "$d/meet-a.here" ] && printf '%s\n' '{"facts":{"met":true}}'"#,
    ),
    (
        "same-base",
        r#"[{"op":"release"}]"#,
        r#"printf '%s\n' '{"facts":{"VERSION_CODENAME":"resolute"}}'"#,
    ),
    (
        "same-derive",
        r#"[{"op":"codename","needs":["os.release"]}]"#,
        r#"printf '%s\n' '{"facts":{"seen":true}}'"#,
    ),
    (
        "same-a",
        r#"[{"op":"parse"}]"#,
        r#"printf '%s\n' '{"facts":{"a":1}}'"#,
    ),
    ("same-b", r#"[{"op":"parse"}]"#, "exit 4"),
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
    PLUGINS
        .iter()
        .map(|(name, _, _)| Plugin {
            name: (*name).to_owned(),
            path: dir.join(name),
        })
        .collect()
}

fn request(name: &str) -> Value {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("collect")
        .join(format!("{name}.request.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ubuntu-26.04")
}

fn options(live: bool) -> Options {
    let root = if live {
        Path::new("/").to_path_buf()
    } else {
        fixture()
    };
    Options {
        privileged: true,
        root: Root::open(&root).unwrap(),
        live,
        now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
        timeout: Duration::from_secs(60),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
    }
}

fn collector(yaml: &str) -> Collector {
    Collector::parse(yaml).unwrap()
}

#[test]
fn reply_lands_under_into_with_diagnostics_redaction_and_meta() {
    let c = collector(
        "id: echo\nread:\n  files: [/etc/os-release]\nparse: {plugin: echo, op: parse}\ninto: deep.echo\n",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["deep"]["echo"]["a"], 1);
    assert_eq!(doc["deep"]["echo"]["nested"]["secret"], REDACTED);
    assert!(!doc.to_string().contains("hunter2"));
    let outcome = &doc["collectors"]["echo"];
    assert_eq!(
        (
            outcome["status"].as_str(),
            outcome["plugin"].as_str(),
            outcome["op"].as_str()
        ),
        (Some("ok"), Some("echo"), Some("parse"))
    );
    assert_eq!(outcome["redacted"], serde_json::json!(["/nested/secret"]));
    assert_eq!(outcome["diagnostics"][0]["line"], 2);
    let meta = &doc["meta"];
    assert_eq!(
        (meta["schema"].as_u64(), meta["collected-at"].as_str()),
        (Some(u64::from(SCHEMA)), Some("2026-11-11T12:00:00Z"))
    );
    assert_eq!(meta["subject"]["kind"], "root");
    assert_eq!(
        meta["subject"]["path"],
        fixture().canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(meta["plugins"]["echo"], "9.4");
    assert!(meta["privileged"].is_boolean());
    let sent = request("echo");
    assert_eq!(
        (
            sent["protocol"].as_u64(),
            sent["op"].as_str(),
            sent["now"].as_str()
        ),
        (Some(1), Some("parse"), Some("2026-11-11T12:00:00Z"))
    );
    assert_eq!(sent["root"], meta["subject"]["path"]);
}

#[test]
fn files_from_and_stat_from_read_the_paths_facts_name_after_their_producer() {
    let reader = collector(
        "id: reader\nread:\n  files: [/etc/os-release]\n  files-from: [listed.*.files]\n  stat-from: [listed.path]\nparse: {plugin: reader, op: parse}\ninto: read\n",
    );
    let lister = collector("id: lister\nparse: {plugin: lister, op: parse}\ninto: listed\n");
    let doc = collect(&[reader, lister], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["reader"]["status"], "ok", "{doc}");
    let inputs = request("reader")["inputs"].as_array().unwrap().clone();
    let paths: Vec<&str> = inputs.iter().filter_map(|i| i["path"].as_str()).collect();
    assert_eq!(
        paths,
        ["/etc/apt", "/etc/os-release", "/usr"],
        "named once each, literally, relative and absent ones dropped: {inputs:?}"
    );
    assert!(
        inputs[1]["content"].as_str().unwrap().contains("ID=ubuntu"),
        "{inputs:?}"
    );
    assert!(
        inputs[0]["stat"].is_object() && inputs[0]["content"].is_null(),
        "{inputs:?}"
    );
}

#[test]
fn a_from_template_globs_its_suffix_below_each_named_path_taken_literally() {
    let templater = collector(
        "id: templater\nread:\n  stat-from: ['{listed.path}/*', '{listed.path}/lib/os-release']\nparse: {plugin: templater, op: parse}\ninto: templated\n",
    );
    let literal = collector(
        "id: literal\nread:\n  stat-from: ['{listed.*.files}/sources.list.d']\nparse: {plugin: literal, op: parse}\ninto: literal\n",
    );
    let lister = collector("id: lister\nparse: {plugin: lister, op: parse}\ninto: listed\n");
    let doc = collect(&[templater, literal, lister], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["templater"]["status"], "ok", "{doc}");
    let inputs = request("templater")["inputs"].as_array().unwrap().clone();
    let paths: Vec<&str> = inputs.iter().filter_map(|i| i["path"].as_str()).collect();
    assert_eq!(
        paths,
        ["/etc/apt/sources.list.d", "/usr/lib", "/usr/lib/os-release"],
        "each base globbed, absent matches dropped: {inputs:?}"
    );
    assert_eq!(doc["collectors"]["literal"]["status"], "ok", "{doc}");
    assert_eq!(
        request("literal")["inputs"],
        serde_json::json!([]),
        "a fact’s /etc/* stays literal and a file base names nothing below it"
    );
}

#[test]
fn statfs_and_statfs_from_pass_the_filesystem_of_globbed_paths_and_of_a_map_s_keys() {
    let sizer = collector(
        "id: sizer\nread:\n  statfs: [/us*]\n  statfs-from: [points]\nparse: {plugin: sizer, op: parse}\ninto: sized\n",
    );
    let mounter = collector("id: mounter\nparse: {plugin: mounter, op: parse}\ninto: points\n");
    let doc = collect(&[sizer, mounter], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["sizer"]["status"], "ok", "{doc}");
    let inputs = request("sizer")["inputs"].as_array().unwrap().clone();
    let paths: Vec<&str> = inputs.iter().filter_map(|i| i["path"].as_str()).collect();
    assert_eq!(
        paths,
        ["/etc", "/usr"],
        "a map names its keys, relative and absent ones dropped: {inputs:?}"
    );
    assert!(
        inputs.iter().all(|i| i["statfs"]["blocks"].is_u64()
            && i["statfs"]["read-only"].is_boolean()
            && i["stat"].is_null()),
        "{inputs:?}"
    );
}

#[test]
fn stat_keep_passes_only_the_stats_its_schema_admits() {
    let keeper = collector(
        "id: keeper\nread:\n  files: [/etc/os-release]\n  stat: [/etc/os-release, /usr]\n  stat-keep: {properties: {kind: {const: directory}}}\nparse: {plugin: keeper, op: parse}\ninto: kept\n",
    );
    let doc = collect(&[keeper], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["keeper"]["status"], "ok", "{doc}");
    let inputs = request("keeper")["inputs"].as_array().unwrap().clone();
    assert_eq!(inputs.len(), 2, "{inputs:?}");
    assert!(
        inputs[0]["content"].is_string() && inputs[0]["stat"].is_null(),
        "a read file keeps its content, not a stat the schema refused: {inputs:?}"
    );
    assert_eq!(inputs[1]["path"], "/usr");
    assert_eq!(inputs[1]["stat"]["kind"], "directory");
    for (read, why) in [
        ("stat-keep: {}", "list the files under read.stat"),
        ("stat: [/x]\n  stat-keep: {type: 5}", "no valid schema"),
        ("stat: [/usr/**/x]", "whole last component"),
    ] {
        let error = Collector::parse(&format!(
            "id: c\nread:\n  {read}\nparse: {{plugin: p, op: o}}\ninto: out\n"
        ))
        .unwrap_err();
        assert!(error.contains(why), "{read}: {error}");
    }
}

#[test]
fn a_named_fact_nobody_produces_fails_the_collector_naming_it() {
    let orphan = collector(
        "id: orphan\nread:\n  stat-from: [nowhere.*.path]\nparse: {plugin: orphan, op: parse}\ninto: orphan\n",
    );
    let doc = collect(&[orphan], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["orphan"]["status"], "error");
    assert_eq!(
        doc["collectors"]["orphan"]["reason"],
        "needs fact nowhere, which no collector produces"
    );
}

#[test]
fn a_named_pattern_must_be_whole_segment_wildcards_after_a_literal_outside_into() {
    for (pattern, why) in [
        ("*.x", "starts with a wildcard"),
        ("a.b*.c", "whole segments"),
        ("a..b", "whole segments"),
        ("out.x", "which this collector writes"),
        ("out", "which this collector writes"),
        ("{a.b", "nor {a fact path}"),
        ("{a.b}x", "nor {a fact path}"),
        ("{a.{b}}/x", "nor {a fact path}"),
        ("{a.b}/**/x", "whole last component"),
        ("{*.x}/y", "starts with a wildcard"),
        ("{out.x}/y", "which this collector writes"),
    ] {
        let error = Collector::parse(&format!(
            "id: c\nread:\n  files-from: ['{pattern}']\nparse: {{plugin: p, op: o}}\ninto: out\n"
        ))
        .unwrap_err();
        assert!(error.contains(why), "{pattern}: {error}");
    }
    assert!(Collector::parse("id: c\nread:\n  stat-from: [env.*.*.path]\nparse: {plugin: p, op: o}\ninto: files.path\n").is_ok());
    assert!(Collector::parse("id: c\nread:\n  stat-from: ['{accounts.passwd.*.home}/.ssh/**']\nparse: {plugin: p, op: o}\ninto: ssh-user\n").is_ok());
}

#[test]
fn files_resolve_in_the_root_and_merge_with_stat() {
    let c = collector(
        "id: dump\nread:\n  files: [/etc/os-release, /etc/absent]\n  stat: [/etc/os-*, /usr/lib/os-release]\nparse: {plugin: dump, op: parse}\ninto: dump\n",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["dump"]["status"], "ok", "{doc}");
    let inputs = request("dump")["inputs"].as_array().unwrap().clone();
    let paths: Vec<_> = inputs.iter().map(|i| i["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/etc/os-release", "/usr/lib/os-release"]);
    assert!(
        inputs[0]["content"]
            .as_str()
            .unwrap()
            .contains("VERSION_CODENAME=resolute")
    );
    assert_eq!(inputs[0]["stat"]["kind"], "symlink");
    assert!(inputs[1].get("content").is_none());
    assert_eq!(inputs[1]["stat"]["kind"], "file");
}

#[test]
fn hash_adds_digests_to_regular_files_alone() {
    let c = collector(
        "id: dump\nread:\n  stat: [/etc/os-release, /usr/lib/os-release]\n  hash: [sha256]\nparse: {plugin: dump, op: parse}\ninto: dump\n",
    );
    let inputs = systemlint::collect::inputs(&c, &options(false)).unwrap();
    let stats: Vec<_> = inputs
        .iter()
        .map(|i| match i {
            systemlint_protocol::Input::File(f) => f.stat.clone().unwrap(),
            _ => panic!("{i:?}"),
        })
        .collect();
    assert_eq!(
        (stats[0].sha256.as_deref(), stats[0].linked_to.is_some()),
        (None, true),
        "a symlink gets no digest"
    );
    assert_eq!(stats[1].sha256.as_ref().map(String::len), Some(64));
    assert_eq!(stats[1].sha512, None);
}

#[test]
fn an_absent_path_reaches_the_plugin_from_an_inline_collector_alone() {
    let mut c = collector(
        "id: dump\nread:\n  stat: [/etc/absent, /usr/lib/os-release]\nparse: {plugin: dump, op: parse}\ninto: dump\n",
    );
    let absent = |c: &Collector| {
        systemlint::collect::inputs(c, &options(false))
            .unwrap()
            .iter()
            .filter_map(|i| match i {
                systemlint_protocol::Input::File(f) if f.absent => Some(f.path.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert!(
        absent(&c).is_empty(),
        "a shipped collector skips an absent path"
    );
    c.inline = true;
    assert_eq!(absent(&c), ["/etc/absent"]);
}

#[test]
fn exec_is_skipped_under_root_and_runs_live() {
    let c = collector(
        "id: exec\nread:\n  exec: [/bin/sh, -c, 'echo out; echo err >&2; exit 3']\nparse: {plugin: base, op: release}\ninto: exec\n",
    );
    let skipped = collect(std::slice::from_ref(&c), &plugins(), &options(false));
    assert_eq!(skipped["collectors"]["exec"]["status"], "skipped");
    assert!(
        skipped["collectors"]["exec"]["reason"]
            .as_str()
            .unwrap()
            .contains("/bin/sh on a live host only"),
        "{skipped}"
    );
    assert!(skipped.get("exec").is_none());
    let c = Collector {
        parse: systemlint::collector::Parse {
            plugin: "live".into(),
            op: "parse".into(),
        },
        into: "exec2".into(),
        ..c
    };
    let live = collect(&[c], &plugins(), &options(true));
    assert_eq!(live["collectors"]["exec"]["status"], "ok", "{live}");
    assert_eq!(live["meta"]["subject"]["kind"], "host");
    let exec = request("live")["inputs"][0].clone();
    assert_eq!(
        (
            exec["stdout"].as_str(),
            exec["stderr"].as_str(),
            exec["exit"].as_i64()
        ),
        (Some("out\n"), Some("err\n"), Some(3))
    );
}

#[test]
fn a_collector_with_files_keeps_them_under_root_without_its_exec() {
    let c = collector(
        "id: mixed\nread:\n  files: [/etc/os-release]\n  exec: [/bin/false]\nparse: {plugin: mixed, op: parse}\ninto: mixed\n",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["mixed"]["status"], "ok", "{doc}");
    let inputs = request("mixed")["inputs"].as_array().unwrap().clone();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["path"], "/etc/os-release");
}

#[test]
fn an_absent_program_reaches_the_plugin_as_exit_127() {
    let c = collector(
        "id: absent\nread:\n  exec: [/nonexistent/systemlint-test, -T]\nparse: {plugin: absent, op: parse}\ninto: absent\n",
    );
    let doc = collect(&[c], &plugins(), &options(true));
    assert_eq!(doc["collectors"]["absent"]["status"], "ok", "{doc}");
    let exec = request("absent")["inputs"][0].clone();
    assert_eq!(
        (exec["exit"].as_i64(), exec["stdout"].as_str()),
        (Some(127), Some(""))
    );
    assert_eq!(exec["stderr"], "/nonexistent/systemlint-test: not found\n");
}

#[test]
fn needs_order_the_run_and_carry_the_facts() {
    let derive =
        collector("id: derive\nparse: {plugin: derive, op: codename}\ninto: apt.codename\n");
    let base = collector("id: base\nparse: {plugin: base, op: release}\ninto: os.release\n");
    let doc = collect(&[derive.clone(), base], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["derive"]["status"], "ok", "{doc}");
    assert_eq!(doc["apt"]["codename"]["seen"], true);
    assert_eq!(
        request("derive")["facts"]["os.release"]["VERSION_CODENAME"],
        "resolute"
    );
    let lonely = collect(std::slice::from_ref(&derive), &plugins(), &options(false));
    assert!(
        lonely["collectors"]["derive"]["reason"]
            .as_str()
            .unwrap()
            .contains("needs fact os.release, which no collector produces"),
        "{lonely}"
    );
    let failing = collector("id: base\nparse: {plugin: broken, op: parse}\ninto: os.release\n");
    let doc = collect(&[derive, failing], &plugins(), &options(false));
    assert!(
        doc["collectors"]["derive"]["reason"]
            .as_str()
            .unwrap()
            .contains("collector base finished error"),
        "{doc}"
    );
}

#[test]
fn progress_counts_each_collector_in_run_order() {
    let derive =
        collector("id: derive\nparse: {plugin: ordered, op: codename}\ninto: apt.codename\n");
    let base = collector("id: base\nparse: {plugin: base, op: release}\ninto: os.release\n");
    let mut seen = Vec::new();
    collect_reporting(
        &[derive, base],
        &plugins(),
        &options(false),
        &mut |done, total, id| seen.push((done, total, id.to_owned())),
    );
    assert_eq!(
        seen,
        [(0, 2, "base".to_owned()), (1, 2, "derive".to_owned())]
    );
}

#[test]
fn two_jobs_run_two_collectors_at_once() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("collect");
    plugins();
    for marker in ["meet-a.here", "meet-b.here"] {
        let _ = std::fs::remove_file(dir.join(marker));
    }
    let meet = |me: &str| {
        collector(&format!(
            "id: meet-{me}\nparse: {{plugin: meet-{me}, op: parse}}\ninto: meet.{me}\n"
        ))
    };
    let doc = collect(
        &[meet("a"), meet("b")],
        &plugins(),
        &Options {
            jobs: 2,
            ..options(false)
        },
    );
    assert_eq!(
        (&doc["meet"]["a"]["met"], &doc["meet"]["b"]["met"]),
        (&Value::Bool(true), &Value::Bool(true)),
        "{doc}"
    );
}

#[test]
fn any_jobs_give_the_sequential_document() {
    let set = || {
        [
            "id: derive\nparse: {plugin: same-derive, op: codename}\ninto: apt.codename\n",
            "id: a\nparse: {plugin: same-a, op: parse}\ninto: x.a\n",
            "id: base\nparse: {plugin: same-base, op: release}\ninto: os.release\n",
            "id: b\nparse: {plugin: same-b, op: parse}\ninto: x.b\n",
        ]
        .map(collector)
    };
    let sequential = collect(
        &set(),
        &plugins(),
        &Options {
            jobs: 1,
            ..options(false)
        },
    );
    assert_eq!(
        sequential["collectors"]["derive"]["status"], "ok",
        "{sequential}"
    );
    assert_eq!(
        sequential["collectors"]["b"]["status"], "error",
        "{sequential}"
    );
    let parallel = collect(
        &set(),
        &plugins(),
        &Options {
            jobs: 64,
            ..options(false)
        },
    );
    assert_eq!(
        serde_json::to_string(&parallel).unwrap(),
        serde_json::to_string(&sequential).unwrap()
    );
}

#[test]
fn a_cycle_fails_every_member() {
    let derive =
        collector("id: derive\nparse: {plugin: derive, op: codename}\ninto: apt.codename\n");
    let looping = collector("id: loop\nparse: {plugin: loop, op: release}\ninto: os.release\n");
    let doc = collect(&[derive, looping], &plugins(), &options(false));
    for id in ["derive", "loop"] {
        assert!(
            doc["collectors"][id]["reason"]
                .as_str()
                .unwrap()
                .contains("wait on this collector in turn"),
            "{doc}"
        );
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
        let c = collector(&format!(
            "id: x\nparse: {{plugin: {plugin}, op: {op}}}\ninto: x\n"
        ));
        let doc = collect(&[c], &plugins(), &options(false));
        assert_eq!(doc["collectors"]["x"]["status"], "error", "{doc}");
        assert!(
            doc["collectors"]["x"]["reason"]
                .as_str()
                .unwrap()
                .contains(reason),
            "{doc}"
        );
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
    assert_eq!(
        rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
        "1970-01-01T00:00:00Z"
    );
    assert!(rfc3339(SystemTime::now()).starts_with("20"));
}

#[test]
fn base64_matches_rfc_4648() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), encoded);
    }
    assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
}

#[test]
fn hash_key_follows_rfc_4231_and_names_itself() {
    let key = HashKey::configured("Jefe");
    assert_eq!(
        key.hash("what do ya want for nothing?"),
        "hmac-sha256:5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(key.id().len(), 16);
    assert_ne!(key.id(), HashKey::configured("Jeff").id());
    let (a, b) = (HashKey::random().unwrap(), HashKey::random().unwrap());
    assert_ne!(
        a.hash("x"),
        b.hash("x"),
        "two runs never share a random key"
    );
    assert!(
        !format!("{a:?}").contains("key:"),
        "Debug never prints the key"
    );
}

#[test]
fn hash_replaces_marked_strings_before_redaction_and_keeps_empty_ones() {
    let c = collector("id: hasher\nparse: {plugin: hasher, op: parse}\ninto: h\n");
    let doc = collect(&[c], &plugins(), &options(false));
    let env = &doc["h"]["env"];
    assert_eq!(
        env["TOKEN"],
        HashKey::configured("a fixture hash key").hash("s3cret")
    );
    assert_eq!(
        (
            env["EMPTY"].as_str(),
            env["N"].as_i64(),
            env["BOTH"].as_str()
        ),
        (Some(""), Some(1), Some(REDACTED))
    );
    assert!(!doc.to_string().contains("s3cret"));
    assert_eq!(doc["collectors"]["hasher"]["hashed"], 2);
    assert_eq!(doc["meta"]["hash-key"]["source"], "configured");
    assert_eq!(
        doc["meta"]["hash-key"]["id"],
        HashKey::configured("a fixture hash key").id()
    );
}

#[test]
fn a_secret_collector_hashes_every_string_once() {
    let c = collector(
        "id: spiller
parse: {plugin: spiller, op: parse}
into: s
secret: true
",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    let key = HashKey::configured("a fixture hash key");
    assert_eq!(
        doc["s"],
        serde_json::json!({"exit-status": 0, "stdout": key.hash("pw"), "stdout-lines": [key.hash("pw"), ""], "a/b": {"c~d": key.hash("x")}})
    );
    assert_eq!(
        doc["collectors"]["spiller"]["hashed"], 3,
        "the plugin’s own mark on stdout is not hashed twice"
    );
}

#[test]
fn a_live_collector_is_skipped_under_root() {
    let c = collector(
        "id: proc\nlive: true\nread:\n  files: [/proc/self/stat]\nparse: {plugin: proc, op: parse}\ninto: proc\n",
    );
    let doc = collect(std::slice::from_ref(&c), &plugins(), &options(false));
    assert_eq!(doc["collectors"]["proc"]["status"], "skipped");
    assert!(
        doc["collectors"]["proc"]["reason"]
            .as_str()
            .unwrap()
            .contains("live host only, and --root"),
        "{doc}"
    );
    assert_eq!(
        collect(&[c], &plugins(), &options(true))["collectors"]["proc"]["status"],
        "ok"
    );
}

#[test]
fn a_privileged_collector_is_skipped_in_an_unprivileged_run() {
    let c = collector(
        "id: secret\nprivileged: true\nread:\n  files: [/etc/os-release]\nparse: {plugin: secret, op: parse}\ninto: secret\n",
    );
    let doc = collect(
        std::slice::from_ref(&c),
        &plugins(),
        &Options {
            privileged: false,
            ..options(true)
        },
    );
    assert_eq!(
        (
            doc["collectors"]["secret"]["status"].as_str(),
            doc["meta"]["privileged"].as_bool()
        ),
        (Some("skipped"), Some(false)),
        "{doc}"
    );
    assert_eq!(
        doc["collectors"]["secret"]["reason"],
        "needs root, and this run is unprivileged"
    );
    assert_eq!(
        collect(&[c], &plugins(), &options(true))["collectors"]["secret"]["status"],
        "ok"
    );
}

#[test]
fn an_image_config_is_read_from_the_host_only_when_given() {
    let c = collector(
        "id: image\nread:\n  image-config: true\nparse: {plugin: image, op: parse}\ninto: image\n",
    );
    let without = collect(std::slice::from_ref(&c), &plugins(), &options(false));
    assert_eq!(without["collectors"]["image"]["status"], "skipped");
    assert!(
        without["collectors"]["image"]["reason"]
            .as_str()
            .unwrap()
            .contains("no --image-config"),
        "{without}"
    );
    let config = Path::new(env!("CARGO_TARGET_TMPDIR")).join("image-config.json");
    std::fs::write(&config, r#"{"config":{"Env":["A=1"]}}"#).unwrap();
    let with = collect(
        std::slice::from_ref(&c),
        &plugins(),
        &Options {
            image_config: Some(config.clone()),
            ..options(false)
        },
    );
    assert_eq!(with["collectors"]["image"]["status"], "ok", "{with}");
    assert_eq!(
        with["meta"]["subject"]["image-config"],
        config.to_str().unwrap()
    );
    let input = request("image")["inputs"][0].clone();
    assert_eq!(
        (input["path"].as_str(), input["content"].as_str()),
        (config.to_str(), Some(r#"{"config":{"Env":["A=1"]}}"#))
    );
    let missing = collect(
        &[c],
        &plugins(),
        &Options {
            image_config: Some(config.with_extension("absent")),
            ..options(false)
        },
    );
    assert!(
        missing["collectors"]["image"]["reason"]
            .as_str()
            .unwrap()
            .contains("can’t read image config"),
        "{missing}"
    );
}

#[test]
fn a_glob_matching_a_directory_skips_it() {
    let c = collector(
        "id: dirs\nread:\n  files: [/etc/*]\nparse: {plugin: dirs, op: parse}\ninto: dirs\n",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["dirs"]["status"], "ok", "{doc}");
    let paths: Vec<String> = request("dirs")["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(paths, ["/etc/os-release"]);
}

#[test]
fn a_glob_through_a_file_is_absent_not_an_error() {
    let c = collector(
        "id: notdir\nread:\n  files: [/etc/*/environ]\n  stat: [/etc/*/environ]\nparse: {plugin: notdir, op: parse}\ninto: notdir\n",
    );
    let doc = collect(&[c], &plugins(), &options(false));
    assert_eq!(
        doc["collectors"]["notdir"]["status"], "ok",
        "/etc/os-release/environ is absent, as /proc/bootconfig/environ is: {doc}"
    );
    assert_eq!(request("notdir")["inputs"], serde_json::json!([]));
}

#[test]
fn a_failed_collector_keeps_its_own_debug_records_and_no_other_collectors() {
    systemlint::trail::install(false, systemlint::trail::LogFormat::Text);
    let failing = collector(
        "id: traced\nread:\n  files: [/etc/os-release]\nparse: {plugin: traced, op: parse}\ninto: traced\n",
    );
    let passing = collector(
        "id: untraced\nread:\n  files: [/etc/os-release]\nparse: {plugin: untraced, op: parse}\ninto: untraced\n",
    );
    let doc = collect(&[failing, passing], &plugins(), &options(false));
    assert_eq!(doc["collectors"]["traced"]["status"], "error");
    let kept = systemlint::trail::take("collector traced");
    assert!(
        kept.iter()
            .any(|l| l == "collector traced sends 1 inputs to traced parse"),
        "{kept:?}"
    );
    assert!(
        kept.iter()
            .any(|l| l.ends_with("/traced exited 3 with 0 bytes on stdout")),
        "{kept:?}"
    );
    assert!(kept.iter().all(|l| !l.contains("untraced")), "{kept:?}");
    assert!(
        systemlint::trail::take("collector traced").is_empty(),
        "taken once"
    );
    assert!(!systemlint::trail::take("collector untraced").is_empty());
}

#[test]
fn a_process_that_exited_mid_read_is_absent_and_a_denied_read_is_not() {
    use std::io::{Error, ErrorKind};
    assert!(systemlint::collect::gone(&Error::from_raw_os_error(
        libc::ESRCH
    )));
    assert!(systemlint::collect::gone(&Error::from(ErrorKind::NotFound)));
    assert!(!systemlint::collect::gone(&Error::from_raw_os_error(
        libc::EACCES
    )));
}

#[test]
fn a_partial_collector_keeps_what_it_may_read_and_names_the_rest() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("partial");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, mode) in [("readable", 0o644), ("refused", 0o000)] {
        let temporary = dir.join(format!("{name}.{}.tmp", std::process::id()));
        std::fs::write(&temporary, "A=1\n").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::rename(&temporary, dir.join(name)).unwrap();
    }
    let options = Options {
        root: Root::open(&dir).unwrap(),
        ..options(false)
    };
    let yaml = "id: dump\nread:\n  files: [/*]\nparse: {plugin: dump, op: parse}\ninto: dump\n";
    let root = rustix::process::geteuid().is_root();
    let partial = collector(&format!("{yaml}partial: true\n"));
    let (inputs, unreadable) = read_partial(&partial, &options, &Named::default()).unwrap();
    let read: Vec<String> = inputs
        .iter()
        .map(|i| {
            serde_json::to_value(i).unwrap()["path"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    if root {
        assert_eq!(
            (read.len(), unreadable.len()),
            (2, 0),
            "root reads a 0000 file"
        );
    } else {
        assert_eq!(read, ["/readable"]);
        assert_eq!(
            unreadable.into_iter().collect::<Vec<_>>(),
            [("/refused".to_owned(), "permission denied".to_owned())]
        );
    }
    let doc = collect(std::slice::from_ref(&partial), &plugins(), &options);
    assert_eq!(doc["collectors"]["dump"]["status"], "ok", "{doc}");
    assert_eq!(
        doc["collectors"]["dump"]["unreadable"].is_object(),
        !root,
        "{doc}"
    );
    let whole = collect(&[collector(yaml)], &plugins(), &options);
    let reason = whole["collectors"]["dump"]["reason"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(
        reason.contains("can’t read /refused"),
        !root,
        "without partial one refusal fails it: {whole}"
    );
}
