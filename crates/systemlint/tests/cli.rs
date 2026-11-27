// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn base(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The core in an empty working and user config directory, with no SYSTEMLINT_CONFIG, in the C locale.
fn core() -> Command {
    let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-home");
    std::fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_systemlint"));
    command
        .env("XDG_CONFIG_HOME", &home)
        .env("LC_ALL", "C")
        .env_remove("SYSTEMLINT_CONFIG")
        .current_dir(&home);
    command
}

/// Runs the core with an empty config and the C locale, returning the exit code and stderr.
fn run(dir: &Path, config: &str, args: &[&str]) -> (i32, String) {
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    let out = core()
        .arg("--config")
        .arg(&path)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn facts(dir: &Path) -> String {
    let path = dir.join("facts.yaml");
    std::fs::write(
        &path,
        format!("meta: {{schema: {}}}\n", systemlint::collect::SCHEMA),
    )
    .unwrap();
    path.display().to_string()
}

#[test]
fn a_usage_error_exits_2() {
    let (code, _) = run(&base("usage"), "", &["check", "--bogus"]);
    assert_eq!(code, 2);
}

#[test]
fn jobs_outside_1_to_64_is_a_usage_error() {
    let dir = base("jobs");
    for refused in ["0", "65"] {
        let (code, stderr) = run(&dir, "", &["--jobs", refused, "plugin", "list"]);
        assert_eq!(code, 2, "--jobs {refused}: {stderr}");
    }
    for taken in ["1", "64"] {
        let (code, stderr) = run(&dir, "", &["--jobs", taken, "plugin", "list"]);
        assert_ne!(code, 2, "--jobs {taken}: {stderr}");
    }
}

#[test]
fn a_json_log_line_names_its_scope() {
    let (code, stderr) = run(
        &base("log-json"),
        "",
        &["-v", "--log-format", "json", "plugin", "list"],
    );
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<serde_json::Value> = stderr
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        lines.iter().any(|l| l["scope"] == "config"
            && l["level"] == "debug"
            && l["timestamp"].is_string()
            && l["message"].is_string()),
        "{stderr}"
    );
}

#[test]
fn a_log_format_without_verbose_exits_2() {
    let (code, stderr) = run(
        &base("log-json-quiet"),
        "",
        &["--log-format", "json", "plugin", "list"],
    );
    assert_eq!(code, 2, "{stderr}");
}

#[test]
fn fix_off_in_the_config_exits_5_naming_the_key() {
    let (code, stderr) = run(
        &base("fix-off"),
        "fix: {enabled: false}\n",
        &["fix", "--dry-run"],
    );
    assert_eq!(code, 5, "{stderr}");
    assert!(stderr.contains("fix.enabled is false"), "{stderr}");
}

#[test]
fn fix_with_force_and_dry_run_exits_2() {
    let (code, stderr) = run(&base("fix-both"), "", &["fix", "--force", "--dry-run"]);
    assert_eq!(code, 2, "{stderr}");
}

#[test]
fn fix_with_all_and_tags_exits_2() {
    let (code, stderr) = run(&base("fix-all"), "", &["fix", "--all", "--tags", "files"]);
    assert_eq!(code, 2, "{stderr}");
}

#[test]
fn a_missing_config_exits_5_with_the_fix() {
    let dir = base("config");
    let missing = dir.join("absent.yaml");
    let out = core()
        .arg("--config")
        .arg(&missing)
        .args(["plugin", "list"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("Pass an existing file to --config or SYSTEMLINT_CONFIG, or drop it to use the defaults."), "{stderr}");
}

#[test]
fn an_invalid_config_exits_5() {
    let (code, stderr) = run(&base("invalid"), "nonsense: 1\n", &["plugin", "list"]);
    assert_eq!(code, 5, "{stderr}");
}

#[test]
fn an_invalid_config_prints_the_layers_read_before_it() {
    let (code, stderr) = run(
        &base("invalid-traced"),
        "nonsense: 1\n",
        &["plugin", "list"],
    );
    assert_eq!(code, 5, "{stderr}");
    assert!(
        stderr.contains("is not a valid configuration")
            && stderr.contains("\n  config ")
            && stderr.contains("is absent, skipped"),
        "{stderr}"
    );
}

#[test]
fn a_document_of_another_schema_prints_the_bytes_read() {
    let dir = base("schema-traced");
    let path = dir.join("facts.yaml");
    std::fs::write(&path, "meta: {schema: 0}\n").unwrap();
    let (code, stderr) = run(&dir, "", &["check", &path.display().to_string()]);
    assert_eq!(code, 6, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "\n  read 18 bytes of facts from {}",
            path.display()
        )),
        "{stderr}"
    );
}

#[test]
fn a_refused_ruleset_directory_exits_5_naming_chmod() {
    let dir = base("refused");
    let rules = dir.join("rules");
    std::fs::create_dir(&rules).unwrap();
    std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o777)).unwrap();
    let facts = facts(&dir);
    let (code, stderr) = run(
        &dir,
        &format!("check: {{directories: [{}]}}\n", rules.display()),
        &["check", &facts],
    );
    assert_eq!(code, 5, "{stderr}");
    assert!(stderr.contains("chmod go-w"), "{stderr}");
    assert!(
        stderr.contains(" owners: root, the user and the core’s owner"),
        "{stderr}"
    );
}

#[test]
fn a_missing_facts_document_exits_6_naming_facts_output() {
    let dir = base("input");
    let absent = dir.join("absent.yaml").display().to_string();
    let (code, stderr) = run(&dir, "", &["check", &absent]);
    assert_eq!(code, 6, "{stderr}");
    assert!(
        stderr.contains(&format!("Run systemlint facts --output {absent} first")),
        "{stderr}"
    );
}

#[test]
fn a_document_of_another_schema_exits_6() {
    let dir = base("schema");
    let path = dir.join("facts.yaml");
    std::fs::write(&path, "meta: {schema: 0}\n").unwrap();
    let (code, stderr) = run(&dir, "", &["check", &path.display().to_string()]);
    assert_eq!(code, 6, "{stderr}");
}

#[test]
fn a_missing_root_exits_6() {
    let dir = base("root");
    for command in ["facts", "fix"] {
        let (code, stderr) = run(
            &dir,
            "",
            &[
                "--quiet",
                command,
                "--root",
                &dir.join("absent").display().to_string(),
            ],
        );
        assert_eq!(code, 6, "{command}: {stderr}");
        assert!(stderr.contains("it does not exist"), "{command}: {stderr}");
    }
}

#[test]
fn an_output_in_a_missing_directory_exits_7_naming_mkdir() {
    let dir = base("output");
    let facts = facts(&dir);
    let missing = dir.join("absent");
    let (code, stderr) = run(
        &dir,
        "",
        &[
            "--quiet",
            "check",
            "--output",
            &missing.join("report.txt").display().to_string(),
            &facts,
        ],
    );
    assert_eq!(code, 7, "{stderr}");
    assert!(
        stderr.contains(&format!("Run mkdir -p {}", missing.display())),
        "{stderr}"
    );
}

#[test]
fn an_output_into_proc_exits_7_naming_the_file_system() {
    let dir = base("output-proc");
    let facts = facts(&dir);
    let (code, stderr) = run(
        &dir,
        "",
        &["--quiet", "check", "--output", "/proc/report.txt", &facts],
    );
    assert_eq!(code, 7, "{stderr}");
    assert!(stderr.starts_with("Can’t write report.txt into /proc: it is on proc, a kernel file system that holds no ordinary files. Pick a directory on a regular file system."), "{stderr}");
}

/// Names the variable holding the core’s arguments, `\u{1f}`-separated, that [`launch_with_no_random`] runs.
const NO_RANDOM: &str = "SYSTEMLINT_TEST_NO_RANDOM";

/// A launcher, inert unless [`NO_RANDOM`] is set: denies `getrandom` with `EPERM` through seccomp, then becomes the core.
#[test]
fn launch_with_no_random() {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::os::unix::process::CommandExt;
    let Ok(args) = std::env::var(NO_RANDOM) else {
        return;
    };
    let filter = SeccompFilter::new(
        [(libc::SYS_getrandom, vec![])].into(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();
    let error = core()
        .args(args.split('\u{1f}'))
        .env_remove(NO_RANDOM)
        .exec();
    panic!("can’t become the core: {error}");
}

#[test]
fn no_random_hash_key_exits_70() {
    let dir = base("no-random");
    let config = dir.join("config.yaml");
    std::fs::write(&config, "").unwrap();
    let args = [
        "--config",
        &config.display().to_string(),
        "--quiet",
        "facts",
        "--root",
        &dir.display().to_string(),
    ]
    .join("\u{1f}");
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "launch_with_no_random", "--nocapture"])
        .env(NO_RANDOM, args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(70), "{stderr}");
    assert!(stderr.contains("can’t draw a random hash key"), "{stderr}");
}

#[test]
fn a_save_in_a_missing_directory_exits_7() {
    let dir = base("save");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let save = dir.join("absent/facts.yaml").display().to_string();
    let (code, stderr) = run(
        &dir,
        "",
        &[
            "--quiet",
            "facts",
            "--root",
            &root.display().to_string(),
            "--output",
            &save,
        ],
    );
    assert_eq!(code, 7, "{stderr}");
}

#[test]
fn a_save_says_what_it_wrote_and_how_to_lint_it_unless_quiet() {
    let dir = base("saved");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let save = dir.join("facts.yaml").display().to_string();
    let (code, stderr) = run(
        &dir,
        "",
        &[
            "facts",
            "--root",
            &root.display().to_string(),
            "--output",
            &save,
        ],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains(&format!("Saved facts from 0 collectors (0 errors) to {save}. Check them with: systemlint check {save}")), "{stderr}");
    let (_, quiet) = run(
        &dir,
        "",
        &[
            "--quiet",
            "facts",
            "--root",
            &root.display().to_string(),
            "--output",
            &save,
        ],
    );
    assert!(!quiet.contains("Saved"), "{quiet}");
}

#[test]
fn an_inline_collector_runs_beside_the_shipped_ones() {
    let dir = base("inline");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let save = dir.join("facts.json");
    let config = "collect:\n  collectors:\n    - {id: nginx, read: {stat: [/etc/nginx.conf]}, parse: {plugin: formats, op: stat}, into: files.nginx}\n";
    run(
        &dir,
        config,
        &[
            "--quiet",
            "facts",
            "--root",
            root.to_str().unwrap(),
            "-o",
            save.to_str().unwrap(),
        ],
    );
    let facts: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&save).unwrap()).unwrap();
    assert_eq!(
        facts["collectors"]["nginx"]["into"], "files.nginx",
        "{facts}"
    );
}

#[test]
fn facts_format_beats_the_output_extension() {
    let dir = base("format");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let (json, yaml) = (dir.join("facts.json"), dir.join("facts.yaml"));
    let written = |path: &std::path::Path, args: &[&str]| {
        let mut all = vec![
            "--quiet",
            "facts",
            "--root",
            root.to_str().unwrap(),
            "-o",
            path.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        assert_eq!(run(&dir, "", &all).0, 0);
        std::fs::read_to_string(path).unwrap()
    };
    assert!(
        written(&json, &[]).starts_with('{'),
        "a .json name writes JSON"
    );
    assert!(
        !written(&yaml, &[]).starts_with('{'),
        "any other name writes YAML"
    );
    assert!(
        !written(&json, &["--format", "yaml"]).starts_with('{'),
        "--format yaml beats .json"
    );
    assert!(
        written(&yaml, &["--format", "json"]).starts_with('{'),
        "--format json beats .yaml"
    );
}

#[test]
fn collect_format_beats_the_output_extension_and_the_flag_beats_it() {
    let dir = base("collect-format");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let yaml = dir.join("facts.yaml");
    let written = |args: &[&str]| {
        let mut all = vec![
            "--quiet",
            "facts",
            "--root",
            root.to_str().unwrap(),
            "-o",
            yaml.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        assert_eq!(run(&dir, "collect: {format: json}\n", &all).0, 0);
        std::fs::read_to_string(&yaml).unwrap()
    };
    assert!(
        written(&[]).starts_with('{'),
        "collect.format json beats .yaml"
    );
    assert!(
        !written(&["--format", "yaml"]).starts_with('{'),
        "--format yaml beats collect.format"
    );
}

/// The report `check` prints under `check.plain: true` and `args` for a document failing one rule.
fn plain_report(dir: &Path, args: &[&str]) -> String {
    let path = dir.join("facts.yaml");
    std::fs::write(
        &path,
        format!("meta: {{schema: {}}}\nx: 1\n", systemlint::collect::SCHEMA),
    )
    .unwrap();
    let file = dir.join("config.yaml");
    std::fs::write(&file, "check:\n  plain: true\n  rulesets:\n    t: {tags: [default], rules: {t/x: {fact: x, expect: {const: 2}, severity: error}}}\n").unwrap();
    let out = core()
        .arg("--config")
        .arg(&file)
        .arg("check")
        .args(args)
        .arg(&path)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn lint_plain_prints_tab_separated_lines_until_a_flag_says_otherwise() {
    let dir = base("lint-plain");
    assert!(
        plain_report(&dir, &[]).contains("t/x\t"),
        "check.plain prints plain lines"
    );
    assert!(
        !plain_report(&dir, &["--no-plain"]).contains("t/x\t"),
        "--no-plain beats check.plain"
    );
    assert!(
        plain_report(&dir, &["--plain", "--no-plain"]).contains("t/x")
            && !plain_report(&dir, &["--plain", "--no-plain"]).contains("t/x\t"),
        "the last of --plain and --no-plain wins"
    );
    assert!(
        plain_report(&dir, &["--format", "json"]).starts_with('{'),
        "--format beats check.plain"
    );
}

#[test]
fn plugins_format_json_lists_plugins_as_json() {
    let dir = base("plugins-format");
    let path = dir.join("config.yaml");
    std::fs::write(&path, "plugins: {format: json}\n").unwrap();
    let json = core()
        .arg("--config")
        .arg(&path)
        .args(["plugin", "list"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&json.stdout).starts_with('['),
        "plugins.format json"
    );
    let human = core()
        .arg("--config")
        .arg(&path)
        .args(["plugin", "list", "--format", "human"])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&human.stdout).starts_with('['),
        "--format human beats plugins.format"
    );
}

#[test]
fn an_output_counts_its_findings_one_in_the_singular() {
    let dir = base("wrote");
    let path = dir.join("facts.yaml");
    std::fs::write(
        &path,
        format!("meta: {{schema: {}}}\nx: 1\n", systemlint::collect::SCHEMA),
    )
    .unwrap();
    let report = dir.join("report.sarif").display().to_string();
    let config = "check:\n  rulesets:\n    t: {tags: [default], rules: {t/x: {fact: x, expect: {const: 2}, severity: error}}}\n";
    let (code, stderr) = run(
        &dir,
        config,
        &[
            "check",
            "--format",
            "sarif",
            "--output",
            &report,
            &path.display().to_string(),
        ],
    );
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!("Wrote 1 finding to {report}.")),
        "{stderr}"
    );
    let (_, quiet) = run(
        &dir,
        config,
        &[
            "--quiet",
            "check",
            "--output",
            &report,
            &path.display().to_string(),
        ],
    );
    assert!(!quiet.contains("Wrote"), "{quiet}");
}

#[test]
fn a_loaded_document_past_a_collector_ttl_leaves_its_rules_not_run() {
    let dir = base("ttl");
    let path = dir.join("facts.yaml");
    let document = |ttl: &str| {
        format!(
            "meta: {{schema: {}, collected-at: '2020-01-01T00:00:00Z'}}\nx: 1\ncollectors: {{c: {{status: ok, into: x{ttl}}}}}\n",
            systemlint::collect::SCHEMA
        )
    };
    let config = "check:\n  rulesets:\n    t: {tags: [default], rules: {t/x: {fact: x, expect: {const: 2}, severity: error}}}\n";
    let (facts, report) = (path.display().to_string(), dir.join("report.json"));
    std::fs::write(&path, document("")).unwrap();
    assert_eq!(
        run(&dir, config, &["check", &facts]).0,
        1,
        "no ttl judges x: 1 forever"
    );
    std::fs::write(&path, document(", ttl: 0")).unwrap();
    let args = [
        "check",
        "--format",
        "json",
        "--output",
        report.to_str().unwrap(),
        &facts,
    ];
    let (code, stderr) = run(&dir, config, &args);
    assert_eq!(code, 0, "{stderr}");
    let text = std::fs::read_to_string(&report).unwrap();
    assert!(text.contains("facts from collector c are"), "{text}");
    assert!(
        text.contains("past their ttl of 0 s: collect again"),
        "{text}"
    );
}

#[test]
fn ruleset_vars_come_from_var_then_vars_then_config_then_default() {
    let dir = base("vars");
    let path = dir.join("facts.yaml");
    std::fs::write(
        &path,
        format!("meta: {{schema: {}}}\nx: 1\n", systemlint::collect::SCHEMA),
    )
    .unwrap();
    let file = dir.join("vars.yaml");
    std::fs::write(&file, "want: 1\n").unwrap();
    let (facts, file) = (path.display().to_string(), file.display().to_string());
    let config = "check:\n  rulesets:\n    t: {tags: [default], vars: {want: {default: 2, minimum: 1, maximum: 9}}, rules: {t/x: {fact: x, expect: {const: '${want}'}, severity: error}}}\n";
    assert_eq!(
        run(&dir, config, &["check", &facts]).0,
        1,
        "the default 2 fails x: 1"
    );
    assert_eq!(
        run(
            &dir,
            &format!("{config}  vars: {{want: 1}}\n"),
            &["check", &facts]
        )
        .0,
        0,
        "check.vars beats the default"
    );
    assert_eq!(
        run(&dir, config, &["check", "--vars", &file, &facts]).0,
        0,
        "--vars beats the default"
    );
    assert_eq!(
        run(
            &dir,
            config,
            &["check", "--vars", &file, "--var", "want=3", &facts]
        )
        .0,
        1,
        "--var beats --vars"
    );
    assert_eq!(
        run(&dir, config, &["check", "--var", "want=1", &facts]).0,
        0,
        "a --var text takes the number type of its default"
    );
    let (code, stderr) = run(&dir, config, &["check", "--var", "wnat=1", &facts]);
    assert_eq!(
        (code, stderr.lines().next()),
        (5, Some("--var sets var wnat, which no ruleset declares")),
        "{stderr}"
    );
    assert_eq!(run(&dir, config, &["check", "--var", "=1", &facts]).0, 2);
}

#[test]
fn a_closed_stdout_ends_the_run_on_sigpipe_with_no_message() {
    use std::os::unix::process::ExitStatusExt;
    let dir = base("sigpipe");
    let path = dir.join("config.yaml");
    std::fs::write(&path, "").unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = core()
        .arg("--config")
        .arg(&path)
        .args(["plugin", "list", "--format", "json"])
        .stdout(writer)
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{:?}", out.status);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_arguments_print_a_short_summary_and_exit_2() {
    let dir = base("summary");
    let (code, stderr) = run(&dir, "", &[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("systemlint --help") && stderr.contains("Examples:"),
        "{stderr}"
    );
    assert!(
        stderr.lines().count() <= 12,
        "the summary stays short: {stderr}"
    );
}

#[test]
fn every_help_opens_with_its_description_then_examples_and_ends_with_a_docs_link() {
    for args in [
        &[][..],
        &["facts"],
        &["check"],
        &["plugin"],
        &["plugin", "list"],
    ] {
        let out = core().args(args).arg("--help").output().unwrap();
        let help = String::from_utf8(out.stdout).unwrap();
        let (examples, usage) = (
            help.find("\nExamples:\n").unwrap_or(usize::MAX),
            help.find("Usage:").unwrap_or(0),
        );
        assert!(examples < usage, "{args:?}: examples before usage\n{help}");
        assert!(
            help.trim_end()
                .lines()
                .last()
                .is_some_and(|l| l.contains("https://kiota.ch/damian-buho/systemlint")),
            "{args:?}: docs link last\n{help}"
        );
    }
}

#[test]
fn ctrl_c_says_so_and_exits_130() {
    let dir = base("interrupt");
    let path = dir.join("config.yaml");
    std::fs::write(&path, "").unwrap();
    let mut child = core()
        .arg("--config")
        .arg(&path)
        .args(["check", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Held open past the wait, so only the signal can end `check -`.
    let stdin = child.stdin.take();
    let caught = || {
        std::fs::read_to_string(format!("/proc/{}/status", child.id()))
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("SigCgt:\t")
                        .map(|m| u64::from_str_radix(m.trim(), 16).unwrap_or(0))
                })
            })
    };
    let mut polls = 0;
    while caught().is_none_or(|mask| mask & (1 << (libc::SIGINT - 1)) == 0) {
        polls += 1;
        assert!(polls < 6000, "the SIGINT handler was never installed");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::INT,
    )
    .unwrap();
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    assert_eq!(out.status.code(), Some(130), "{:?}", out.status);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Interrupted, stopping plugins…\n"
    );
}

#[test]
fn a_missing_systemlint_config_exits_5_naming_it() {
    let dir = base("env-config");
    let missing = dir.join("absent.yaml");
    let out = core()
        .env("SYSTEMLINT_CONFIG", &missing)
        .env("LC_ALL", "C")
        .args(["plugin", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&missing.display().to_string()),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_invalid_project_config_in_the_working_directory_exits_5_naming_it() {
    let dir = base("project-config");
    std::fs::write(dir.join(".systemlint.yaml"), "check:\n  format: html\n").unwrap();
    let out = core()
        .current_dir(&dir)
        .env("LC_ALL", "C")
        .args(["plugin", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains(".systemlint.yaml is not a valid configuration"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_project_config_skips_the_working_directory_file() {
    let dir = base("no-project");
    std::fs::write(dir.join(".systemlint.yaml"), "nonsense: 1\n").unwrap();
    let read = core()
        .current_dir(&dir)
        .args(["plugin", "list"])
        .output()
        .unwrap();
    assert_eq!(
        read.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    let skipped = core()
        .current_dir(&dir)
        .args(["--no-project-config", "plugin", "list"])
        .output()
        .unwrap();
    assert_eq!(
        skipped.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&skipped.stderr)
    );
}

#[test]
fn a_run_without_tags_counts_the_rules_the_default_left_out_in_the_summary() {
    let dir = base("left-out");
    let path = dir.join("facts.yaml");
    std::fs::write(
        &path,
        format!("meta: {{schema: {}}}\nx: 1\n", systemlint::collect::SCHEMA),
    )
    .unwrap();
    let facts = path.display().to_string();
    std::fs::write(dir.join("config.yaml"), "check:\n  rulesets:\n    perf: {tags: [performance], rules: {perf/x: {fact: x, expect: {const: 2}, severity: error}, perf/y: {fact: x, expect: {const: 3}}}}\n").unwrap();
    let report = |args: &[&str]| {
        let out = core()
            .arg("--config")
            .arg(dir.join("config.yaml"))
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.code().unwrap(), text)
    };
    let (code, text) = report(&["check", &facts]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("Not selected      2 rules, run them by naming their ruleset in --tags\n"),
        "{text}"
    );
    let (code, text) = report(&["check", "--tags", "performance", &facts]);
    assert_eq!(code, 1, "{text}");
    assert!(!text.contains("Not selected"), "{text}");
    let (code, text) = report(&["check", "--all", &facts]);
    assert_eq!(code, 1, "--all selects the non-default ruleset: {text}");
    let (code, text) = report(&["check", "--all", "--tags", "performance", &facts]);
    assert_eq!(code, 2, "--all and --tags exclude each other: {text}");
    let (_, quiet) = report(&["--quiet", "check", &facts]);
    assert!(!quiet.contains("Not selected"), "{quiet}");
}

#[test]
fn a_container_pattern_from_the_flag_or_the_config_turns_containers_on() {
    let dir = base("container-pattern");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let root = root.display().to_string();
    let args = ["facts", "--root", &root, "--output", "-"];
    let (_, flag) = run(&dir, "", &[&args[..], &["--container", "web"]].concat());
    let (_, config) = run(&dir, "collect: {container: [web]}\n", &args);
    let (_, none) = run(&dir, "", &args);
    assert!(flag.contains("Containers not checked"), "{flag}");
    assert!(config.contains("Containers not checked"), "{config}");
    assert!(!none.contains("Containers not checked"), "{none}");
}
