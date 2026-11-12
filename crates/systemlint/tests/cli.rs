// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn base(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the core with an empty config and the C locale, returning the exit code and stderr.
fn run(dir: &Path, config: &str, args: &[&str]) -> (i32, String) {
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_systemlint")).arg("--config").arg(&path).args(args).env("LC_ALL", "C").output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn facts(dir: &Path) -> String {
    let path = dir.join("facts.yaml");
    std::fs::write(&path, format!("meta: {{schema: {}}}\n", systemlint::collect::SCHEMA)).unwrap();
    path.display().to_string()
}

#[test]
fn a_usage_error_exits_2() {
    let (code, _) = run(&base("usage"), "", &["lint", "--bogus"]);
    assert_eq!(code, 2);
}

#[test]
fn a_missing_config_exits_5_with_the_fix() {
    let dir = base("config");
    let missing = dir.join("absent.yaml");
    let out = Command::new(env!("CARGO_BIN_EXE_systemlint")).arg("--config").arg(&missing).args(["plugin", "list"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("drop --config to use the defaults"), "{stderr}");
}

#[test]
fn an_invalid_config_exits_5() {
    let (code, stderr) = run(&base("invalid"), "nonsense: 1\n", &["plugin", "list"]);
    assert_eq!(code, 5, "{stderr}");
}

#[test]
fn a_refused_ruleset_directory_exits_5_naming_chmod() {
    let dir = base("refused");
    let rules = dir.join("rules");
    std::fs::create_dir(&rules).unwrap();
    std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o777)).unwrap();
    let facts = facts(&dir);
    let (code, stderr) = run(&dir, &format!("lint: {{directories: [{}]}}\n", rules.display()), &["lint", &facts]);
    assert_eq!(code, 5, "{stderr}");
    assert!(stderr.contains("chmod go-w"), "{stderr}");
}

#[test]
fn a_missing_facts_document_exits_6_naming_facts_output() {
    let dir = base("input");
    let absent = dir.join("absent.yaml").display().to_string();
    let (code, stderr) = run(&dir, "", &["lint", &absent]);
    assert_eq!(code, 6, "{stderr}");
    assert!(stderr.contains(&format!("Run systemlint facts --output {absent} first")), "{stderr}");
}

#[test]
fn a_document_of_another_schema_exits_6() {
    let dir = base("schema");
    let path = dir.join("facts.yaml");
    std::fs::write(&path, "meta: {schema: 0}\n").unwrap();
    let (code, stderr) = run(&dir, "", &["lint", &path.display().to_string()]);
    assert_eq!(code, 6, "{stderr}");
}

#[test]
fn a_missing_root_exits_6() {
    let dir = base("root");
    let (code, stderr) = run(&dir, "", &["--quiet", "facts", "--root", &dir.join("absent").display().to_string()]);
    assert_eq!(code, 6, "{stderr}");
    assert!(stderr.contains("it does not exist"), "{stderr}");
}

#[test]
fn an_output_in_a_missing_directory_exits_7_naming_mkdir() {
    let dir = base("output");
    let facts = facts(&dir);
    let missing = dir.join("absent");
    let (code, stderr) = run(&dir, "", &["--quiet", "lint", "--output", &missing.join("report.txt").display().to_string(), &facts]);
    assert_eq!(code, 7, "{stderr}");
    assert!(stderr.contains(&format!("Run mkdir -p {}", missing.display())), "{stderr}");
}

#[test]
fn a_save_in_a_missing_directory_exits_7() {
    let dir = base("save");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let save = dir.join("absent/facts.yaml").display().to_string();
    let (code, stderr) = run(&dir, "", &["--quiet", "facts", "--root", &root.display().to_string(), "--output", &save]);
    assert_eq!(code, 7, "{stderr}");
}

#[test]
fn a_save_says_what_it_wrote_and_how_to_lint_it_unless_quiet() {
    let dir = base("saved");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let save = dir.join("facts.yaml").display().to_string();
    let (code, stderr) = run(&dir, "", &["facts", "--root", &root.display().to_string(), "--output", &save]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains(&format!("Saved facts from 0 collectors (0 errors) to {save}. Lint them with: systemlint lint {save}")), "{stderr}");
    let (_, quiet) = run(&dir, "", &["--quiet", "facts", "--root", &root.display().to_string(), "--output", &save]);
    assert!(!quiet.contains("Saved"), "{quiet}");
}

#[test]
fn facts_format_beats_the_output_extension() {
    let dir = base("format");
    let root = dir.join("root");
    std::fs::create_dir(&root).unwrap();
    let (json, yaml) = (dir.join("facts.json"), dir.join("facts.yaml"));
    let written = |path: &std::path::Path, args: &[&str]| {
        let mut all = vec!["--quiet", "facts", "--root", root.to_str().unwrap(), "-o", path.to_str().unwrap()];
        all.extend_from_slice(args);
        assert_eq!(run(&dir, "", &all).0, 0);
        std::fs::read_to_string(path).unwrap()
    };
    assert!(written(&json, &[]).starts_with('{'), "a .json name writes JSON");
    assert!(!written(&yaml, &[]).starts_with('{'), "any other name writes YAML");
    assert!(!written(&json, &["--format", "yaml"]).starts_with('{'), "--format yaml beats .json");
    assert!(written(&yaml, &["--format", "json"]).starts_with('{'), "--format json beats .yaml");
}

#[test]
fn an_output_counts_its_findings_one_in_the_singular() {
    let dir = base("wrote");
    let path = dir.join("facts.yaml");
    std::fs::write(&path, format!("meta: {{schema: {}}}\nx: 1\n", systemlint::collect::SCHEMA)).unwrap();
    let report = dir.join("report.sarif").display().to_string();
    let config = "lint:\n  rulesets:\n    t: {rules: {t/x: {fact: x, expect: {const: 2}, severity: error}}}\n";
    let (code, stderr) = run(&dir, config, &["lint", "--format", "sarif", "--output", &report, &path.display().to_string()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains(&format!("Wrote 1 finding to {report}.")), "{stderr}");
    let (_, quiet) = run(&dir, config, &["--quiet", "lint", "--output", &report, &path.display().to_string()]);
    assert!(!quiet.contains("Wrote"), "{quiet}");
}

#[test]
fn a_closed_stdout_ends_the_run_on_sigpipe_with_no_message() {
    use std::os::unix::process::ExitStatusExt;
    let dir = base("sigpipe");
    let path = dir.join("config.yaml");
    std::fs::write(&path, "").unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_systemlint")).arg("--config").arg(&path).args(["plugin", "list", "--format", "json"]).stdout(writer).stderr(std::process::Stdio::piped()).output().unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{:?}", out.status);
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
}
