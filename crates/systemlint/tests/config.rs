// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use systemlint::config::{Config, ENV, Layer, PROJECT, SYSTEM, layers};
use systemlint::report::{Colour, Format};

fn write(name: &str, text: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("config")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn relative_directories_resolve_beside_the_file() {
    let path = write(
        "relative",
        "plugins:\n  directories: [plugins, /opt/systemlint/plugins]\ncollect:\n  directories: [collectors]\n",
    );
    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.plugins.directories,
        [
            path.parent().unwrap().join("plugins"),
            PathBuf::from("/opt/systemlint/plugins")
        ]
    );
    assert_eq!(
        config.collect.directories,
        [path.parent().unwrap().join("collectors")]
    );
}

#[test]
fn empty_file_is_the_default() {
    let config = Config::load(&write("empty", "{}\n")).unwrap();
    assert!(config.plugins.directories.is_empty());
}

#[test]
fn unknown_key_is_refused() {
    let error = Config::load(&write("unknown", "plugin:\n  directories: []\n")).unwrap_err();
    assert!(error.contains("not a valid configuration"), "{error}");
}

#[test]
fn missing_file_names_the_path() {
    let error = Config::load(Path::new("/nonexistent/systemlint.yaml")).unwrap_err();
    assert!(error.contains("/nonexistent/systemlint.yaml"), "{error}");
}

#[test]
fn the_check_section_resolves_directories_and_read_waivers() {
    let path = write(
        "check",
        "check:\n  directories: [rules]\n  tags: [fixture, '!experimental']\n  fail-on: warning\n  rulesets:\n    strict: {extends: [fixture], rules: {apt/https: error}}\n  waivers:\n    - {rule: apt/*, subject: /etc/apt/*, reason: mirror moves in December, until: 2026-12-31}\n",
    );
    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.check.directories,
        [path.parent().unwrap().join("rules")]
    );
    assert_eq!(
        (
            config.check.tags.len(),
            config.check.waivers[0].until.as_str()
        ),
        (2, "2026-12-31")
    );
    assert!(config.check.rulesets.contains_key("strict"));
}

#[test]
fn a_comply_section_is_refused() {
    let error =
        Config::load(&write("comply", "comply:\n  directories: [standards]\n")).unwrap_err();
    assert!(error.contains("comply"), "{error}");
}

#[test]
fn a_waiver_without_a_day_or_reason_and_a_bad_fail_on_are_refused() {
    for (name, text) in [
        (
            "no-day",
            "check:\n  waivers: [{rule: a, reason: r, until: soon}]\n",
        ),
        (
            "no-reason",
            "check:\n  waivers: [{rule: a, reason: ' ', until: 2026-12-31}]\n",
        ),
    ] {
        assert!(
            Config::load(&write(name, text))
                .unwrap_err()
                .contains("needs a reason and an until day"),
            "{name}"
        );
    }
    assert!(
        Config::load(&write("fail-on", "check:\n  fail-on: loud\n"))
            .unwrap_err()
            .contains("check.fail-on \"loud\"")
    );
}

#[test]
fn a_collect_timeout_needs_1_second() {
    assert!(
        Config::load(&write("timeout-0", "collect:\n  timeout: 0\n"))
            .unwrap_err()
            .contains("collect.timeout needs 1 second or more")
    );
    assert_eq!(
        Config::load(&write("timeout-1", "collect:\n  timeout: 1\n"))
            .unwrap()
            .collect
            .timeout,
        Some(1)
    );
    assert!(
        Config::load(&write("timeout-negative", "collect:\n  timeout: -1\n")).is_err(),
        "a negative timeout is not a number of seconds"
    );
}

#[test]
fn collect_jobs_run_1_to_64() {
    for refused in [0, 65] {
        assert!(
            Config::load(&write(
                &format!("jobs-{refused}"),
                &format!("collect:\n  jobs: {refused}\n")
            ))
            .unwrap_err()
            .contains("collect.jobs needs 1 to 64"),
            "{refused}"
        );
    }
    for taken in [1, 64] {
        assert_eq!(
            Config::load(&write(
                &format!("jobs-{taken}"),
                &format!("collect:\n  jobs: {taken}\n")
            ))
            .unwrap()
            .collect
            .jobs,
            Some(taken)
        );
    }
}

#[test]
fn an_inline_collector_is_checked_and_can_not_exec() {
    let inline = |read: &str| {
        format!(
            "collect:\n  collectors:\n    - id: nginx\n      read: {{{read}}}\n      parse: {{plugin: formats, op: stat}}\n      into: files.nginx\n"
        )
    };
    let config = Config::load(&write(
        "inline",
        &inline("stat: [/etc/nginx/nginx.conf], hash: [sha256]"),
    ))
    .unwrap();
    assert_eq!(
        (
            config.collect.collectors[0].read.stat.as_slice(),
            config.collect.collectors[0].inline
        ),
        (&["/etc/nginx/nginx.conf".to_owned()][..], true)
    );
    assert!(
        Config::load(&write(
            "inline-exec",
            &inline("stat: [/etc/x], exec: [/bin/true]")
        ))
        .unwrap_err()
        .contains("collect.collectors nginx: an inline collector can’t exec")
    );
    assert!(
        Config::load(&write(
            "inline-network",
            "collect:\n  network: true\n  collectors:\n    - id: web\n      network: true\n      read: {addr: [\"kiota.ch:443\"]}\n      parse: {plugin: formats, op: probes}\n      into: probes\n"
        ))
        .unwrap_err()
        .contains("collect.collectors web: an inline collector can’t exec or reach the network")
    );
    assert!(
        Config::load(&write("inline-relative", &inline("stat: [etc/x]")))
            .unwrap_err()
            .contains("collect.collectors nginx: read glob etc/x is not absolute")
    );
}

#[test]
fn a_hash_key_needs_16_characters() {
    assert!(
        Config::load(&write("key-15", "collect:\n  hash-key: fifteen-chars-x\n"))
            .unwrap_err()
            .contains("16 characters or more")
    );
    assert!(
        Config::load(&write(
            "key-15-wide",
            "collect:\n  hash-key: ñññññññññññññññ\n"
        ))
        .is_err(),
        "characters, not bytes"
    );
    assert_eq!(
        Config::load(&write("key-16", "collect:\n  hash-key: sixteen-chars-xx\n"))
            .unwrap()
            .collect
            .hash_key
            .as_deref(),
        Some("sixteen-chars-xx")
    );
}

#[test]
fn layers_run_system_user_project_environment_then_flag() {
    let vars = |n: &str| match n {
        "XDG_CONFIG_HOME" => Some("relative".to_owned()),
        "HOME" => Some("/home/u".to_owned()),
        "SYSTEMLINT_CONFIG" => Some("/ci/config.yaml".to_owned()),
        _ => None,
    };
    let found = layers(Some(Path::new("flag.yaml")), true, vars, Path::new("/repo"));
    let expected = [
        (SYSTEM, Layer::Optional),
        ("/home/u/.config/systemlint/config.yaml", Layer::Optional),
        ("/repo/.systemlint.yaml", Layer::Project),
        ("/ci/config.yaml", Layer::Required),
        ("flag.yaml", Layer::Required),
    ];
    assert_eq!(found, expected.map(|(p, r)| (PathBuf::from(p), r)));
    assert_eq!((ENV, PROJECT), ("SYSTEMLINT_CONFIG", ".systemlint.yaml"));
}

#[test]
fn an_empty_variable_and_no_home_add_no_layer() {
    let found = layers(
        None,
        true,
        |n| (n == "SYSTEMLINT_CONFIG").then(String::new),
        Path::new("/repo"),
    );
    assert_eq!(
        found,
        [
            (PathBuf::from(SYSTEM), Layer::Optional),
            (PathBuf::from("/repo/.systemlint.yaml"), Layer::Project)
        ]
    );
}

#[test]
fn a_higher_layer_replaces_a_lower_one_key_by_key() {
    let system = write(
        "layer-system",
        "collect:\n  timeout: 10\ncheck:\n  tags: [apt]\n  fail-on: warning\n",
    );
    let user = write(
        "layer-user",
        "plugins:\n  directories: [plugins]\ncheck:\n  format: sarif\n  color: never\n",
    );
    let project = write(
        "layer-project",
        "collect:\n  timeout: 20\ncheck:\n  tags: [sshd]\n",
    );
    let absent = system.with_file_name("absent.yaml");
    let config = Config::layered(&[
        (system, Layer::Optional),
        (user.clone(), Layer::Optional),
        (absent, Layer::Optional),
        (project, Layer::Required),
    ])
    .unwrap();
    assert_eq!(config.collect.timeout, Some(20));
    assert_eq!(
        (config.check.tags, config.check.fail_on.as_deref()),
        (vec!["sshd".to_owned()], Some("warning"))
    );
    assert_eq!(
        (config.check.format, config.check.color),
        (Some(Format::Sarif), Some(Colour::Never))
    );
    assert_eq!(
        config.plugins.directories,
        [user.parent().unwrap().join("plugins")]
    );
}

#[test]
fn no_layer_is_the_default_and_a_required_one_must_exist() {
    let config = Config::layered(&[(
        PathBuf::from("/nonexistent/systemlint.yaml"),
        Layer::Optional,
    )])
    .unwrap();
    assert_eq!((config.check.format, config.collect.timeout), (None, None));
    let error = Config::layered(&[(
        PathBuf::from("/nonexistent/systemlint.yaml"),
        Layer::Required,
    )])
    .unwrap_err();
    assert!(error.contains("/nonexistent/systemlint.yaml"), "{error}");
}

#[test]
fn an_invalid_layer_is_named_even_under_a_valid_one() {
    let bad = write("layer-bad", "check:\n  color: sometimes\n");
    let good = write("layer-good", "check:\n  color: always\n");
    let error =
        Config::layered(&[(bad.clone(), Layer::Optional), (good, Layer::Optional)]).unwrap_err();
    assert!(
        error.starts_with(&format!("{} is not a valid configuration", bad.display())),
        "{error}"
    );
}

#[test]
fn no_project_config_drops_only_the_project_layer() {
    let found = layers(None, false, |_| None, Path::new("/repo"));
    assert_eq!(found, [(PathBuf::from(SYSTEM), Layer::Optional)]);
}

#[test]
fn project_config_false_below_skips_the_project_file() {
    let user = write("project-off-user", "project-config: false\n");
    let project = write("project-off-project", "check:\n  tags: [sshd]\n");
    let config = Config::layered(&[
        (user.clone(), Layer::Optional),
        (project.clone(), Layer::Project),
    ])
    .unwrap();
    assert!(
        config.check.tags.is_empty(),
        "project-config: false skips the project layer"
    );
    let on = write("project-on-user", "project-config: true\n");
    let config = Config::layered(&[(on, Layer::Optional), (project, Layer::Project)]).unwrap();
    assert_eq!(config.check.tags, ["sshd"], "project-config: true reads it");
}

#[test]
fn project_config_in_the_project_or_a_required_layer_is_refused() {
    let set = write("project-key-misplaced", "project-config: false\n");
    for layer in [Layer::Project, Layer::Required] {
        let error = Config::layered(&[(set.clone(), layer)]).unwrap_err();
        assert!(error.contains("--no-project-config"), "{layer:?}: {error}");
    }
}
