// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::path::Path;

use serde_json::{Value, json};
use systemlint::judge::{
    Check, Outcome, Waiver, compile, describe, interpolate, level_of, lint, parse_path, pin, score,
};
use systemlint::rules::{Score, Severity, Spec};
use systemlint::version::{Scheme, compare_deb};

fn facts(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../fixtures/lint/facts/{name}.yaml"));
    systemlint::document::load(&path).unwrap()
}

fn spec(yaml: &str) -> Spec {
    systemlint::yaml::from_str(yaml).unwrap()
}

fn run(yaml: &str, document: &Value) -> Vec<Check> {
    lint(
        document,
        &[compile("test/rule", spec(yaml)).unwrap()],
        &[],
        "2026-11-11",
    )
}

fn outcomes(checks: &[Check]) -> Vec<(String, Outcome)> {
    checks
        .iter()
        .map(|c| (c.subject_text(), c.outcome))
        .collect()
}

#[test]
fn a_star_binds_one_subject_across_when_and_fact() {
    let checks = run(
        "fact: apt.sources.*.uri\nwhen: {apt.sources.*.enabled: true}\nexpect: {pattern: '^https://'}\n",
        &facts("root"),
    );
    let found = outcomes(&checks);
    assert_eq!(
        found,
        [
            ("/etc/apt/sources.list.d/old.sources".into(), Outcome::Skip),
            (
                "/etc/apt/sources.list.d/ubuntu.sources".into(),
                Outcome::Pass
            )
        ],
        "the disabled http source is skipped, not judged"
    );
    assert!(
        checks[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("enabled is false"),
        "{:?}",
        checks[0].reason
    );
}

#[test]
fn a_fail_names_its_subject_in_message_and_fix() {
    let mut document = facts("root");
    document["apt"]["sources"]["/etc/apt/sources.list.d/old.sources"]["enabled"] = json!(true);
    let checks = run(
        "fact: apt.sources.*.uri\nwhen: {apt.sources.*.enabled: true}\nexpect: {pattern: '^https://'}\nmessage: '{subject} fetches over {got}'\nfix: switch {subject} to https://\nseverity: warning\n",
        &document,
    );
    let fail = checks.iter().find(|c| c.outcome == Outcome::Fail).unwrap();
    assert_eq!(
        fail.message.as_deref(),
        Some("/etc/apt/sources.list.d/old.sources fetches over “http://old.example/debian”")
    );
    assert_eq!(
        fail.fix.as_deref(),
        Some("switch /etc/apt/sources.list.d/old.sources to https://")
    );
    assert_eq!(
        fail.text.as_deref(),
        Some("{subject} fetches over {got}"),
        "the template stays for translation"
    );
    assert_eq!(
        (fail.severity, fail.score),
        (Some(Severity::Warning), Some(5.0))
    );
}

#[test]
fn an_absent_fact_is_unknown_and_names_the_collector() {
    let unprivileged = facts("unprivileged");
    let checks = run(
        "fact: files./etc/shadow.world-readable\nexpect: {const: false}\n",
        &unprivileged,
    );
    assert_eq!(checks[0].outcome, Outcome::Unknown);
    assert_eq!(checks[0].collector.as_deref(), Some("shadow"));
    assert!(
        checks[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("collector shadow error: can’t stat /etc/shadow"),
        "{:?}",
        checks[0].reason
    );
    let missing = run(
        "fact: os.release.VERSION_CODENAME\nexpect: {const: resolute}\n",
        &unprivileged,
    );
    assert!(
        missing[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("absent from what collector os-release produced"),
        "{:?}",
        missing[0].reason
    );
    let orphan = run(
        "fact: sysctl.kernel.kptr_restrict\nexpect: {const: 2}\n",
        &unprivileged,
    );
    assert!(
        orphan[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("no collector produces it"),
        "{:?}",
        orphan[0].reason
    );
    let collection = run(
        "fact: units.*.active\nexpect: {const: true}\n",
        &unprivileged,
    );
    assert_eq!(
        outcomes(&collection),
        [(String::new(), Outcome::Unknown)],
        "an absent collection is one unknown, never zero checks"
    );
    let sibling = json!({"systemd": {"units": {}}, "collectors": {"systemd-state": {"status": "error", "into": "systemd.state", "reason": "x"}, "systemd-units": {"status": "ok", "into": "systemd.units"}}});
    let nested = run(
        "fact: systemd.state.*.active\nkeys: {const: ufw.service}\nexpect: {const: active}\n",
        &sibling,
    );
    assert_eq!(
        outcomes(&nested),
        [(String::new(), Outcome::Unknown)],
        "a collection absent under a parent its sibling filled is still one unknown"
    );
    assert_eq!(nested[0].collector.as_deref(), Some("systemd-state"));
    let empty = run(
        "fact: systemd.units.*.active\nexpect: {const: active}\n",
        &sibling,
    );
    assert_eq!(
        outcomes(&empty),
        [],
        "a present but empty collection has no check"
    );
}

#[test]
fn an_empty_collection_gives_no_checks() {
    let mut document = facts("root");
    document["apt"]["sources"] = json!({});
    assert!(
        run(
            "fact: apt.sources.*.uri\nexpect: {pattern: '^https://'}\n",
            &document
        )
        .is_empty()
    );
}

#[test]
fn a_failed_collector_under_a_star_is_one_unknown_subject_beside_the_present_ones() {
    let document = json!({
        "files": {"shadow": {"/etc/shadow": {"uid": 0}}, "cron": {}},
        "collectors": {
            "files-shadow": {"status": "ok", "into": "files.shadow"},
            "files-cron": {"status": "ok", "into": "files.cron"},
            "files-sudoers": {"status": "error", "reason": "can’t list /etc/sudoers.d: Permission denied", "into": "files.sudoers"},
        },
    });
    let checks = run("fact: files.*.*.uid\nexpect: {const: 0}\n", &document);
    assert_eq!(
        outcomes(&checks),
        [
            ("shadow, /etc/shadow".into(), Outcome::Pass),
            ("sudoers".into(), Outcome::Unknown)
        ],
        "an empty group gives no check, a failed one never vanishes"
    );
    assert_eq!(checks[1].collector.as_deref(), Some("files-sudoers"));
    assert!(
        checks[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("collector files-sudoers error: can’t list /etc/sudoers.d"),
        "{:?}",
        checks[1].reason
    );
}

#[test]
fn when_is_kleene_logic_false_beats_unknown_in_and_true_beats_it_in_or() {
    let document = facts("root");
    let and = run(
        "fact: os.release.VERSION_ID\nwhen: {os.release.ID: debian, os.release.MISSING: x}\nexpect: {const: '26.04'}\n",
        &document,
    );
    assert_eq!(and[0].outcome, Outcome::Skip);
    let and_unknown = run(
        "fact: os.release.VERSION_ID\nwhen: {os.release.ID: ubuntu, os.release.MISSING: x}\nexpect: {const: '26.04'}\n",
        &document,
    );
    assert_eq!(and_unknown[0].outcome, Outcome::Unknown);
    let or = run(
        "fact: os.release.VERSION_ID\nwhen: [{os.release.MISSING: x}, {os.release.ID: ubuntu}]\nexpect: {const: '26.04'}\n",
        &document,
    );
    assert_eq!(or[0].outcome, Outcome::Pass);
    let or_unknown = run(
        "fact: os.release.VERSION_ID\nwhen: [{os.release.MISSING: x}, {os.release.ID: debian}]\nexpect: {const: '26.04'}\n",
        &document,
    );
    assert_eq!(or_unknown[0].outcome, Outcome::Unknown);
    let schema = run(
        "fact: os.release.VERSION_ID\nwhen: {os.release.ID: {enum: [ubuntu, debian]}}\nexpect: {const: '24.04'}\n",
        &document,
    );
    assert_eq!(schema[0].outcome, Outcome::Fail);
}

#[test]
fn x_version_orders_debian_versions() {
    let document = facts("root");
    assert_eq!(run("fact: packages.openssh-server.version\nexpect: {x-version: {scheme: deb, min: '1:9.6p1-3ubuntu13.3'}}\n", &document)[0].outcome, Outcome::Pass);
    let below = run(
        "fact: packages.openssh-server.version\nexpect: {x-version: {scheme: deb, min: '1:9.6p1', below: '1:9.6p1-3ubuntu13.4'}}\n",
        &document,
    );
    assert_eq!(below[0].outcome, Outcome::Fail);
    assert!(
        below[0]
            .message
            .as_deref()
            .unwrap()
            .contains("below 1:9.6p1-3ubuntu13.4"),
        "{:?}",
        below[0].message
    );
    assert!(
        compile("x", spec("fact: a\nexpect: {x-version: {scheme: npm}}\n"))
            .err()
            .unwrap()
            .contains("scheme npm is unknown; the known ones are deb, semver, rpm, apk, pacman")
    );
    assert!(
        compile(
            "x",
            spec("fact: a\nexpect: {x-version: {scheme: deb, min: 'abc'}}\n")
        )
        .err()
        .unwrap()
        .contains("not a Debian version")
    );
}

#[test]
fn deb_ordering_matches_dpkg() {
    for (a, b, order) in [
        ("1.0", "1.0", Ordering::Equal),
        ("1.0~rc1", "1.0", Ordering::Less),
        ("1.0", "1.0+b1", Ordering::Less),
        ("1:1.0", "2.0", Ordering::Greater),
        ("1.0-1", "1.0-1ubuntu1", Ordering::Less),
        ("1.10", "1.9", Ordering::Greater),
        ("1.0a", "1.0", Ordering::Greater),
        ("1.001", "1.1", Ordering::Equal),
        (
            "1:9.6p1-3ubuntu13.3",
            "1:9.6p1-3ubuntu13.10",
            Ordering::Less,
        ),
        ("0:1.0", "1.0", Ordering::Equal),
    ] {
        assert_eq!(compare_deb(a, b), Ok(order), "{a} vs {b}");
    }
}

fn orders(scheme: Scheme, cases: &[(&str, &str, Ordering)]) {
    for (a, b, order) in cases {
        assert_eq!(
            scheme.compare(a, b),
            Ok(*order),
            "{} {a} vs {b}",
            scheme.name()
        );
        assert_eq!(
            scheme.compare(b, a),
            Ok(order.reverse()),
            "{} {b} vs {a}",
            scheme.name()
        );
    }
}

fn refuses(scheme: Scheme, versions: &[&str]) {
    for version in versions {
        assert!(
            scheme
                .compare(version, version)
                .unwrap_err()
                .contains(scheme.noun()),
            "{} accepted {version:?}",
            scheme.name()
        );
    }
}

#[test]
fn semver_ordering_follows_the_spec_precedence() {
    let chain = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.9.0",
        "1.10.0",
        "2.0.0",
    ];
    orders(
        Scheme::Semver,
        &chain
            .windows(2)
            .map(|w| (w[0], w[1], Ordering::Less))
            .collect::<Vec<_>>(),
    );
    orders(
        Scheme::Semver,
        &[
            ("1.0.0+build.1", "1.0.0+build.2", Ordering::Equal),
            ("1.0.0-1", "1.0.0-a", Ordering::Less),
            ("99999999999999999999999.0.0", "2.0.0", Ordering::Greater),
        ],
    );
    refuses(
        Scheme::Semver,
        &[
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-01",
            "v1.0.0",
            "1.0.0-",
            "1.0.0+",
            "1.0.0-a..b",
            "1.0.0-a_b",
            "",
        ],
    );
}

#[test]
fn rpm_ordering_matches_rpmvercmp() {
    use Ordering::{Equal, Greater, Less};
    orders(
        Scheme::Rpm,
        &[
            ("1.0", "1.0", Equal),
            ("2.0.1a", "2.0.1", Greater),
            ("5.5p10", "5.5p2", Greater),
            ("10xyz", "10.1xyz", Less),
            ("1b.fc17", "1.fc17", Less),
            ("2_0", "2.0", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0^", "1.0", Greater),
            ("1.0^git1", "1.01", Less),
            ("1.0^git1~pre", "1.0^git1", Less),
            ("1.0~rc1^git1", "1.0~rc1", Greater),
        ],
    );
    orders(
        Scheme::Rpm,
        &[
            ("1:1.0", "2.0", Greater),
            ("0:1.0", "1.0", Equal),
            (":1.0", "1.0", Equal),
            ("1.0-1", "1.0-2", Less),
            ("1.0", "1.0-1", Less),
            ("1.0-1.el9", "1.0-1.el10", Less),
        ],
    );
    refuses(Scheme::Rpm, &["", "1.0 -1", "1.0\n"]);
}

#[test]
fn pacman_ordering_matches_alpm_pkg_vercmp() {
    use Ordering::{Equal, Greater, Less};
    orders(
        Scheme::Pacman,
        &[
            ("1.5.1", "1.5", Greater),
            ("1.5.b", "1.5", Greater),
            ("1.5a", "1.5", Less),
            ("1.5rc1", "1.5", Less),
            ("1..0", "1.0", Greater),
            ("1.0~rc1", "1.0", Greater),
            ("1.0+1", "1.0.1", Equal),
            ("1.001", "1.1", Equal),
        ],
    );
    orders(
        Scheme::Pacman,
        &[
            ("1:1.0", "2.0", Greater),
            ("1.0-1", "1.0", Equal),
            ("1.0-1", "1.0-2", Less),
            ("1.0-10", "1.0-9", Greater),
        ],
    );
    refuses(Scheme::Pacman, &["", "1.0 1"]);
}

#[test]
fn apk_ordering_matches_apk_tools() {
    use Ordering::{Equal, Greater, Less};
    let chain = [
        "1.0_alpha",
        "1.0_alpha2",
        "1.0_beta",
        "1.0_pre",
        "1.0_rc1",
        "1.0",
        "1.0-r1",
        "1.0_cvs",
        "1.0_svn",
        "1.0_git",
        "1.0_hg",
        "1.0_p1",
        "1.0a",
        "1.0.1",
    ];
    orders(
        Scheme::Apk,
        &chain
            .windows(2)
            .map(|w| (w[0], w[1], Less))
            .collect::<Vec<_>>(),
    );
    orders(
        Scheme::Apk,
        &[
            ("1.01", "1.1", Less),
            ("01.0", "1.0", Equal),
            ("1.0~ab12", "1.0", Greater),
            ("1.0~ab12-r1", "1.0~ab12", Greater),
            ("1.10", "1.9", Greater),
        ],
    );
    refuses(
        Scheme::Apk,
        &[
            "",
            "a1",
            "1.0-1",
            "1.0_foo",
            "1.0b2",
            "1.0~",
            "1.0~AB",
            "1.0-r",
            "1.0-r1-r2",
            "1.0_p1a",
        ],
    );
}

#[test]
fn x_version_compares_in_the_named_scheme() {
    let document = json!({"meta": {}, "collectors": {}, "pkg": {"version": "3.0.15-r1"}});
    assert_eq!(run("fact: pkg.version\nexpect: {x-version: {scheme: apk, min: '3.0.15_rc1', below: '3.0.15-r2'}}\n", &document)[0].outcome, Outcome::Pass);
    let below = run(
        "fact: pkg.version\nexpect: {x-version: {scheme: apk, min: '3.0.15-r2'}}\n",
        &document,
    );
    assert_eq!(below[0].outcome, Outcome::Fail);
    assert!(
        below[0]
            .message
            .as_deref()
            .unwrap()
            .contains("is not an Alpine version at least 3.0.15-r2"),
        "{:?}",
        below[0].message
    );
    assert!(
        compile(
            "x",
            spec("fact: a\nexpect: {x-version: {scheme: semver, min: '1.0'}}\n")
        )
        .err()
        .unwrap()
        .contains("not a SemVer version")
    );
    assert!(
        compile("x", spec("fact: a\nexpect: {x-version: {min: '1.0'}}\n"))
            .err()
            .unwrap()
            .contains("needs a scheme: deb, semver, rpm, apk, pacman")
    );
}

#[test]
fn keys_leave_out_subjects_by_the_key_of_the_last_star() {
    let document = json!({"meta": {}, "collectors": {}, "files": {"ssh": {"id_ed25519": {"mode": "0644"}, "id_ed25519.pub": {"mode": "0644"}, "known_hosts": {"mode": "0644"}}}});
    let rule = "fact: files.ssh.*.mode\nkeys: {not: {pattern: '\\.pub$|^known_hosts$'}}\nwhen: {files.ssh.*.mode: {type: string}}\nexpect: {const: '0600'}\nmessage: '{subject} is {got}'\n";
    let checks = run(rule, &document);
    assert_eq!(
        outcomes(&checks),
        [("id_ed25519".into(), Outcome::Fail)],
        "filtered keys are no subject at all, not skip"
    );
    assert!(
        checks[0]
            .message
            .as_deref()
            .unwrap()
            .starts_with("id_ed25519 is"),
        "{:?}",
        checks[0].message
    );
    assert!(
        run(
            "fact: files.ssh.*.mode\nkeys: {const: nothing}\nexpect: {const: '0600'}\n",
            &document
        )
        .is_empty(),
        "a key that matches nothing binds no subject"
    );
    let nested = json!({"meta": {}, "collectors": {}, "users": {"root": {}, "ann": {"keys": {"a.pub": 1, "b": 1}}}});
    assert_eq!(
        outcomes(&run(
            "fact: users.*.keys.*\nkeys: {not: {pattern: '\\.pub$'}}\nexpect: {const: 2}\n",
            &nested
        )),
        [
            ("ann, b".into(), Outcome::Fail),
            ("root".into(), Outcome::Unknown)
        ],
        "a binding cut short by an absent fact stays"
    );
    assert!(
        compile("x", spec("fact: a.b\nkeys: {pattern: x}\nexpect: {}\n"))
            .err()
            .unwrap()
            .contains("keys filters the key a * binds, and fact a.b has no *")
    );
    assert!(
        compile("x", spec("fact: a.*\nkeys: {type: nope}\nexpect: {}\n"))
            .err()
            .unwrap()
            .contains("rule x: keys ")
    );
}

#[test]
fn paths_are_dotted_or_json_pointers() {
    let document = json!({"meta": {}, "collectors": {}, "files": {"/etc/ssh/sshd_config.d/a.conf": {"mode": "0644"}}});
    let pointer = run(
        "fact: /files/~1etc~1ssh~1sshd_config.d~1a.conf/mode\nexpect: {const: '0600'}\n",
        &document,
    );
    assert_eq!(pointer[0].outcome, Outcome::Fail);
    assert!(parse_path("a..b").is_err() && parse_path("").is_err());
    assert!(
        compile("x", spec("fact: a.b\nwhen: {a.*.c: 1}\nexpect: {}\n"))
            .err()
            .unwrap()
            .contains("more * than fact")
    );
}

#[test]
fn score_bands_follow_spiderlint_at_every_edge() {
    for (value, level) in [
        (0.0, Severity::Hint),
        (0.9, Severity::Hint),
        (1.0, Severity::Info),
        (3.2, Severity::Info),
        (3.3, Severity::Warning),
        (6.5, Severity::Warning),
        (6.6, Severity::Error),
        (9.9, Severity::Error),
        (12.0, Severity::Error),
    ] {
        assert_eq!(level_of(value), level, "{value}");
    }
    assert_eq!(pin(Severity::Warning, 9.0), 6.5);
    assert_eq!(pin(Severity::Error, 1.0), 6.6);
    let curve = [(0.0, 9.0), (30.0, 3.0)];
    assert_eq!(
        [
            interpolate(&curve, -5.0),
            interpolate(&curve, 15.0),
            interpolate(&curve, 99.0)
        ],
        [9.0, 6.0, 3.0]
    );
}

#[test]
fn a_curve_crosses_levels_unless_a_level_pins_it() {
    let base = Spec {
        score: Some(Score::Curve(vec![(0.0, 9.0), (30.0, 3.0)])),
        severity: Some(Severity::Warning),
        ..Spec::default()
    };
    assert_eq!(
        score(&base, Some(&json!(3))),
        8.4,
        "a definition’s curve crosses into error"
    );
    assert_eq!(
        score(
            &Spec {
                pinned: true,
                ..base.clone()
            },
            Some(&json!(3))
        ),
        6.5,
        "an override’s level pins it"
    );
    assert_eq!(
        score(
            &Spec {
                score: Some(Score::Fixed(7.4)),
                severity: None,
                ..Spec::default()
            },
            None
        ),
        7.4
    );
    assert_eq!(score(&Spec::default(), None), 5.0, "no level is a warning");
}

#[test]
fn a_constant_message_keeps_the_value_out_and_got_quotes_it() {
    let document = facts("root");
    let constant = run(
        "fact: os.release.VERSION_ID\nexpect: {const: '24.04'}\nmessage: release is old\n",
        &document,
    );
    assert_eq!(constant[0].message.as_deref(), Some("release is old"));
    assert_eq!(constant[0].value, Some(json!("26.04")));
    let got = run(
        "fact: os.release.VERSION_ID\nexpect: {const: '24.04'}\nmessage: got {got}\n",
        &document,
    );
    assert_eq!(got[0].message.as_deref(), Some("got “26.04”"));
    let plain = run(
        "fact: os.release.VERSION_ID\nexpect: {const: '24.04'}\n",
        &document,
    );
    assert!(
        plain[0]
            .message
            .as_deref()
            .unwrap()
            .starts_with("os.release.VERSION_ID: "),
        "{:?}",
        plain[0].message
    );
}

#[test]
fn describe_elides_long_strings_and_lists_words() {
    let long = "a".repeat(150) + &"b".repeat(150);
    let shown = describe(Some(&json!(long)));
    assert_eq!(shown.chars().count(), 202);
    assert!(shown.starts_with("“aaa") && shown.ends_with("bbb”") && shown.contains('…'));
    assert_eq!(describe(Some(&json!(["a", 2]))), "“a”, 2");
    assert_eq!(describe(Some(&json!([]))), "none");
    assert_eq!(describe(None), "none");
    assert_eq!(describe(Some(&json!([{}, {}]))), "2 items");
}

#[test]
fn a_waiver_holds_through_its_day_then_expires_into_a_finding() {
    let document = facts("root");
    let rule = compile(
        "os/old",
        spec("fact: os.release.VERSION_ID\nexpect: {const: '24.04'}\nseverity: error\n"),
    )
    .unwrap();
    let waiver = Waiver {
        rule: "os/*".into(),
        subject: None,
        reason: "upgrade booked".into(),
        until: "2026-11-30".into(),
    };
    let held = lint(
        &document,
        std::slice::from_ref(&rule),
        std::slice::from_ref(&waiver),
        "2026-11-30",
    );
    assert!(held[0].waiver.as_ref().unwrap().active && !held[0].is_failing());
    let expired = lint(
        &document,
        std::slice::from_ref(&rule),
        std::slice::from_ref(&waiver),
        "2026-12-01",
    );
    assert!(!expired[0].waiver.as_ref().unwrap().active && expired[0].is_failing());
    let other = Waiver {
        subject: Some("/etc/*".into()),
        ..waiver
    };
    assert!(
        lint(&document, &[rule], &[other], "2026-11-01")[0]
            .waiver
            .is_none(),
        "a subject glob misses a rule with no subject"
    );
}

#[test]
fn suggest_fills_the_fact_bound_to_the_same_subject_or_its_fallback() {
    let rule = "fact: s.*.old\nexpect: {maxItems: 0}\nsuggest: {fact: s.*.new, otherwise: the host value}\nfix: use {suggested}\n";
    let document = json!({"s": {"a": {"old": ["x"], "new": ["y"]}, "b": {"old": ["x"], "new": []}, "c": {"old": ["x"]}}});
    let fixes: Vec<_> = run(rule, &document)
        .into_iter()
        .map(|c| (c.subject_text(), c.fix.unwrap()))
        .collect();
    assert_eq!(
        fixes,
        [
            ("a".to_owned(), "use “y”".to_owned()),
            ("b".to_owned(), "use the host value".to_owned()),
            ("c".to_owned(), "use the host value".to_owned())
        ]
    );
    let error = compile(
        "test/rule",
        spec("fact: s.*.old\nexpect: {maxItems: 0}\nsuggest: {fact: s.*.*.new, otherwise: x}\n"),
    )
    .err()
    .unwrap();
    assert!(
        error.contains("suggest has 2 * where fact s.*.old has 1"),
        "{error}"
    );
}

fn in_ruleset(yaml: &str, document: &Value) -> Result<Vec<Check>, String> {
    let library = systemlint::rules::Library::new(std::collections::BTreeMap::from([(
        "deb".to_owned(),
        systemlint::yaml::from_str(yaml).unwrap(),
    )]))?;
    let rules = library
        .select(&["deb".to_owned()])?
        .into_iter()
        .map(|(id, spec)| compile(&id, spec))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(lint(document, &rules, &[], "2026-11-11"))
}

#[test]
fn a_ruleset_that_does_not_apply_answers_one_not_applicable_check_per_rule() {
    let rule = "rules:\n  apt/https: {fact: apt.sources.*.uri, expect: {pattern: '^https://'}}\n";
    let checks = in_ruleset(
        &format!("when: {{os.release.ID: debian}}\n{rule}"),
        &facts("root"),
    )
    .unwrap();
    assert_eq!(
        outcomes(&checks),
        [(String::new(), Outcome::NotApplicable)],
        "two sources, one answer"
    );
    assert_eq!(
        checks[0].reason.as_deref(),
        Some("ruleset deb: when os.release.ID is “ubuntu”")
    );
    assert_eq!(
        serde_json::to_value(checks[0].outcome).unwrap(),
        "not-applicable"
    );
    let applies = in_ruleset(
        &format!("when: {{os.release.ID: {{const: ubuntu}}}}\n{rule}"),
        &facts("root"),
    )
    .unwrap();
    assert_eq!(
        applies.len(),
        2,
        "a ruleset that applies judges every subject: {applies:?}"
    );
    let absent = in_ruleset(
        &format!("when: {{os.release.MISSING: x}}\n{rule}"),
        &facts("root"),
    )
    .unwrap();
    assert_eq!(
        outcomes(&absent),
        [(String::new(), Outcome::Unknown)],
        "an absent applicability fact is unknown, never not applicable"
    );
    assert!(
        absent[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("ruleset deb: when os.release.MISSING is absent"),
        "{:?}",
        absent[0].reason
    );
    let star = in_ruleset(
        &format!("when: {{apt.sources.*.enabled: true}}\n{rule}"),
        &facts("root"),
    )
    .unwrap_err();
    assert!(
        star.contains("ruleset deb: when apt.sources.*.enabled has more * than a ruleset"),
        "{star}"
    );
}

#[test]
fn a_manual_rule_answers_manual_once_unless_its_ruleset_does_not_apply() {
    let rule = "rules:\n  review/backups: {manual: true, title: Review the backup policy, rationale: read /etc/backup.policy}\n";
    let checks = in_ruleset(rule, &facts("root")).unwrap();
    assert_eq!(outcomes(&checks), [(String::new(), Outcome::Manual)]);
    assert_eq!(
        (
            checks[0].fact.as_str(),
            checks[0].rationale.as_deref(),
            checks[0].score
        ),
        ("", Some("read /etc/backup.policy"), None)
    );
    let elsewhere = in_ruleset(
        &format!("when: {{os.release.ID: debian}}\n{rule}"),
        &facts("root"),
    )
    .unwrap();
    assert_eq!(
        outcomes(&elsewhere),
        [(String::new(), Outcome::NotApplicable)]
    );
}

#[test]
fn several_facts_combine_in_kleene_logic() {
    let document = json!({"a": 1, "b": 2});
    let (p, f, u) = (
        "{fact: a, expect: {const: 1}}",
        "{fact: b, expect: {const: 1}}",
        "{fact: missing, expect: {}}",
    );
    for (how, members, expected) in [
        ("all", [p, p], Outcome::Pass),
        ("all", [p, f], Outcome::Fail),
        ("all", [p, u], Outcome::Unknown),
        ("all", [u, f], Outcome::Fail),
        ("any", [f, f], Outcome::Fail),
        ("any", [f, p], Outcome::Pass),
        ("any", [f, u], Outcome::Unknown),
        ("any", [u, p], Outcome::Pass),
        ("none", [f, f], Outcome::Pass),
        ("none", [f, p], Outcome::Fail),
        ("none", [f, u], Outcome::Unknown),
        ("none", [u, p], Outcome::Fail),
    ] {
        let checks = run(
            &format!("facts: {{{how}: [{}, {}]}}\n", members[0], members[1]),
            &document,
        );
        assert_eq!(
            outcomes(&checks),
            [(String::new(), expected)],
            "{how} {members:?}"
        );
    }
}

#[test]
fn several_facts_share_the_subject_the_first_fact_binds() {
    let document = json!({"sshd": {"hosts": {"h1": {"root": "yes"}, "h2": {"root": "yes"}}}, "pkg": {"h1": {"installed": true}, "h2": {"installed": false}}});
    let yaml = "facts: {any: [{fact: sshd.hosts.*.root, expect: {const: 'no'}}, {fact: pkg.*.installed, expect: {const: false}}]}\nmessage: '{subject}: {fact} is {got}'\n";
    let checks = run(yaml, &document);
    assert_eq!(
        outcomes(&checks),
        [("h1".into(), Outcome::Fail), ("h2".into(), Outcome::Pass)]
    );
    assert_eq!(
        (checks[0].fact.as_str(), checks[0].message.as_deref()),
        (
            "sshd.hosts.h1.root",
            Some("h1: sshd.hosts.h1.root is “yes”")
        ),
        "the first failing fact reports"
    );
    let none = run(
        "facts: {none: [{fact: b, expect: {const: 1}}, {fact: a, expect: {const: 1}}]}\n",
        &json!({"a": 1, "b": 2}),
    );
    assert_eq!(
        (none[0].fact.as_str(), none[0].message.as_deref()),
        (
            "a",
            Some("a: satisfies its expect, which none of the facts may")
        ),
        "none reports the fact that holds"
    );
}

#[test]
fn several_facts_refuse_an_empty_list_a_bad_schema_and_an_unbound_star() {
    for (yaml, wanted) in [
        ("facts: {all: []}\n", "facts lists no fact"),
        (
            "facts: {any: [{fact: a, expect: {type: 7}}]}\n",
            "facts a: expect",
        ),
        (
            "facts: {all: [{fact: a.*, expect: {}}, {fact: b.*.*, expect: {}}]}\n",
            "facts b.*.* has more * than the first fact a.*",
        ),
    ] {
        let error = compile("test/rule", spec(yaml)).err().unwrap_or_default();
        assert!(error.contains(wanted), "{yaml}: {error}");
    }
}

#[test]
fn an_absent_first_collection_is_one_unknown_fact_the_others_can_still_decide() {
    let rule = |how: &str| {
        format!(
            "facts: {{{how}: [{{fact: sshd.contexts.*.permitrootlogin, expect: {{const: 'no'}}}}, {{fact: apt.installed, expect: {{not: {{required: [openssh-server]}}}}}}, {{fact: x.*.y, expect: {{}}}}]}}\n"
        )
    };
    let without = json!({"apt": {"installed": {"bash": {}}}});
    let with = json!({"apt": {"installed": {"openssh-server": {}}}});
    assert_eq!(
        outcomes(&run(&rule("any"), &without)),
        [(String::new(), Outcome::Pass)],
        "sshd is not installed"
    );
    assert_eq!(
        outcomes(&run(&rule("any"), &with)),
        [(String::new(), Outcome::Unknown)],
        "installed, and its config unread"
    );
    assert_eq!(
        outcomes(&run(&rule("all"), &with)),
        [(String::new(), Outcome::Fail)],
        "installed fails all whatever the config says"
    );
    assert_eq!(
        outcomes(&run(&rule("all"), &without)),
        [(String::new(), Outcome::Unknown)],
        "a starred fact left out never passes"
    );
}
