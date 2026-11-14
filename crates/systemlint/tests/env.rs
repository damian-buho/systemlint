// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use systemlint::collect::{HashKey, Options, hash, inputs};
use systemlint::collector::Collector;
use systemlint::judge::{Check, Outcome, compile, lint};
use systemlint::rules::Library;
use systemlint::source::Root;
use systemlint_protocol::{PROTOCOL, Request};

const COLLECTORS: [&str; 6] = [
    "env-files",
    "env-defaults",
    "env-units",
    "env-processes",
    "env-containers",
    "env-image",
];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn image_config() -> PathBuf {
    repository()
        .join("fixtures/image-config.json")
        .canonicalize()
        .unwrap()
}

// Every env collector read from the fixture root, processes as if live, parsed in-process and hashed as the core does.
fn document() -> Value {
    let key = HashKey::configured("a fixture hash key");
    let (mut groups, mut outcomes) = (Map::new(), Map::new());
    for id in COLLECTORS {
        let c = Collector::parse(
            &std::fs::read_to_string(repository().join(format!("collectors/{id}.yaml"))).unwrap(),
        )
        .unwrap();
        let options = Options {
            privileged: true,
            root: Root::open(&repository().join("fixtures/services")).unwrap(),
            live: c.live,
            now: UNIX_EPOCH + Duration::from_secs(1_794_398_400),
            timeout: Duration::from_secs(60),
            hash_key: key.clone(),
            image_config: Some(image_config()),
            jobs: 1,
            network: None,
            containers: false,
        };
        let request = Request {
            protocol: PROTOCOL,
            op: c.parse.op.clone(),
            root: "/".to_owned(),
            now: None,
            inputs: inputs(&c, &options).unwrap(),
            facts: BTreeMap::new(),
        };
        let reply = systemlint_env::op(request).unwrap();
        assert!(
            reply.diagnostics.is_empty(),
            "{id}: {:?}",
            reply.diagnostics
        );
        let mut facts = Value::Object(reply.facts.into_iter().collect());
        hash(&mut facts, &reply.hash, &key, id);
        groups.insert(c.into.strip_prefix("env.").unwrap().to_owned(), facts);
        outcomes.insert(id.to_owned(), json!({"status": "ok", "into": c.into}));
    }
    json!({"env": groups, "collectors": outcomes})
}

fn checks(document: &Value) -> Vec<Check> {
    let ruleset = systemlint::yaml::from_str(
        &std::fs::read_to_string(repository().join("rulesets/env.yaml")).unwrap(),
    )
    .unwrap();
    let library = Library::new(BTreeMap::from([("env".to_owned(), ruleset)])).unwrap();
    let rules: Vec<_> = library
        .select(&["env".to_owned()])
        .unwrap()
        .into_iter()
        .map(|(id, spec)| compile(&id, spec).unwrap())
        .collect();
    assert_eq!(rules.len(), 9);
    lint(document, &rules, &[], "2026-11-11")
}

#[test]
fn units_ask_systemctl_for_three_properties_in_one_argument() {
    let c = Collector::parse(
        &std::fs::read_to_string(repository().join("collectors/env-units.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        c.read.exec.unwrap(),
        [
            "/usr/bin/systemctl",
            "show",
            "--property=Id,Environment,EnvironmentFiles",
            "*.service"
        ]
    );
}

#[test]
fn every_source_lands_with_secrets_hashed_and_proxy_passwords_masked() {
    let document = document();
    let env = &document["env"];
    assert_eq!(
        env["files"].as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "/etc/environment",
            "/etc/ld.so.preload",
            "/etc/profile.d/site.sh"
        ]
    );
    assert_eq!(
        env["defaults"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["/etc/default/app"]
    );
    assert_eq!(
        env["units"].as_object().unwrap().keys().collect::<Vec<_>>(),
        ["app.service", "clean.service"],
        "a masked unit is no subject"
    );
    assert_eq!(
        env["units"]["app.service"]["environment-files"],
        json!(["/etc/default/app"])
    );
    assert_eq!(
        env["processes"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["app.service", "containerd.service"],
        "a container is left to env-containers"
    );
    assert_eq!(env["processes"]["app.service"]["pid"], 100);
    assert_eq!(
        env["containers"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["container:web"],
        "named as Docker names it"
    );
    assert_eq!(
        env["image"][image_config().to_str().unwrap()]["vars"]["NODE_TLS_REJECT_UNAUTHORIZED"],
        "0"
    );
    assert!(
        env["defaults"]["/etc/default/app"]["vars"]["APP_API_TOKEN"]
            .as_str()
            .unwrap()
            .starts_with("hmac-sha256:")
    );
    assert_eq!(
        env["defaults"]["/etc/default/app"]["vars"]["APP_EMPTY_PASSWORD"],
        ""
    );
    assert_eq!(
        env["files"]["/etc/environment"]["vars"]["B19_SECRETS_ENABLED"], "True",
        "a switch word stays clear, so secret-name passes it"
    );
    assert_eq!(
        env["files"]["/etc/profile.d/site.sh"]["vars"]["https_proxy"],
        "http://user:[redacted]@proxy.example:3128"
    );
    let text = document.to_string();
    for secret in ["abc123", "hunter2", ":pw@"] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
}

#[test]
fn the_fixture_fails_every_env_rule_on_its_one_subject() {
    let checks = checks(&document());
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Unknown),
        "{checks:#?}"
    );
    let image = format!("image, {}", image_config().display());
    let mut failing: Vec<(&str, String)> = checks
        .iter()
        .filter(|c| c.is_failing())
        .map(|c| (c.rule.as_str(), c.subject_text()))
        .collect();
    failing.sort();
    let mut expected = vec![
        ("env/ca-override", "units, app.service".to_owned()),
        (
            "env/interpreter-injection",
            "files, /etc/profile.d/site.sh".to_owned(),
        ),
        ("env/ld-library-path", "units, app.service".to_owned()),
        ("env/ld-preload", "files, /etc/ld.so.preload".to_owned()),
        ("env/path-entry", "files, /etc/environment".to_owned()),
        ("env/proxy-http", "files, /etc/profile.d/site.sh".to_owned()),
        (
            "env/python-path",
            "files, /etc/profile.d/site.sh".to_owned(),
        ),
        ("env/secret-name", "defaults, /etc/default/app".to_owned()),
        ("env/tls-verify", image),
        ("env/tls-verify", "containers, container:web".to_owned()),
    ];
    expected.sort();
    assert_eq!(failing, expected);
    let skipped: Vec<String> = checks
        .iter()
        .filter(|c| c.rule == "env/secret-name" && c.outcome == Outcome::Skip)
        .map(|c| c.subject_text())
        .collect();
    assert_eq!(
        skipped,
        [
            "containers, container:web",
            "processes, app.service",
            "processes, containerd.service"
        ],
        "a process is no place a credential is written"
    );
    let tls = checks
        .iter()
        .find(|c| {
            c.rule == "env/tls-verify" && c.is_failing() && c.subject_text().starts_with("image")
        })
        .unwrap();
    assert!(
        tls.message
            .as_deref()
            .unwrap()
            .contains("sets NODE_TLS_REJECT_UNAUTHORIZED to “0”"),
        "{:?}",
        tls.message
    );
}

#[test]
fn proxies_on_loopback_or_https_pass_and_http_elsewhere_fails() {
    let mut document = json!({"env": {"files": {}}, "collectors": {"env-files": {"status": "ok", "into": "env.files"}}});
    for (name, url) in [
        ("a", "http://127.0.0.1:3128"),
        ("b", "http://u:p@localhost:8080"),
        ("c", "https://proxy:443"),
        ("d", "http://[::1]:3128"),
        ("e", "HTTP://proxy:80"),
        ("f", "http://proxy.lan:3128"),
    ] {
        document["env"]["files"][name] = json!({"kind": "file", "vars": {"ALL_PROXY": url}});
    }
    let failing: Vec<String> = checks(&document)
        .into_iter()
        .filter(|c| c.rule == "env/proxy-http" && c.is_failing())
        .map(|c| c.subject_text())
        .collect();
    assert_eq!(failing, ["files, e", "files, f"]);
}

#[test]
fn node_options_fail_only_with_a_preloading_flag() {
    let mut document = json!({"env": {"files": {}}, "collectors": {"env-files": {"status": "ok", "into": "env.files"}}});
    for (name, options) in [
        ("a", "--max-old-space-size=4096"),
        ("b", "-r ./hook.js"),
        ("c", "--import=x.mjs"),
        ("d", "--max-old-space-size=1 --require x"),
        ("e", "--required-flag"),
    ] {
        document["env"]["files"][name] = json!({"kind": "file", "vars": {"NODE_OPTIONS": options}});
    }
    let failing: Vec<String> = checks(&document)
        .into_iter()
        .filter(|c| c.rule == "env/interpreter-injection" && c.is_failing())
        .map(|c| c.subject_text())
        .collect();
    assert_eq!(failing, ["files, b", "files, c", "files, d"]);
}
