// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `rules` page collection: catalog entries, topic pages, anchors, escaping and the standard index order.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use systemlint::pages;
use systemlint::rules::{Library, Ruleset};

const RULESET: &str = r#"
description: Settings of <daemon>
topic: Demo and <tests>
tags: [default]
rules:
  demo/one:
    title: One is <on>
    fact: demo.one
    expect: {const: false}
    severity: warning
    score: 4.0
    fix: set `One <off>` in <file>
    tags: [cis-demo:1.1.2]
  demo/two:
    fact: demo.two
    expect: {const: false}
    tags: [cis-demo:1.1.10]
"#;

const BARE: &str = r#"
rules:
  bare/one:
    fact: bare.one
    expect: {const: false}
"#;

fn library() -> Library {
    let ruleset: Ruleset = systemlint::yaml::from_str(RULESET).unwrap();
    let bare: Ruleset = systemlint::yaml::from_str(BARE).unwrap();
    Library::new(BTreeMap::from([
        ("demo".to_owned(), ruleset),
        ("bare".to_owned(), bare),
    ]))
    .unwrap()
}

#[test]
fn catalog_lists_every_rule_with_its_ruleset() {
    let text = pages::catalog(&library()).unwrap();
    let document: serde_json::Value = systemlint::yaml::from_str(&text).unwrap();
    let items = document["org"]["projectfile"]["pages"]["rules"]["items"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["bare/one", "demo/one", "demo/two"]);
    assert_eq!(items[1]["ruleset"], "demo");
    assert_eq!(items[1]["title"], "One is <on>");
    assert!(items[2].get("title").is_none(), "{text}");
}

#[test]
fn section_escapes_markup_outside_code_and_links_within_the_collection() {
    let library = library();
    let section = pages::section(&library, "demo/one", &library.definitions["demo/one"]);
    assert!(
        section.starts_with("### One is &lt;on&gt; {#demo/one}\n"),
        "{section}"
    );
    assert!(
        section.contains("set `One <off>` in &lt;file&gt;"),
        "{section}"
    );
    assert!(section.contains("[demo](#demo)"), "{section}");
    assert!(
        section.contains("[`cis-demo:1.1.2`](standards/cis-demo.md)"),
        "{section}"
    );
}

#[test]
fn section_without_title_is_titled_by_its_id() {
    let library = library();
    let section = pages::section(&library, "demo/two", &library.definitions["demo/two"]);
    assert!(
        section.starts_with("### demo/two {#demo/two}\n"),
        "{section}"
    );
}

#[test]
fn topic_page_holds_its_rulesets_rules_and_standard_lists_control_2_before_10() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pages-standard");
    let _ = std::fs::remove_dir_all(&dir);
    let count = pages::write_all(&dir, &library()).unwrap();
    assert_eq!(count, 4);
    let topic = std::fs::read_to_string(dir.join("demo-and-tests.md")).unwrap();
    assert!(
        topic.starts_with("# Demo and &lt;tests&gt;\n\n## demo {#demo}\n"),
        "{topic}"
    );
    let one = topic.find("{#demo/one}").unwrap();
    let two = topic.find("{#demo/two}").unwrap();
    assert!(one < two, "{topic}");
    let other = std::fs::read_to_string(dir.join("other.md")).unwrap();
    assert!(other.contains("{#bare/one}"), "{other}");
    let standard = std::fs::read_to_string(dir.join("standards/cis-demo.md")).unwrap();
    let two = standard.find("| 1.1.2 |").unwrap();
    let ten = standard.find("| 1.1.10 |").unwrap();
    assert!(two < ten, "{standard}");
    assert!(
        standard.contains("[One is &lt;on&gt;](../demo-and-tests.md#demo/one)"),
        "{standard}"
    );
    assert!(!dir.join("demo/two.md").exists());
    assert!(!dir.join("rulesets").exists());
    let index = std::fs::read_to_string(dir.join("index.md")).unwrap();
    assert!(
        index.contains(
            "- [Demo and &lt;tests&gt;](demo-and-tests.md): [demo](demo-and-tests.md#demo)"
        ),
        "{index}"
    );
    assert!(
        index.contains("- [Other](other.md): [bare](other.md#bare)"),
        "{index}"
    );
}

#[test]
fn markdown_without_output_is_a_usage_error() {
    let status = Command::new(env!("CARGO_BIN_EXE_systemlint"))
        .args(["rules", "--format", "markdown"])
        .env("LC_ALL", "C")
        .output()
        .unwrap()
        .status;
    assert_eq!(status.code(), Some(2));
}
