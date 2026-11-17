// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `rules` page collection: catalog entries, page links, escaping and the standard index order.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use systemlint::pages;
use systemlint::rules::{Library, Ruleset};

const RULESET: &str = r#"
description: Settings of <daemon>
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

fn library() -> Library {
    let ruleset: Ruleset = systemlint::yaml::from_str(RULESET).unwrap();
    Library::new(BTreeMap::from([("demo".to_owned(), ruleset)])).unwrap()
}

#[test]
fn catalog_lists_every_rule_with_its_ruleset() {
    let text = pages::catalog(&library()).unwrap();
    let document: serde_json::Value = systemlint::yaml::from_str(&text).unwrap();
    let items = document["org"]["projectfile"]["pages"]["rules"]["items"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["demo/one", "demo/two"]);
    assert_eq!(items[0]["ruleset"], "demo");
    assert_eq!(items[0]["title"], "One is <on>");
    assert!(items[1].get("title").is_none(), "{text}");
}

#[test]
fn page_escapes_markup_outside_code_and_links_one_level_up() {
    let library = library();
    let page = pages::page(&library, "demo/one", &library.definitions["demo/one"]);
    assert!(page.starts_with("# One is &lt;on&gt;\n"), "{page}");
    assert!(page.contains("set `One <off>` in &lt;file&gt;"), "{page}");
    assert!(page.contains("[demo](../rulesets/demo.md)"), "{page}");
    assert!(
        page.contains("[`cis-demo:1.1.2`](../standards/cis-demo.md)"),
        "{page}"
    );
}

#[test]
fn page_without_title_is_titled_by_its_id() {
    let library = library();
    let page = pages::page(&library, "demo/two", &library.definitions["demo/two"]);
    assert!(page.starts_with("# demo/two\n"), "{page}");
}

#[test]
fn standard_lists_control_2_before_10() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pages-standard");
    let _ = std::fs::remove_dir_all(&dir);
    let count = pages::write_all(&dir, &library()).unwrap();
    assert_eq!(count, 5);
    let standard = std::fs::read_to_string(dir.join("standards/cis-demo.md")).unwrap();
    let two = standard.find("| 1.1.2 |").unwrap();
    let ten = standard.find("| 1.1.10 |").unwrap();
    assert!(two < ten, "{standard}");
    assert!(
        standard.contains("[One is &lt;on&gt;](../demo/one.md)"),
        "{standard}"
    );
    assert!(dir.join("demo/two.md").is_file());
    assert!(
        std::fs::read_to_string(dir.join("index.md"))
            .unwrap()
            .contains("[demo](rulesets/demo.md): Settings of &lt;daemon&gt;")
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
