// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `rules` page collection: the catalog at `org.projectfile.pages.rules.items` and one Markdown page per topic.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::rules::{Library, Score, Severity, Spec};

/// One catalog entry: what a reader needs to find a rule, never its schema.
#[derive(Serialize)]
struct Item<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    ruleset: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<&'a Score>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    tags: &'a [String],
}

/// The catalog of every rule `library` defines, as a projectfile document in YAML.
pub fn catalog(library: &Library) -> Result<String, String> {
    let items: Vec<Item> = library
        .definitions
        .iter()
        .map(|(id, spec)| Item {
            id,
            title: spec.title.as_deref(),
            ruleset: owner(library, id),
            severity: spec.severity,
            score: spec.score.as_ref(),
            tags: &spec.tags,
        })
        .collect();
    log::debug!("rule catalog of {} rules", items.len());
    let document = json!({"org": {"projectfile": {"pages": {"rules": {"items": items}}}}});
    serde_saphyr::to_string_with_options(&document, expanded())
        .map_err(|e| format!("can’t encode the rule catalog as YAML: {e}"))
}

/// Serializer options that indent a list under its key, as yamllint asks.
fn expanded() -> serde_saphyr::SerializerOptions {
    let mut options = serde_saphyr::SerializerOptions::default();
    options.compact_list_indent = false;
    options
}

fn owner<'a>(library: &'a Library, id: &str) -> &'a str {
    library.owners.get(id).map_or("", String::as_str)
}

/// The standard a control tag belongs to: `cis-ubuntu-26.04` for `cis-ubuntu-26.04:5.1.20`.
fn standard(tag: &str) -> Option<(&str, &str)> {
    tag.split_once(':')
        .filter(|(s, c)| !s.is_empty() && !c.is_empty())
}

/// Markdown text with every `<` and `>` outside code spans escaped, so a `<user>` placeholder is no HTML tag.
/// A fix as markdown: its sentence, or a numbered list whose commands and file lines sit in a code block under their step.
fn fix_markdown(fix: &crate::rules::Fix) -> String {
    use crate::rules::{Fix, Step};
    let steps = match fix {
        Fix::Text(text) => return escaped(text),
        Fix::Steps(steps) => steps,
    };
    let mut out = String::new();
    let mut number = 0;
    for step in steps {
        match step {
            Step::Say(text) => {
                number += 1;
                out.push_str(&format!("{number}. {}\n", escaped(text)));
            }
            Step::Show(shown) => {
                let lines: Vec<String> = shown.lines().iter().map(|l| format!("   {l}")).collect();
                out.push_str(&format!("\n   ```text\n{}\n   ```\n\n", lines.join("\n")));
            }
        }
    }
    out.trim_end().to_owned()
}

fn escaped(text: &str) -> String {
    text.split('`')
        .enumerate()
        .map(|(i, part)| {
            if i % 2 == 1 {
                part.to_owned()
            } else {
                part.replace('<', "&lt;").replace('>', "&gt;")
            }
        })
        .collect::<Vec<_>>()
        .join("`")
}

/// The path from the page at collection path `from` to the collection path `to`.
fn relative(from: &str, to: &str) -> String {
    let depth = from.matches('/').count();
    format!("{}{to}", "../".repeat(depth))
}

/// The topic page that never named one gets.
const OTHER: &str = "Other";

/// The topic whose page lists `ruleset`: its own `topic`, else `Other`.
fn topic<'a>(library: &'a Library, ruleset: &str) -> &'a str {
    library
        .rulesets
        .get(ruleset)
        .and_then(|r| r.topic.as_deref())
        .unwrap_or(OTHER)
}

/// A topic’s page in the collection, `logging-and-auditing.md` for `Logging and auditing`.
fn topic_file(topic: &str) -> String {
    let slug: Vec<String> = topic
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect();
    format!("{}.md", slug.join("-"))
}

/// A rule’s place in the collection: its topic page, anchored by its ID.
fn href(library: &Library, id: &str) -> String {
    format!("{}#{id}", topic_file(topic(library, owner(library, id))))
}

fn score_text(score: &Score) -> String {
    match score {
        Score::Fixed(points) => format!("{points:.1}"),
        Score::Curve(curve) => curve
            .iter()
            .map(|(v, p)| format!("{v} → {p:.1}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn schema(label: &str, value: &Map<String, Value>) -> String {
    format!(
        "#### {label}\n\n```json\n{}\n```",
        serde_json::to_string_pretty(value).unwrap_or_default()
    )
}

/// One rule’s section on its topic page: its title anchored by its ID, a table of what it is, then its message, fix, rationale, schema and references.
pub fn section(library: &Library, id: &str, spec: &Spec) -> String {
    let ruleset = owner(library, id);
    let tags = spec
        .tags
        .iter()
        .map(|tag| match standard(tag) {
            Some((s, _)) => format!("[`{tag}`](standards/{s}.md)"),
            None => format!("`{tag}`"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut rows = vec![
        ("ID", format!("`{id}`")),
        ("Ruleset", format!("[{ruleset}](#{ruleset})")),
    ];
    rows.extend(
        spec.severity
            .map(|s| ("Severity", format!("{s:?}").to_lowercase())),
    );
    rows.extend(spec.score.as_ref().map(|s| ("Score", score_text(s))));
    if spec.manual {
        rows.push(("Check", "manual".to_owned()));
    }
    rows.extend(spec.fact.as_ref().map(|f| ("Reads", format!("`{f}`"))));
    if !tags.is_empty() {
        rows.push(("Tags", tags));
    }
    let mut blocks = vec![
        format!(
            "### {} {{#{id}}}",
            escaped(spec.title.as_deref().unwrap_or(id))
        ),
        ["| | |", "|---|---|"]
            .into_iter()
            .map(str::to_owned)
            .chain(
                rows.iter()
                    .map(|(label, value)| format!("| {label} | {value} |")),
            )
            .collect::<Vec<_>>()
            .join("\n"),
    ];
    for (label, text) in [("Message", &spec.message), ("Rationale", &spec.rationale)] {
        if let Some(text) = text {
            blocks.push(format!("#### {label}\n\n{}", escaped(text)));
        }
    }
    if let Some(fix) = &spec.fix {
        blocks.push(format!("#### Fix\n\n{}", fix_markdown(fix)));
    }
    if let Some(expect) = &spec.expect {
        blocks.push(schema("Expects", expect));
    }
    if !spec.conflicts.is_empty() {
        let links = spec
            .conflicts
            .iter()
            .map(|c| format!("- [{c}]({})", href(library, c)));
        blocks.push(format!(
            "#### Conflicts\n\n{}",
            links.collect::<Vec<_>>().join("\n")
        ));
    }
    let references: Vec<String> = spec
        .docs
        .iter()
        .map(|url| format!("- <{url}>"))
        .chain(
            spec.references
                .iter()
                .map(|r| format!("- [{}]({})", escaped(&r.title), r.url)),
        )
        .collect();
    if !references.is_empty() {
        blocks.push(format!("#### References\n\n{}", references.join("\n")));
    }
    blocks.join("\n\n")
}

/// The rules of each standard by control: `cis-ubuntu-26.04` → `5.1.20` → rule IDs.
fn standards(library: &Library) -> BTreeMap<&str, BTreeMap<&str, Vec<&str>>> {
    let mut found: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for (id, spec) in &library.definitions {
        for (s, control) in spec.tags.iter().filter_map(|t| standard(t)) {
            found
                .entry(s)
                .or_default()
                .entry(control)
                .or_default()
                .push(id);
        }
    }
    found
}

fn write(dir: &Path, rel: &str, body: &str) -> Result<(), String> {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("can’t create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, body).map_err(|e| format!("can’t write {}: {e}", path.display()))
}

/// Every page under `dir`: one per topic, holding its rulesets’ rules one after another, one per standard, and `index.md`; returns how many.
pub fn write_all(dir: &Path, library: &Library) -> Result<usize, String> {
    let mut count = 0;
    let mut topics: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for name in library.rulesets.keys() {
        if !library.owners.values().any(|o| o == name) {
            log::debug!("ruleset {name} defines no rule, so no page lists it");
            continue;
        }
        topics.entry(topic(library, name)).or_default().push(name);
    }
    let mut index = format!(
        "# Rules\n\nRules: {}\n\n## Topics\n\n",
        library.definitions.len()
    );
    for (topic, rulesets) in &topics {
        let file = topic_file(topic);
        let mut blocks = vec![format!("# {}", escaped(topic))];
        for name in rulesets {
            let description = library.rulesets[*name]
                .description
                .as_deref()
                .map(escaped)
                .unwrap_or_default();
            blocks.push(format!("## {name} {{#{name}}}\n\n{description}"));
            blocks.extend(
                library
                    .owners
                    .iter()
                    .filter(|(_, o)| o == name)
                    .map(|(id, _)| section(library, id, &library.definitions[id])),
            );
        }
        log::debug!("topic {topic} lists {} rulesets in {file}", rulesets.len());
        write(dir, &file, &(blocks.join("\n\n") + "\n"))?;
        let links: Vec<String> = rulesets
            .iter()
            .map(|name| format!("[{name}]({file}#{name})"))
            .collect();
        index += &format!("- [{}]({file}): {}\n", escaped(topic), links.join(", "));
        count += 1;
    }
    let standards = standards(library);
    if !standards.is_empty() {
        index += "\n## Standards\n\n";
    }
    for (s, controls) in &standards {
        let mut controls: Vec<_> = controls.iter().collect();
        controls.sort_by_key(|(control, _)| natural(control));
        let rows = controls.iter().flat_map(|(control, ids)| {
            ids.iter().map(move |id| {
                format!(
                    "| {control} | [{}]({}) |",
                    title(library, id),
                    relative("standards/", &href(library, id))
                )
            })
        });
        let body = format!(
            "# {s}\n\n| Control | Rule |\n|---|---|\n{}\n",
            rows.collect::<Vec<_>>().join("\n")
        );
        write(dir, &format!("standards/{s}.md"), &body)?;
        index += &format!("- [{s}](standards/{s}.md): {} controls\n", controls.len());
        count += 1;
    }
    write(dir, "index.md", &index)?;
    log::info!("{} rule pages written to {}", count + 1, dir.display());
    Ok(count + 1)
}

/// A control as numbers where it has them, so `1.1.1.2` sorts before `1.1.1.10`.
fn natural(control: &str) -> Vec<(u64, String)> {
    control
        .split(['.', '-'])
        .map(|part| (part.parse().unwrap_or(u64::MAX), part.to_owned()))
        .collect()
}

fn title(library: &Library, id: &str) -> String {
    escaped(
        library
            .definitions
            .get(id)
            .and_then(|s| s.title.as_deref())
            .unwrap_or(id),
    )
}
