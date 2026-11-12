// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Lint output in every format, each standard’s answer within it, and the `--fail-on` threshold.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::str::FromStr;

use serde_json::{Value, json};

use crate::comply::{Report, Verdict};
use crate::judge::{Check, Outcome, band};
use crate::rules::Severity;

/// The failures that make `lint` exit 1: at or above a level, at or above a score, or never.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FailOn {
    Level(Severity),
    Score(f64),
    Never,
}

impl FromStr for FailOn {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "never" => Ok(Self::Never),
            "error" => Ok(Self::Level(Severity::Error)),
            "warning" => Ok(Self::Level(Severity::Warning)),
            "info" => Ok(Self::Level(Severity::Info)),
            _ => match text.parse::<f64>() {
                Ok(score) if (0.1..=9.9).contains(&score) => Ok(Self::Score(score)),
                _ => Err(format!("fail-on {text:?} is not error, warning, info, never or a score from 0.1 to 9.9")),
            },
        }
    }
}

impl FailOn {
    /// Whether any check fails at or above this threshold; a hint never does.
    pub fn reached(self, checks: &[Check]) -> bool {
        checks.iter().filter(|c| c.is_failing() && c.severity != Some(Severity::Hint)).any(|c| match self {
            Self::Never => false,
            Self::Level(level) => c.severity >= Some(level),
            Self::Score(score) => c.score.unwrap_or_default() >= score,
        })
    }
}

/// The count of each outcome, waived failures apart.
pub fn summary(checks: &[Check]) -> Value {
    let count = |o: Outcome| checks.iter().filter(|c| c.outcome == o).count();
    let waived = checks.iter().filter(|c| c.outcome == Outcome::Fail && !c.is_failing()).count();
    json!({"checks": checks.len(), "pass": count(Outcome::Pass), "fail": count(Outcome::Fail) - waived, "waived": waived, "unknown": count(Outcome::Unknown), "skip": count(Outcome::Skip)})
}

/// The lowest share passed, in tenths, each grade still reaches, best first; F takes the rest.
const FLOORS: [(f64, char); 5] = [(9.0, 'A'), (7.0, 'B'), (6.0, 'C'), (4.0, 'D'), (2.0, 'E')];

/// Columns a wrapped human line fills at most.
const WIDTH: usize = 80;

/// A run’s grade, S to F, and the share of judged checks it rests on.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Rating {
    pub grade: char,
    pub score: f64,
}

/// What a failure costs the rating: 1 at the warning base, rising with the square of its score.
pub fn weight(score: f64) -> f64 {
    (score / band(Severity::Warning).2).powi(2)
}

/// The grade as spiderlint gives it: S with no failure, else the share passed after costs; an error caps it at B, nothing judged gives none.
pub fn rate(checks: &[Check]) -> Option<Rating> {
    let judged: Vec<&Check> = checks.iter().filter(|c| c.outcome == Outcome::Pass || c.is_failing()).collect();
    if judged.is_empty() {
        log::debug!("no rating: none of {} checks was judged", checks.len());
        return None;
    }
    let failing: Vec<&&Check> = judged.iter().filter(|c| c.is_failing()).collect();
    let cost: f64 = failing.iter().map(|c| weight(c.score.unwrap_or_default())).sum();
    let total = judged.len() as f64;
    let kept = (total - cost).max(0.0);
    let floors = if failing.iter().any(|c| c.severity == Some(Severity::Error)) { &FLOORS[1..] } else { &FLOORS[..] };
    let grade = if failing.is_empty() { 'S' } else { floors.iter().find(|(tenths, _)| kept * 10.0 >= tenths * total).map_or('F', |f| f.1) };
    log::debug!("rating {grade}: {} failing of {total} judged cost {cost}", failing.len());
    Some(Rating { grade, score: (kept / total * 10_000.0).round() / 10_000.0 })
}

/// Whether to colour the report: `--color` when not auto, else the environment, else whether the stream is a terminal.
pub fn colour(choice: Colour, var: impl Fn(&str) -> Option<String>, terminal: bool) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    let decided = match choice {
        Colour::Always => true,
        Colour::Never => false,
        Colour::Auto if set("SYSTEMLINT_NO_COLOR") || set("NO_COLOR") => false,
        Colour::Auto if set("FORCE_COLOR") => var("FORCE_COLOR").as_deref() != Some("0"),
        Colour::Auto => var("TERM").as_deref() != Some("dumb") && terminal,
    };
    log::debug!("colour {decided} from --color {choice:?}, terminal {terminal}");
    decided
}

/// The `--color` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Colour {
    Auto,
    Always,
    Never,
}

/// `text` in an SGR style from the 16-colour palette, or as it is.
fn paint(on: bool, code: &str, text: &str) -> String {
    if on { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
}

/// The capitalised level word and its colour code: red error, yellow warning, dim info and hint.
fn level_word(severity: Option<Severity>) -> (&'static str, &'static str) {
    match severity {
        Some(Severity::Error) => ("Error", "31"),
        Some(Severity::Warning) => ("Warning", "33"),
        Some(Severity::Info) => ("Info", "2"),
        _ => ("Hint", "2"),
    }
}

/// The skip reason of the collector an `unknown` check waited on, when that collector was skipped.
fn skip_reason<'a>(document: &'a Value, check: &Check) -> Option<&'a str> {
    let outcome = &document["collectors"][check.collector.as_deref()?];
    outcome["reason"].as_str().filter(|_| check.outcome == Outcome::Unknown && outcome["status"] == "skipped")
}

/// Whether `value` is `text` or a list holding it.
fn names(value: Option<&Value>, text: &str) -> bool {
    match value {
        Some(Value::String(s)) => s == text,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(text)),
        _ => false,
    }
}

/// Whether two failures of one rule point at each other, as the two sides of a duplicate do.
fn mirrored(a: &Check, b: &Check) -> bool {
    names(a.value.as_ref(), &b.subject_text()) && names(b.value.as_ref(), &a.subject_text())
}

/// The failures of one rule in clusters, each cluster one problem: a failure alone, or every subject pointing at another.
fn clusters<'a>(checks: &[&'a Check]) -> Vec<Vec<&'a Check>> {
    let mut out: Vec<Vec<&Check>> = Vec::new();
    for check in checks {
        match out.iter_mut().find(|cluster| cluster.iter().any(|c| mirrored(c, check))) {
            Some(cluster) => cluster.push(check),
            None => out.push(vec![check]),
        }
    }
    log::debug!("{} failures fold into {} problems", checks.len(), out.len());
    out
}

/// What one location adds to its rule’s title: the message without a title, else the field and offending value the message names.
fn detail(check: &Check) -> Option<String> {
    let Some(template) = check.text.as_deref().filter(|_| check.title.is_some()) else { return check.message.clone() };
    let var = |name: &str| check.variables.get(name).filter(|_| template.contains(&format!("{{{name}}}"))).cloned();
    let got = var("got").filter(|g| g != "none");
    match (var("field"), got) {
        (Some(field), Some(got)) => Some(format!("{field} {got}")),
        (field, got) => field.or(got),
    }
}

/// One `- ` line: the subject, then what it adds, either alone when the other is missing.
fn location(subject: &str, detail: Option<&str>) -> String {
    match (subject.is_empty(), detail) {
        (false, Some(d)) => format!("- {subject}: {d}"),
        (true, Some(d)) => format!("- {d}"),
        (_, None) => format!("- {subject}"),
    }
}

/// The header of one rule’s block: label, rule ID in bold, and the title when the rule has one.
fn header(label: &str, check: &Check, on: bool) -> String {
    let id = paint(on, "1", &format!("[{}]", check.rule));
    check.title.as_deref().map_or_else(|| format!("{label}: {id}"), |title| format!("{label}: {id} {title}"))
}

/// The failing checks of one rule as a block: level and highest score, why, a line per location, the fix once when every location shares it, then the references when `verbose`.
fn failure_block(out: &mut String, group: &[&Check], verbose: bool, on: bool) {
    let worst = group.iter().copied().max_by(|a, b| a.score.unwrap_or_default().total_cmp(&b.score.unwrap_or_default())).unwrap_or(group[0]);
    let (word, code) = level_word(worst.severity);
    let label = format!("{} ({:.1})", paint(on, code, word), worst.score.unwrap_or_default());
    let _ = writeln!(out, "{}", header(&label, worst, on));
    if let Some(why) = &worst.rationale {
        let _ = writeln!(out, "Why: {why}");
    }
    let problems = clusters(group);
    let shared = problems.iter().all(|p| p[0].fix == problems[0][0].fix);
    for problem in &problems {
        for check in problem {
            let (subject, said) = (check.subject_text(), if problem.len() > 1 { None } else { detail(check) });
            let named = check.title.is_none() && said.as_deref().is_some_and(|m| m.contains(&subject));
            let mut line = location(if named { "" } else { &subject }, said.as_deref());
            if let Some(w) = &check.waiver {
                let _ = write!(line, " (waiver expired on {}: {})", w.until, w.reason);
            }
            let _ = writeln!(out, "{line}");
        }
        if let Some(fix) = problem[0].fix.as_deref().filter(|_| !shared) {
            let _ = writeln!(out, "  Fix: {fix}");
        }
    }
    if let Some(fix) = problems[0][0].fix.as_deref().filter(|_| shared) {
        let _ = writeln!(out, "Fix: {fix}");
    }
    for reference in worst.references.iter().filter(|_| verbose) {
        let _ = writeln!(out, "See: {} <{}>", reference.title, reference.url);
    }
    out.push('\n');
}

/// `items` joined by commas into lines of at most `WIDTH` columns, each indented by two spaces.
fn wrap(items: &[String], on: bool) -> String {
    let (mut out, mut width) = (String::new(), 0);
    for item in items {
        let length = item.chars().count();
        if width > 0 && width + 2 + length > WIDTH {
            out.push_str(",\n");
            width = 0;
        } else if width > 0 {
            out.push_str(", ");
            width += 2;
        }
        if width == 0 {
            out.push_str("  ");
            width = 2;
        }
        out.push_str(&paint(on, "1", item));
        width += length;
    }
    out + "\n"
}

/// The checks grouped by rule, in rule order.
fn by_rule<'a>(checks: impl Iterator<Item = &'a Check>) -> BTreeMap<&'a str, Vec<&'a Check>> {
    let mut groups: BTreeMap<&str, Vec<&Check>> = BTreeMap::new();
    for check in checks {
        groups.entry(&check.rule).or_default().push(check);
    }
    groups
}

/// The failing groups, lowest score first, so the worst sits just above the summary.
fn ranked(checks: &[Check]) -> Vec<Vec<&Check>> {
    let mut groups: Vec<Vec<&Check>> = by_rule(checks.iter().filter(|c| c.is_failing())).into_values().collect();
    let worst = |g: &Vec<&Check>| g.iter().map(|c| c.score.unwrap_or_default()).fold(0.0, f64::max);
    groups.sort_by(|a, b| worst(a).total_cmp(&worst(b)).then_with(|| a[0].rule.cmp(&b[0].rule)));
    groups
}

/// `count` and its noun, plural unless one.
fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The closing line: rating, failures by level, then the other outcomes, zero counts beyond the levels left out.
fn summary_line(document: &Value, checks: &[Check], on: bool) -> String {
    let failing = |level: Severity| checks.iter().filter(|c| c.is_failing() && c.severity == Some(level)).count();
    let rating = rate(checks).map_or_else(|| "No rating".to_owned(), |r| {
        let code = match r.grade { 'S' | 'A' => "32", 'B' | 'C' => "33", _ => "31" };
        format!("Rating {}", paint(on, &format!("1;{code}"), &r.grade.to_string()))
    });
    let mut levels = vec![counted(failing(Severity::Error), "error", "errors"), counted(failing(Severity::Warning), "warning", "warnings"), format!("{} info", failing(Severity::Info))];
    let hints = failing(Severity::Hint);
    if hints > 0 {
        levels.push(counted(hints, "hint", "hints"));
    }
    let s = summary(checks);
    let not_run = checks.iter().filter(|c| skip_reason(document, c).is_some()).count();
    let unknown = s["unknown"].as_u64().unwrap_or_default() as usize - not_run;
    let rest: Vec<String> = [("pass", s["pass"].as_u64().unwrap_or_default() as usize), ("waived", s["waived"].as_u64().unwrap_or_default() as usize), ("unknown", unknown), ("not run", not_run), ("skip", s["skip"].as_u64().unwrap_or_default() as usize)]
        .into_iter()
        .filter(|(name, n)| *n > 0 || *name == "pass")
        .map(|(name, n)| format!("{n} {name}"))
        .collect();
    format!("{rating} · {} · {}\n", levels.join(", "), rest.join(", "))
}

/// The verdict word and its colour code, like a level’s: red non-compliant, yellow indeterminate, dim otherwise.
fn verdict_word(verdict: Verdict) -> (String, &'static str) {
    let code = match verdict {
        Verdict::NonCompliant => "31",
        Verdict::Indeterminate => "33",
        Verdict::Compliant | Verdict::Manual => "2",
    };
    (name(verdict), code)
}

/// One standard’s section: its verdict, a row per control with the reasons under it, coverage and note.
fn standard_block(out: &mut String, report: &Report, on: bool) {
    let (word, code) = verdict_word(report.verdict);
    let title = if report.name == report.standard { String::new() } else { format!(" {}", report.name) };
    let _ = writeln!(out, "Standard: {} {}{title}", paint(on, code, &word), paint(on, "1", &format!("[{}]", report.standard)));
    let width = report.controls.iter().map(|c| c.id.chars().count()).max().unwrap_or(0);
    for control in &report.controls {
        let (word, code) = verdict_word(control.verdict);
        let row = format!("- {:width$}  {}{:pad$}  {}", control.id, paint(on, code, &word), "", control.title.as_deref().unwrap_or_default(), pad = 13 - word.len());
        let _ = writeln!(out, "{}", row.trim_end());
        for reason in &control.reasons {
            let _ = writeln!(out, "  {:width$}  {reason}", "");
        }
    }
    if let Some(c) = &report.coverage {
        let _ = writeln!(out, "Coverage: {} of {} controls", c.covered, c.total);
    }
    if let Some(note) = &report.note {
        let _ = writeln!(out, "Note: {note}");
    }
    out.push('\n');
}

/// One block per rule: not run reasons, unknowns, waivers, failures lowest score first (with references when `verbose`), each standard, then the rating and counts unless `quiet`.
pub fn lint_human(document: &Value, checks: &[Check], compliance: &[Report], quiet: bool, verbose: bool, on: bool) -> String {
    let mut out = String::new();
    let mut not_run: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    for check in checks {
        if let (Some(reason), Some(collector)) = (skip_reason(document, check), check.collector.as_deref()) {
            let (collectors, rules) = not_run.entry(reason).or_default();
            collectors.insert(collector);
            rules.insert(&check.rule);
        }
    }
    for (reason, (collectors, rules)) in &not_run {
        log::debug!("{} rules not run: collectors {collectors:?} {reason}", rules.len());
        let _ = writeln!(out, "Not run ({}): {reason}", collectors.iter().copied().collect::<Vec<_>>().join(", "));
        out.push_str(&wrap(&rules.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>(), on));
        out.push('\n');
    }
    for group in by_rule(checks.iter().filter(|c| c.outcome == Outcome::Unknown && skip_reason(document, c).is_none())).values() {
        let _ = writeln!(out, "{}", header("Unknown", group[0], on));
        group.iter().for_each(|c| { let _ = writeln!(out, "{}", location(&c.subject_text(), c.reason.as_deref())); });
        out.push('\n');
    }
    for group in by_rule(checks.iter().filter(|c| c.outcome == Outcome::Fail && !c.is_failing())).values() {
        let _ = writeln!(out, "{}", header("Waived", group[0], on));
        for (check, w) in group.iter().filter_map(|c| Some((c, c.waiver.as_ref()?))) {
            let _ = writeln!(out, "{}", location(&check.subject_text(), Some(&format!("{} (until {})", w.reason, w.until))));
        }
        out.push('\n');
    }
    for group in ranked(checks) {
        failure_block(&mut out, &group, verbose, on);
    }
    for report in compliance {
        standard_block(&mut out, report, on);
    }
    if !quiet {
        out.push_str(&summary_line(document, checks, on));
    }
    out
}

/// `text` as one tab-separated field: tabs and newlines become spaces.
fn field(text: &str) -> String {
    text.replace(['\t', '\n'], " ")
}

/// One finding per tab-separated line, in the human order and undecorated, a rule not run once: outcome or level, score, rule, subject, message, fix; then each standard and its controls.
pub fn lint_plain(document: &Value, checks: &[Check], compliance: &[Report], quiet: bool) -> String {
    let mut out = String::new();
    let mut row = |cells: [&str; 6]| { let _ = writeln!(out, "{}", cells.map(field).join("\t")); };
    for (rule, group) in by_rule(checks.iter().filter(|c| skip_reason(document, c).is_some())) {
        row(["not-run", "", rule, "", skip_reason(document, group[0]).unwrap_or_default(), ""]);
    }
    for check in checks.iter().filter(|c| c.outcome == Outcome::Unknown && skip_reason(document, c).is_none()) {
        row(["unknown", "", &check.rule, &check.subject_text(), check.reason.as_deref().unwrap_or_default(), ""]);
    }
    for check in checks.iter().filter(|c| c.outcome == Outcome::Fail && !c.is_failing()) {
        let until = check.waiver.as_ref().map(|w| format!("waived until {}: {}", w.until, w.reason)).unwrap_or_default();
        row(["waived", &format!("{:.1}", check.score.unwrap_or_default()), &check.rule, &check.subject_text(), check.message.as_deref().unwrap_or_default(), &until]);
    }
    for check in ranked(checks).into_iter().flatten() {
        row([&name(check.severity), &format!("{:.1}", check.score.unwrap_or_default()), &check.rule, &check.subject_text(), check.message.as_deref().unwrap_or_default(), check.fix.as_deref().unwrap_or_default()]);
    }
    for report in compliance {
        let coverage = report.coverage.as_ref().map(|c| format!("{} of {}", c.covered, c.total)).unwrap_or_default();
        row(["standard", &name(report.verdict), &report.standard, "", &coverage, &report.name]);
        for control in &report.controls {
            row(["control", &name(control.verdict), &report.standard, &control.id, &control.reasons.join("; "), control.title.as_deref().unwrap_or_default()]);
        }
    }
    if !quiet {
        let grade = rate(checks).map_or_else(|| "-".to_owned(), |r| r.grade.to_string());
        let _ = writeln!(out, "rating\t{grade}\t\t\t{}\t", field(summary_line(document, checks, false).trim_end()));
    }
    out
}

/// The `meta` of the facts, every check, the counts, the rating and each standard’s answer, as indented JSON.
pub fn lint_json(document: &Value, checks: &[Check], compliance: &[Report]) -> String {
    let mut report = json!({"meta": document["meta"], "checks": checks, "summary": summary(checks), "rating": rate(checks)});
    if !compliance.is_empty() {
        report["compliance"] = compliance.iter().map(|r| (r.standard.clone(), json!(r))).collect::<serde_json::Map<_, _>>().into();
    }
    serde_json::to_string_pretty(&report).unwrap_or_default() + "\n"
}

/// The SARIF level of a failure: error, warning, or note for info and hint.
fn level(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::Error) => "error",
        Some(Severity::Warning) => "warning",
        _ => "note",
    }
}

/// `text` with the characters a URI path cannot hold percent-encoded.
fn uri_path(text: &str) -> String {
    text.chars().fold(String::new(), |mut out, c| {
        match c {
            '%' | ' ' | '#' | '?' | '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}' => {
                let mut bytes = [0; 4];
                c.encode_utf8(&mut bytes).bytes().for_each(|b| out.push_str(&format!("%{b:02X}")));
            }
            _ => out.push(c),
        }
        out
    })
}

/// The file a check is about: its last subject key that is an absolute path, with a trailing `:line`.
fn file_of(check: &Check) -> Option<(String, Option<u64>)> {
    let key = check.subject.iter().rev().find(|k| k.starts_with('/'))?;
    match key.rsplit_once(':') {
        Some((path, line)) if line.parse::<u64>().is_ok_and(|n| n > 0) => Some((path.to_owned(), line.parse().ok())),
        _ => Some((key.clone(), None)),
    }
}

/// The SARIF location of a check: the subject file under `ROOT` when there is one, always the fact path.
fn locations(check: &Check) -> Value {
    let logical = json!([{"fullyQualifiedName": if check.subject.is_empty() { check.fact.clone() } else { format!("{} {}", check.fact, check.subject_text()) }, "kind": "object"}]);
    let Some((path, line)) = file_of(check) else { return json!([{"logicalLocations": logical}]) };
    let mut physical = json!({"artifactLocation": {"uri": uri_path(path.trim_start_matches('/')), "uriBaseId": "ROOT"}});
    if let Some(line) = line {
        physical["region"] = json!({"startLine": line});
    }
    json!([{"physicalLocation": physical, "logicalLocations": logical}])
}

/// The SARIF result of a failure or an unknown; none for pass and skip.
fn result(check: &Check) -> Option<Value> {
    let mut out = match check.outcome {
        Outcome::Fail => json!({"ruleId": check.rule, "kind": "fail", "level": level(check.severity), "message": {"text": check.message.as_deref().unwrap_or(&check.rule)}}),
        Outcome::Unknown => json!({"ruleId": check.rule, "kind": "open", "level": "none", "message": {"text": check.reason.as_deref().unwrap_or("unknown")}}),
        Outcome::Pass | Outcome::Skip => return None,
    };
    out["locations"] = locations(check);
    out["partialFingerprints"] = json!({"systemlintSubject/v1": format!("{}|{}", check.rule, check.subject_text())});
    if let Some(waiver) = check.waiver.as_ref().filter(|w| w.active && check.outcome == Outcome::Fail) {
        out["suppressions"] = json!([{"kind": "external", "status": "accepted", "justification": format!("{} (until {})", waiver.reason, waiver.until)}]);
    }
    if let Some(fix) = &check.fix {
        out["properties"] = json!({"fix": fix});
    }
    Some(out)
}

/// The controls a rule covers, as SARIF relationships into each standard’s taxonomy.
fn relationships(rule: &str, compliance: &[Report]) -> Vec<Value> {
    let pairs = compliance.iter().enumerate().flat_map(|(index, r)| r.controls.iter().filter(|c| c.rules.iter().any(|id| id == rule)).map(move |c| (index, r, c)));
    pairs.map(|(index, r, c)| json!({"target": {"id": c.id, "toolComponent": {"name": r.standard, "index": index}}, "kinds": ["relevant"]})).collect()
}

/// Each standard as a SARIF taxonomy, a taxon per control carrying its verdict.
fn taxonomies(compliance: &[Report]) -> Vec<Value> {
    let taxon = |c: &crate::comply::ControlResult| {
        let mut taxon = json!({"id": c.id, "properties": {"verdict": c.verdict, "reasons": c.reasons}});
        if let Some(title) = &c.title {
            taxon["shortDescription"] = json!({"text": title});
        }
        taxon
    };
    compliance.iter().map(|r| json!({"name": r.standard, "fullName": r.name, "taxa": r.controls.iter().map(taxon).collect::<Vec<_>>()})).collect()
}

/// A rule’s rationale and references as SARIF `help`, in plain text and markdown, or `None` when it has neither.
fn help(check: &Check) -> Option<Value> {
    let (mut text, mut markdown) = (check.rationale.clone().into_iter().collect::<Vec<_>>(), check.rationale.clone().into_iter().collect::<Vec<_>>());
    text.extend(check.references.iter().map(|r| format!("{}: {}", r.title, r.url)));
    markdown.extend(check.references.iter().map(|r| format!("- [{}]({})", r.title.replace(']', "\\]"), r.url)));
    (!text.is_empty()).then(|| json!({"text": text.join("\n"), "markdown": markdown.join("\n\n")}))
}

/// The descriptor of every rule the checks name: title, tags, docs, rationale and references, default level, `security-severity` from the score and the controls it covers.
fn descriptors(checks: &[Check], compliance: &[Report]) -> Vec<Value> {
    let mut seen = std::collections::BTreeMap::new();
    for check in checks {
        seen.entry(check.rule.as_str()).or_insert(check);
    }
    seen.into_iter()
        .map(|(id, check)| {
            let mut rule = json!({"id": id, "defaultConfiguration": {"level": level(check.severity)}, "properties": {"tags": check.tags}});
            if let Some(title) = &check.title {
                rule["shortDescription"] = json!({"text": title});
            }
            if let Some(docs) = check.docs.as_ref().or(check.references.first().map(|r| &r.url)) {
                rule["helpUri"] = json!(docs);
            }
            if let Some(help) = help(check) {
                rule["help"] = help;
            }
            if let Some(score) = check.score {
                rule["properties"]["security-severity"] = json!(format!("{score:.1}"));
            }
            let related = relationships(id, compliance);
            if !related.is_empty() {
                rule["relationships"] = json!(related);
            }
            rule
        })
        .collect()
}

/// The checks as a SARIF 2.1.0 log: failures, waived failures as suppressed, unknowns as `open`, collector errors as notifications, standards as taxonomies.
pub fn lint_sarif(document: &Value, checks: &[Check], compliance: &[Report]) -> String {
    let meta = &document["meta"];
    let root = match meta["subject"]["kind"].as_str() {
        Some("root") => meta["subject"]["path"].as_str().filter(|p| p.starts_with('/')).map(|p| format!("file://{}/", uri_path(p.trim_end_matches('/')))),
        _ => Some("file:///".to_owned()),
    };
    let base = root.map_or_else(|| json!({"description": {"text": "The root filesystem systemlint read"}}), |uri| json!({"uri": uri}));
    let errors: Vec<Value> = document["collectors"].as_object().into_iter().flatten().filter(|(_, o)| o["status"] == "error").map(|(id, o)| json!({"level": "error", "message": {"text": format!("collector {id}: {}", o["reason"].as_str().unwrap_or_default())}})).collect();
    let mut log = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "systemlint", "version": systemlint_protocol::VERSION, "informationUri": "https://kiota.ch/damian-buho/systemlint", "rules": descriptors(checks, compliance)}},
            "originalUriBaseIds": {"ROOT": base},
            "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": errors, "properties": {"collected-at": meta["collected-at"], "privileged": meta["privileged"]}}],
            "results": checks.iter().filter_map(result).collect::<Vec<_>>(),
            "properties": {"rating": rate(checks)},
        }],
    });
    if !compliance.is_empty() {
        log["runs"][0]["taxonomies"] = json!(taxonomies(compliance));
        log["runs"][0]["properties"]["compliance"] = compliance.iter().map(|r| (r.standard.clone(), json!(r.verdict))).collect::<serde_json::Map<_, _>>().into();
    }
    serde_json::to_string_pretty(&log).unwrap_or_default() + "\n"
}

/// `text` as a Prometheus label value: backslash, quote and newline escaped.
fn label(text: &str) -> String {
    text.replace('\\', r"\\").replace('"', "\\\"").replace('\n', r"\n")
}

/// The serialised name of an outcome or severity, empty for none.
fn name(value: impl serde::Serialize) -> String {
    serde_json::to_value(value).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// The run as node-exporter textfile metrics: counts by outcome, by rule, failures by severity, standards, collector status and privilege.
pub fn lint_textfile(document: &Value, checks: &[Check], compliance: &[Report]) -> String {
    let mut out = String::new();
    let s = summary(checks);
    out.push_str("# HELP systemlint_checks Checks of the last lint run by outcome.\n# TYPE systemlint_checks gauge\n");
    for outcome in ["pass", "fail", "waived", "unknown", "skip"] {
        let _ = writeln!(out, "systemlint_checks{{outcome=\"{outcome}\"}} {}", s[outcome]);
    }
    let mut per_rule = std::collections::BTreeMap::new();
    for check in checks {
        let outcome = if check.outcome == Outcome::Fail && !check.is_failing() { "waived".to_owned() } else { name(check.outcome) };
        *per_rule.entry((check.rule.as_str(), outcome)).or_insert(0_usize) += 1;
    }
    out.push_str("# HELP systemlint_rule_checks Checks of the last lint run by rule and outcome.\n# TYPE systemlint_rule_checks gauge\n");
    for ((rule, outcome), count) in &per_rule {
        let _ = writeln!(out, "systemlint_rule_checks{{rule=\"{}\",outcome=\"{outcome}\"}} {count}", label(rule));
    }
    out.push_str("# HELP systemlint_failures Failing checks of the last lint run by severity, waived ones apart.\n# TYPE systemlint_failures gauge\n");
    for severity in [Severity::Error, Severity::Warning, Severity::Info, Severity::Hint] {
        let _ = writeln!(out, "systemlint_failures{{severity=\"{}\"}} {}", name(severity), checks.iter().filter(|c| c.is_failing() && c.severity == Some(severity)).count());
    }
    if let Some(rating) = rate(checks) {
        out.push_str("# HELP systemlint_rating Share of judged checks the last lint run kept after failure costs, labelled with its grade.\n# TYPE systemlint_rating gauge\n");
        let _ = writeln!(out, "systemlint_rating{{grade=\"{}\"}} {}", rating.grade, rating.score);
    }
    if !compliance.is_empty() {
        let verdicts = [Verdict::Compliant, Verdict::NonCompliant, Verdict::Indeterminate, Verdict::Manual];
        out.push_str("# HELP systemlint_controls Controls of each standard by verdict.\n# TYPE systemlint_controls gauge\n");
        for (report, verdict) in compliance.iter().flat_map(|r| verdicts.map(|v| (r, v))) {
            let _ = writeln!(out, "systemlint_controls{{standard=\"{}\",verdict=\"{}\"}} {}", label(&report.standard), name(verdict), report.controls.iter().filter(|c| c.verdict == verdict).count());
        }
        out.push_str("# HELP systemlint_compliance Whether each standard answered this verdict.\n# TYPE systemlint_compliance gauge\n");
        for (report, verdict) in compliance.iter().flat_map(|r| verdicts[..3].iter().map(move |v| (r, *v))) {
            let _ = writeln!(out, "systemlint_compliance{{standard=\"{}\",verdict=\"{}\"}} {}", label(&report.standard), name(verdict), u8::from(report.verdict == verdict));
        }
    }
    out.push_str("# HELP systemlint_collector_status Whether each collector ended ok, error or skipped.\n# TYPE systemlint_collector_status gauge\n");
    for (id, outcome) in document["collectors"].as_object().into_iter().flatten() {
        for status in ["ok", "error", "skipped"] {
            let _ = writeln!(out, "systemlint_collector_status{{collector=\"{}\",status=\"{status}\"}} {}", label(id), u8::from(outcome["status"] == status));
        }
    }
    out.push_str("# HELP systemlint_privileged Whether the facts were collected as root.\n# TYPE systemlint_privileged gauge\n");
    let _ = writeln!(out, "systemlint_privileged {}", u8::from(document["meta"]["privileged"] == true));
    out
}
