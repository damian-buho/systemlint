// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Lint and compliance output, human or JSON, and the `--fail-on` threshold.

use std::fmt::Write;
use std::str::FromStr;

use serde_json::{Value, json};

use crate::comply::{Report, Verdict};
use crate::judge::{Check, Outcome};
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

fn about(check: &Check) -> String {
    if check.subject.is_empty() { check.rule.clone() } else { format!("{} {}", check.rule, check.subject_text()) }
}

/// One line per failure and unknown, then the counts unless `quiet`.
pub fn lint_human(checks: &[Check], quiet: bool) -> String {
    let mut out = String::new();
    for check in checks {
        match (check.outcome, &check.waiver) {
            (Outcome::Fail, Some(w)) if w.active => {
                let _ = writeln!(out, "waived {}: {} ({}, until {})", about(check), check.message.as_deref().unwrap_or_default(), w.reason, w.until);
            }
            (Outcome::Fail, waiver) => {
                let severity = serde_json::to_value(check.severity).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
                let _ = writeln!(out, "{severity} {}: {}", about(check), check.message.as_deref().unwrap_or_default());
                if let Some(w) = waiver {
                    let _ = writeln!(out, "  waiver expired on {}: {}", w.until, w.reason);
                }
                if let Some(fix) = &check.fix {
                    let _ = writeln!(out, "  fix: {fix}");
                }
            }
            (Outcome::Unknown, _) => {
                let _ = writeln!(out, "unknown {}: {}", about(check), check.reason.as_deref().unwrap_or_default());
            }
            _ => {}
        }
    }
    if !quiet {
        let s = summary(checks);
        let _ = writeln!(out, "{} checks: {} pass, {} fail, {} waived, {} unknown, {} skip", s["checks"], s["pass"], s["fail"], s["waived"], s["unknown"], s["skip"]);
    }
    out
}

/// The `meta` of the facts, every check and the counts, as indented JSON.
pub fn lint_json(document: &Value, checks: &[Check]) -> String {
    let report = json!({"meta": document["meta"], "checks": checks, "summary": summary(checks)});
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

/// The descriptor of every rule the checks name: tags, docs, default level and `security-severity` from the score.
fn descriptors(checks: &[Check]) -> Vec<Value> {
    let mut seen = std::collections::BTreeMap::new();
    for check in checks {
        seen.entry(check.rule.as_str()).or_insert(check);
    }
    seen.into_iter()
        .map(|(id, check)| {
            let mut rule = json!({"id": id, "defaultConfiguration": {"level": level(check.severity)}, "properties": {"tags": check.tags}});
            if let Some(docs) = &check.docs {
                rule["helpUri"] = json!(docs);
            }
            if let Some(score) = check.score {
                rule["properties"]["security-severity"] = json!(format!("{score:.1}"));
            }
            rule
        })
        .collect()
}

/// The checks as a SARIF 2.1.0 log: failures, waived failures as suppressed, unknowns as `open`, collector errors as notifications.
pub fn lint_sarif(document: &Value, checks: &[Check]) -> String {
    let meta = &document["meta"];
    let root = match meta["subject"]["kind"].as_str() {
        Some("root") => meta["subject"]["path"].as_str().filter(|p| p.starts_with('/')).map(|p| format!("file://{}/", uri_path(p.trim_end_matches('/')))),
        _ => Some("file:///".to_owned()),
    };
    let base = root.map_or_else(|| json!({"description": {"text": "The root filesystem systemlint read"}}), |uri| json!({"uri": uri}));
    let errors: Vec<Value> = document["collectors"].as_object().into_iter().flatten().filter(|(_, o)| o["status"] == "error").map(|(id, o)| json!({"level": "error", "message": {"text": format!("collector {id}: {}", o["reason"].as_str().unwrap_or_default())}})).collect();
    let log = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "systemlint", "version": systemlint_protocol::VERSION, "informationUri": "https://kiota.ch/damian-buho/systemlint", "rules": descriptors(checks)}},
            "originalUriBaseIds": {"ROOT": base},
            "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": errors, "properties": {"collected-at": meta["collected-at"], "privileged": meta["privileged"]}}],
            "results": checks.iter().filter_map(result).collect::<Vec<_>>(),
        }],
    });
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

/// The run as node-exporter textfile metrics: counts by outcome, by rule, failures by severity, collector status and privilege.
pub fn lint_textfile(document: &Value, checks: &[Check]) -> String {
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

fn word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Compliant => "compliant",
        Verdict::NonCompliant => "non-compliant",
        Verdict::Indeterminate => "indeterminate",
        Verdict::Manual => "manual",
    }
}

/// The verdict, then one row per control with the reasons under it.
pub fn comply_human(report: &Report) -> String {
    let mut out = format!("{}: {}\n", report.name, word(report.verdict));
    let width = report.controls.iter().map(|c| c.id.chars().count()).max().unwrap_or(0);
    for control in &report.controls {
        let row = format!("  {:width$}  {:13}  {}", control.id, word(control.verdict), control.title.as_deref().unwrap_or_default());
        let _ = writeln!(out, "{}", row.trim_end());
        for reason in &control.reasons {
            let _ = writeln!(out, "  {:width$}    {reason}", "");
        }
    }
    if let Some(c) = &report.coverage {
        let _ = writeln!(out, "coverage: {} of {} controls", c.covered, c.total);
    }
    if let Some(note) = &report.note {
        let _ = writeln!(out, "note: {note}");
    }
    out
}

/// The compliance answer as indented JSON.
pub fn comply_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default() + "\n"
}
