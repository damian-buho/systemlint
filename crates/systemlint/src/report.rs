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
