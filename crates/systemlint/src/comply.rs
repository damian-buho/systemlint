// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Compliance: checks grouped by the controls their rules are tagged with, against an optional catalog.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::discovery::{Refusal, Trust};
use crate::judge::{Check, Outcome, Rule};

/// A standard’s catalog: its display name and every control.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub controls: Vec<Control>,
}

/// One control a catalog lists.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub manual: bool,
}

/// The answer for one control or the whole standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Compliant,
    NonCompliant,
    Indeterminate,
    Manual,
    NotApplicable,
}

impl Verdict {
    /// The exit code of `lint --standard` answering this: 0 compliant or not applicable, 1 non-compliant, 3 indeterminate or manual.
    pub fn code(self) -> u8 {
        match self {
            Self::Compliant | Self::NotApplicable => 0,
            Self::NonCompliant => 1,
            Self::Indeterminate | Self::Manual => 3,
        }
    }
}

/// One row of the per-control table.
#[derive(Debug, Clone, Serialize)]
pub struct ControlResult {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub verdict: Verdict,
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// How many catalog controls a rule covers.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub covered: usize,
    pub total: usize,
}

/// The whole compliance answer.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub standard: String,
    pub name: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
    pub controls: Vec<ControlResult>,
}

/// The directories to search for catalogs, in order: each rules directory, then its `standards` sibling.
pub fn directories(rule_dirs: &[PathBuf]) -> Vec<PathBuf> {
    rule_dirs.iter().flat_map(|d| [d.clone(), d.parent().unwrap_or(Path::new("/")).join("standards")]).collect()
}

/// The catalog `<standard>.yaml` from the first trusted directory holding one that is no ruleset, if any.
pub fn catalog(dirs: &[PathBuf], trust: &Trust, standard: &str) -> (Result<Option<Catalog>, String>, Vec<Refusal>) {
    let (texts, refusals) = crate::discovery::yaml_files(dirs, trust);
    let ruleset = |text: &str| crate::yaml::from_str::<crate::rules::Ruleset>(text).is_ok();
    let Some((path, text)) = texts.into_iter().find(|(p, t)| p.file_stem().is_some_and(|s| s == standard) && !ruleset(t)) else {
        log::debug!("no catalog for standard {standard}");
        return (Ok(None), refusals);
    };
    log::debug!("catalog of standard {standard} from {}", path.display());
    let parsed = crate::yaml::from_str::<Catalog>(&text).map(Some).map_err(|e| format!("{} is not a valid catalog: {e}", path.display()));
    (parsed, refusals)
}

/// The verdict over several standards: non-compliant beats indeterminate beats compliant, not applicable only when every standard is.
pub fn overall(reports: &[Report]) -> Verdict {
    let any = |v: Verdict| reports.iter().any(|r| r.verdict == v);
    let verdict = if any(Verdict::NonCompliant) {
        Verdict::NonCompliant
    } else if reports.is_empty() || any(Verdict::Indeterminate) || any(Verdict::Manual) {
        Verdict::Indeterminate
    } else if reports.iter().all(|r| r.verdict == Verdict::NotApplicable) {
        Verdict::NotApplicable
    } else {
        Verdict::Compliant
    };
    log::debug!("{} standards answer {verdict:?}", reports.len());
    verdict
}

/// The control IDs of `standard` a rule is tagged with.
fn controls_of<'a>(tags: &'a [String], standard: &str) -> impl Iterator<Item = &'a str> {
    let prefix = format!("{standard}:");
    tags.iter().filter_map(move |t| t.strip_prefix(prefix.as_str()))
}

fn judge(id: &str, title: Option<String>, rules: &[&Rule], checks: &[Check]) -> ControlResult {
    let ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
    let mine: Vec<&Check> = checks.iter().filter(|c| ids.contains(&c.rule)).collect();
    let failing: Vec<String> = mine.iter().filter(|c| c.is_failing()).map(|c| format!("{} {}: {}", c.rule, c.subject_text(), c.message.as_deref().unwrap_or_default())).collect();
    let unknown: Vec<String> = mine.iter().filter(|c| c.outcome == Outcome::Unknown).map(|c| format!("{}: {}", c.rule, c.reason.as_deref().unwrap_or_default())).collect();
    let manual: Vec<String> = mine.iter().filter(|c| c.outcome == Outcome::Manual).map(|c| c.title.as_ref().map_or_else(|| c.rule.clone(), |t| format!("{}: {t}", c.rule))).collect();
    let mut inapplicable: Vec<String> = mine.iter().filter(|c| c.outcome == Outcome::NotApplicable).filter_map(|c| c.reason.clone()).collect();
    inapplicable.sort();
    inapplicable.dedup();
    let (verdict, reasons) = if !failing.is_empty() {
        (Verdict::NonCompliant, failing)
    } else if !unknown.is_empty() {
        (Verdict::Indeterminate, unknown)
    } else if !manual.is_empty() {
        (Verdict::Manual, manual)
    } else if mine.iter().all(|c| c.outcome == Outcome::NotApplicable) {
        (Verdict::NotApplicable, if inapplicable.is_empty() { vec!["no rule binds a subject".to_owned()] } else { inapplicable })
    } else {
        (Verdict::Compliant, vec![])
    };
    log::debug!("control {id}: {verdict:?} from {} rules and {} checks", ids.len(), mine.len());
    ControlResult { id: id.to_owned(), title, verdict, rules: ids, reasons }
}

/// The compliance answer for `standard` from the tagged `rules` and their `checks`.
pub fn comply(standard: &str, rules: &[Rule], checks: &[Check], catalog: Option<&Catalog>) -> Report {
    let mut tagged: Vec<String> = rules.iter().flat_map(|r| controls_of(&r.spec.tags, standard).map(str::to_owned)).collect();
    tagged.sort();
    tagged.dedup();
    let covering = |control: &str| -> Vec<&Rule> { rules.iter().filter(|r| controls_of(&r.spec.tags, standard).any(|c| c == control)).collect() };
    let mut controls = Vec::new();
    if let Some(catalog) = catalog {
        for control in &catalog.controls {
            let rules = covering(&control.id);
            controls.push(match (rules.is_empty(), control.manual) {
                (true, true) => ControlResult { id: control.id.clone(), title: control.title.clone(), verdict: Verdict::Manual, rules: vec![], reasons: vec![] },
                (true, false) => ControlResult { id: control.id.clone(), title: control.title.clone(), verdict: Verdict::Indeterminate, rules: vec![], reasons: vec!["no rule covers it".to_owned()] },
                _ => judge(&control.id, control.title.clone(), &rules, checks),
            });
        }
    }
    for id in tagged.iter().filter(|id| catalog.is_none_or(|c| !c.controls.iter().any(|k| &k.id == *id))) {
        let mut row = judge(id, None, &covering(id), checks);
        if catalog.is_some() {
            log::debug!("control {id} of {standard} is tagged but not in the catalog");
            row.reasons.push("not in the catalog".to_owned());
        }
        controls.push(row);
    }
    let verdict = if controls.iter().any(|c| c.verdict == Verdict::NonCompliant) {
        Verdict::NonCompliant
    } else if controls.is_empty() || controls.iter().any(|c| c.verdict == Verdict::Indeterminate) {
        Verdict::Indeterminate
    } else if controls.iter().all(|c| c.verdict == Verdict::NotApplicable) {
        Verdict::NotApplicable
    } else {
        Verdict::Compliant
    };
    let note = match catalog {
        None if controls.is_empty() => Some(format!("no rule is tagged {standard}:*, and there is no catalog of {standard}")),
        None => Some(format!("there is no catalog of {standard}, so compliant only means no rule tagged {standard}:* failed")),
        Some(_) => None,
    };
    let coverage = catalog.map(|c| Coverage { covered: controls[..c.controls.len()].iter().filter(|k| !k.rules.is_empty() && k.verdict != Verdict::NotApplicable).count(), total: c.controls.len() });
    let name = catalog.and_then(|c| c.name.clone()).unwrap_or_else(|| standard.to_owned());
    log::debug!("standard {standard}: {verdict:?} over {} controls", controls.len());
    Report { standard: standard.to_owned(), name, verdict, note, coverage, controls }
}
