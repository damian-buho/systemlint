// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Judges a facts document: subjects bound by `*`, the `when` guard, `expect`, the four outcomes, scores and waivers.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use jsonschema::paths::Location;
use jsonschema::{Keyword, ValidationError, Validator};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::rules::{Score, Severity, Spec, When, glob};
use crate::version::compare_deb;

/// What one rule found on one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
    Unknown,
}

/// A configured exception to one rule, on every subject or the ones its glob matches, until a day.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub reason: String,
    pub until: String,
}

/// A waiver that matched a failed check, and whether it still holds on the lint day.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Waived {
    pub reason: String,
    pub until: String,
    pub active: bool,
}

/// One rule judged on one subject.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    pub rule: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject: Vec<String>,
    pub fact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiver: Option<Waived>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
}

impl Check {
    /// The subject keys as one string, the form a waiver’s `subject` glob matches.
    pub fn subject_text(&self) -> String {
        self.subject.join(", ")
    }

    /// Whether this check counts against the run: a fail no active waiver covers.
    pub fn is_failing(&self) -> bool {
        self.outcome == Outcome::Fail && !self.waiver.as_ref().is_some_and(|w| w.active)
    }
}

/// One segment of a fact path: a key, or `*` binding a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Key(String),
    Star,
}

/// A dotted path, or a JSON Pointer when it starts with `/`; a `*` segment binds a subject.
pub fn parse_path(text: &str) -> Result<Vec<Segment>, String> {
    let raw: Vec<String> = match text.strip_prefix('/') {
        Some(pointer) => pointer.split('/').map(|s| s.replace("~1", "/").replace("~0", "~")).collect(),
        None => text.split('.').map(str::to_owned).collect(),
    };
    if text.is_empty() || raw.iter().any(String::is_empty) {
        return Err(format!("fact path {text:?} has an empty segment"));
    }
    Ok(raw.into_iter().map(|s| if s == "*" { Segment::Star } else { Segment::Key(s) }).collect())
}

fn stars(path: &[Segment]) -> usize {
    path.iter().filter(|s| **s == Segment::Star).count()
}

fn concrete(path: &[Segment], bound: &[String]) -> Vec<String> {
    let mut keys = bound.iter();
    path.iter().map(|s| match s {
        Segment::Key(k) => k.clone(),
        Segment::Star => keys.next().cloned().unwrap_or_else(|| "*".to_owned()),
    }).collect()
}

fn child<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        Value::Array(items) => key.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    }
}

fn get<'a>(document: &'a Value, keys: &[String]) -> Option<&'a Value> {
    keys.iter().try_fold(document, |value, key| child(value, key))
}

fn children(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Object(map) => Some(map.keys().cloned().collect()),
        Value::Array(items) => Some((0..items.len()).map(|i| i.to_string()).collect()),
        _ => None,
    }
}

/// Every binding of the path’s `*`s present in `document`, or `None` when the path is absent before its first `*`.
fn subjects(document: &Value, path: &[Segment]) -> Option<Vec<Vec<String>>> {
    let last = path.iter().rposition(|s| *s == Segment::Star);
    let prefix = last.map_or(&path[..0], |i| &path[..=i]);
    let mut found = Vec::new();
    walk(document, prefix, Vec::new(), &mut found).then_some(found)
}

fn walk(value: &Value, path: &[Segment], bound: Vec<String>, found: &mut Vec<Vec<String>>) -> bool {
    match path.split_first() {
        None => found.push(bound),
        Some((Segment::Key(key), rest)) => match child(value, key) {
            Some(next) => return walk(next, rest, bound, found),
            None => return !bound.is_empty(),
        },
        Some((Segment::Star, rest)) => {
            let Some(keys) = children(value) else { return !bound.is_empty() };
            for key in keys {
                let next = [bound.clone(), vec![key.clone()]].concat();
                walk(child(value, &key).unwrap_or(&Value::Null), rest, next, found);
            }
        }
    }
    true
}

/// The collector whose `into` covers `keys`, with its outcome.
fn producer<'a>(document: &'a Value, keys: &[String]) -> Option<(&'a String, &'a Value)> {
    document["collectors"].as_object()?.iter().find(|(_, outcome)| {
        let into: Vec<&str> = outcome["into"].as_str().unwrap_or_default().split('.').collect();
        into.iter().zip(keys).all(|(a, b)| a == b) && !into[0].is_empty()
    })
}

/// Why the fact at `keys` is absent, naming the collector that should have produced it.
fn absent(document: &Value, keys: &[String]) -> (String, Option<String>) {
    let path = keys.join(".");
    match producer(document, keys) {
        Some((id, outcome)) if outcome["status"] == "ok" => (format!("{path} is absent from what collector {id} produced"), Some(id.clone())),
        Some((id, outcome)) => (format!("{path} is absent: collector {id} {}: {}", outcome["status"].as_str().unwrap_or("did not finish"), outcome["reason"].as_str().unwrap_or("no reason given")), Some(id.clone())),
        None => (format!("{path} is absent, and no collector produces it"), None),
    }
}

/// `x-version: {scheme: deb, min, below}`: a version at or above `min` and below `below`.
struct XVersion {
    min: Option<String>,
    below: Option<String>,
}

impl XVersion {
    fn holds(&self, instance: &Value) -> bool {
        let Some(version) = instance.as_str() else { return false };
        let at_least = self.min.as_deref().is_none_or(|min| compare_deb(version, min).is_ok_and(|o| o != Ordering::Less));
        let under = self.below.as_deref().is_none_or(|below| compare_deb(version, below).is_ok_and(|o| o == Ordering::Less));
        at_least && under
    }
}

impl<'i> Keyword<'i> for XVersion {
    fn validate(&self, instance: &'i Value) -> Result<(), ValidationError<'i>> {
        if self.holds(instance) {
            return Ok(());
        }
        let bounds = [self.min.as_ref().map(|m| format!("at least {m}")), self.below.as_ref().map(|b| format!("below {b}"))].into_iter().flatten().collect::<Vec<_>>().join(" and ");
        Err(ValidationError::custom(format!("{instance} is not a Debian version {bounds}")))
    }

    fn is_valid(&self, instance: &'i Value) -> bool {
        self.holds(instance)
    }
}

fn x_version<'a>(_parent: &'a Map<String, Value>, value: &'a Value, _path: Location) -> Result<Box<dyn for<'i> Keyword<'i>>, ValidationError<'a>> {
    let bound = |name: &str| -> Result<Option<String>, ValidationError<'a>> {
        match value.get(name) {
            None => Ok(None),
            Some(Value::String(v)) => compare_deb(v, v).map(|_| Some(v.clone())).map_err(ValidationError::custom),
            Some(other) => Err(ValidationError::custom(format!("x-version {name} {other} is not a string"))),
        }
    };
    match value.get("scheme").and_then(Value::as_str) {
        Some("deb") => {}
        Some(other) => return Err(ValidationError::custom(format!("x-version scheme {other} is unknown; deb is the one known"))),
        None => return Err(ValidationError::custom("x-version needs scheme: deb")),
    }
    if let Some(extra) = value.as_object().and_then(|o| o.keys().find(|k| !["scheme", "min", "below"].contains(&k.as_str()))) {
        return Err(ValidationError::custom(format!("x-version has unknown key {extra}")));
    }
    Ok(Box::new(XVersion { min: bound("min")?, below: bound("below")? }))
}

/// A validator for `schema`, with the `x-version` keyword.
pub fn schema(schema: &Map<String, Value>) -> Result<Validator, String> {
    jsonschema::options().with_keyword("x-version", x_version).build(&Value::Object(schema.clone())).map_err(|e| e.to_string())
}

/// A `when` entry: a constant to equal, or a schema object to satisfy.
enum Test {
    Equal(Value),
    Schema(Validator),
}

struct Guard {
    path: Vec<Segment>,
    test: Test,
}

/// A rule ready to judge.
pub struct Rule {
    pub id: String,
    pub spec: Spec,
    fact: Vec<Segment>,
    when: Vec<Vec<Guard>>,
    expect: Validator,
}

/// Compiles one selected rule, refusing a bad path, schema or `when`.
pub fn compile(id: &str, spec: Spec) -> Result<Rule, String> {
    let fail = |e: String| format!("rule {id}: {e}");
    let fact_text = spec.fact.as_deref().ok_or_else(|| fail("has no fact".to_owned()))?;
    let fact = parse_path(fact_text).map_err(fail)?;
    let expect = schema(spec.expect.as_ref().ok_or_else(|| fail("has no expect".to_owned()))?).map_err(|e| fail(format!("expect {e}")))?;
    let branches = match &spec.when {
        None => vec![],
        Some(When::All(map)) => vec![map.clone()],
        Some(When::Any(list)) if list.is_empty() => return Err(fail("when is an empty list".to_owned())),
        Some(When::Any(list)) => list.clone(),
    };
    let mut when = Vec::new();
    for branch in branches {
        let mut guards = Vec::new();
        for (path, expected) in branch {
            let parsed = parse_path(&path).map_err(fail)?;
            if stars(&parsed) > stars(&fact) {
                return Err(fail(format!("when {path} has more * than fact {fact_text}, so it binds no subject")));
            }
            let test = match &expected {
                Value::Object(map) => Test::Schema(schema(map).map_err(|e| fail(format!("when {path}: {e}")))?),
                other => Test::Equal(other.clone()),
            };
            guards.push(Guard { path: parsed, test });
        }
        when.push(guards);
    }
    Ok(Rule { id: id.to_owned(), spec, fact, when, expect })
}

enum Tri {
    True,
    False(String),
    Unknown(String, Option<String>),
}

fn guard(rule: &Rule, document: &Value, bound: &[String]) -> Tri {
    if rule.when.is_empty() {
        return Tri::True;
    }
    let mut unknown = None;
    let mut first_false = None;
    for branch in &rule.when {
        let mut result = Tri::True;
        for g in branch {
            let keys = concrete(&g.path, bound);
            let Some(actual) = get(document, &keys) else {
                if matches!(result, Tri::True) {
                    let (reason, collector) = absent(document, &keys);
                    result = Tri::Unknown(format!("when {reason}"), collector);
                }
                continue;
            };
            let holds = match &g.test {
                Test::Equal(expected) => actual == expected,
                Test::Schema(validator) => validator.is_valid(actual),
            };
            if !holds {
                result = Tri::False(format!("when {} is {}", keys.join("."), describe(Some(actual))));
                break;
            }
        }
        match result {
            Tri::True => return Tri::True,
            Tri::Unknown(..) if unknown.is_none() => unknown = Some(result),
            Tri::False(_) if first_false.is_none() => first_false = Some(result),
            _ => {}
        }
    }
    unknown.or(first_false).unwrap_or(Tri::True)
}

const BANDS: [(Severity, f64, f64, f64); 4] = [(Severity::Error, 6.6, 9.9, 8.0), (Severity::Warning, 3.3, 6.5, 5.0), (Severity::Info, 1.0, 3.2, 2.0), (Severity::Hint, 0.0, 0.9, 0.5)];

/// A score on the one-decimal grid, 0.0 to 9.9.
pub fn round(score: f64) -> f64 {
    ((score * 10.0).round() / 10.0).clamp(0.0, 9.9)
}

/// The level whose band holds the score.
pub fn level_of(score: f64) -> Severity {
    let tenths = round(score);
    BANDS.iter().find(|(_, min, _, _)| tenths >= *min).map_or(Severity::Hint, |b| b.0)
}

fn band(level: Severity) -> (f64, f64, f64) {
    BANDS.iter().find(|b| b.0 == level).map_or((3.3, 6.5, 5.0), |b| (b.1, b.2, b.3))
}

/// The score moved into a level’s band.
pub fn pin(level: Severity, score: f64) -> f64 {
    let (min, max, _) = band(level);
    round(score).clamp(min, max)
}

/// The score between the two curve points around `value`, flat beyond the ends.
pub fn interpolate(curve: &[(f64, f64)], value: f64) -> f64 {
    let mut points = curve.to_vec();
    points.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (Some(first), Some(last)) = (points.first(), points.last()) else { return 0.0 };
    let at = value.clamp(first.0, last.0);
    let index = points.iter().position(|p| p.0 >= at).unwrap_or(0).max(1).min(points.len() - 1);
    let ((x0, y0), (x1, y1)) = (points[index - 1], points[index]);
    if points.len() == 1 || x1 == x0 {
        return round(y1);
    }
    round(y0 + (y1 - y0) * (at - x0) / (x1 - x0))
}

/// The score of a failure on `value`: the fixed number, else the curve over a number, else the level’s base; pinned stays in its band.
pub fn score(spec: &Spec, value: Option<&Value>) -> f64 {
    let level = spec.severity.unwrap_or(Severity::Warning);
    let raw = match (&spec.score, value.and_then(Value::as_f64)) {
        (Some(Score::Fixed(n)), _) => *n,
        (Some(Score::Curve(curve)), Some(v)) => interpolate(curve, v),
        _ => band(level).2,
    };
    if spec.pinned { pin(level, raw) } else { round(raw) }
}

fn elide(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 200 {
        return text.to_owned();
    }
    format!("{}…{}", chars[..100].iter().collect::<String>(), chars[chars.len() - 99..].iter().collect::<String>())
}

/// An offending value as a finding shows it: a string quoted, a list of scalars as words, absent or empty as none.
pub fn describe(value: Option<&Value>) -> String {
    match value {
        None => "none".to_owned(),
        Some(Value::String(s)) => format!("“{}”", elide(s)),
        Some(Value::Array(items)) if items.is_empty() => "none".to_owned(),
        Some(Value::Array(items)) if items.iter().all(|i| i.is_string() || i.is_number()) => elide(&items.iter().map(|i| describe(Some(i))).collect::<Vec<_>>().join(", ")),
        Some(Value::Array(items)) => format!("{} items", items.len()),
        Some(other) => {
            let json = other.to_string();
            if json.chars().count() > 80 { format!("{}…", json.chars().take(77).collect::<String>()) } else { json }
        }
    }
}

fn fill(template: &str, variables: &BTreeMap<String, String>) -> String {
    variables.iter().fold(template.to_owned(), |text, (name, value)| text.replace(&format!("{{{name}}}"), value))
}

fn base(rule: &Rule, outcome: Outcome, bound: &[String]) -> Check {
    Check {
        rule: rule.id.clone(),
        outcome,
        subject: bound.to_vec(),
        fact: concrete(&rule.fact, bound).join("."),
        severity: None,
        score: None,
        message: None,
        text: None,
        variables: BTreeMap::new(),
        value: None,
        reason: None,
        collector: None,
        waiver: None,
        tags: rule.spec.tags.clone(),
        fix: None,
        docs: rule.spec.docs.clone(),
    }
}

fn check(rule: &Rule, document: &Value, bound: &[String]) -> Check {
    match guard(rule, document, bound) {
        Tri::False(reason) => return Check { reason: Some(reason), ..base(rule, Outcome::Skip, bound) },
        Tri::Unknown(reason, collector) => return Check { reason: Some(reason), collector, ..base(rule, Outcome::Unknown, bound) },
        Tri::True => {}
    }
    let keys = concrete(&rule.fact, bound);
    let Some(value) = get(document, &keys) else {
        let (reason, collector) = absent(document, &keys);
        return Check { reason: Some(reason), collector, ..base(rule, Outcome::Unknown, bound) };
    };
    let Err(error) = rule.expect.validate(value) else {
        return base(rule, Outcome::Pass, bound);
    };
    let pointer = error.instance_path().as_str().to_owned();
    let got = describe(value.pointer(&pointer));
    let field = pointer.rsplit('/').next().filter(|f| !f.is_empty()).map_or_else(|| keys.last().cloned().unwrap_or_default(), str::to_owned);
    let subject = bound.join(", ");
    let variables: BTreeMap<String, String> = [("got", got), ("field", field), ("fact", keys.join(".")), ("subject", if subject.is_empty() { "<subject>".to_owned() } else { subject })].into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    let message = match &rule.spec.message {
        Some(template) => fill(template, &variables),
        None => format!("{}{pointer}: {error}", keys.join(".")),
    };
    let score = score(&rule.spec, value.pointer(&pointer));
    log::debug!("rule {} fails on {:?} with score {score}", rule.id, bound);
    Check {
        severity: Some(level_of(score)),
        score: Some(score),
        message: Some(message),
        fix: rule.spec.fix.as_ref().map(|f| fill(f, &variables)),
        text: rule.spec.message.clone(),
        variables: if rule.spec.message.is_some() { variables } else { BTreeMap::new() },
        value: Some(value.clone()),
        ..base(rule, Outcome::Fail, bound)
    }
}

/// Every check of `rule` on `document`, one per subject; none when its subjects exist and are empty.
pub fn judge(rule: &Rule, document: &Value) -> Vec<Check> {
    let Some(bindings) = subjects(document, &rule.fact) else {
        let last = rule.fact.iter().position(|s| *s == Segment::Star).unwrap_or(rule.fact.len());
        let keys = concrete(&rule.fact[..last], &[]);
        let (reason, collector) = absent(document, &keys);
        log::debug!("rule {} has no subjects: {reason}", rule.id);
        return vec![Check { reason: Some(reason), collector, ..base(rule, Outcome::Unknown, &[]) }];
    };
    log::debug!("rule {} judges {} subjects", rule.id, bindings.len());
    bindings.iter().map(|bound| check(rule, document, bound)).collect()
}

/// Every check of every rule, with the first matching waiver attached to each failure, active through its `until` day.
pub fn lint(document: &Value, rules: &[Rule], waivers: &[Waiver], today: &str) -> Vec<Check> {
    let mut checks: Vec<Check> = rules.iter().flat_map(|rule| judge(rule, document)).collect();
    for check in checks.iter_mut().filter(|c| c.outcome == Outcome::Fail) {
        let subject = check.subject_text();
        if let Some(waiver) = waivers.iter().find(|w| glob(&w.rule, &check.rule) && w.subject.as_deref().is_none_or(|s| glob(s, &subject))) {
            let active = today <= waiver.until.as_str();
            log::debug!("rule {} on {subject:?} waived until {} (active {active})", check.rule, waiver.until);
            check.waiver = Some(Waived { reason: waiver.reason.clone(), until: waiver.until.clone(), active });
        }
    }
    checks
}

/// Checks a waiver’s `until` is a `YYYY-MM-DD` day.
pub fn valid_day(day: &str) -> bool {
    let b = day.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}
