// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Judges a facts document: ruleset applicability, subjects bound by `*`, the `when` guard, `expect`, the outcomes, scores and waivers.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use jsonschema::paths::Location;
use jsonschema::{Keyword, ValidationError, Validator};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::rules::{Facts, Member, Reference, Score, Severity, Spec, When, glob};
use crate::version::Scheme;

/// What one rule found on one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
    Unknown,
    NotApplicable,
    Manual,
    Conflict,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
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
    pub remedy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
}

impl Check {
    /// The subject keys as one string, the form a waiver’s `subject` glob matches beside the label.
    pub fn subject_text(&self) -> String {
        self.subject.join(", ")
    }

    /// The subject as a report shows it and `{subject}` fills in: its last key, the one that names the thing.
    pub fn subject_label(&self) -> String {
        self.subject.last().cloned().unwrap_or_default()
    }

    /// The message without the whole subject label it opens with, or `None` when it opens with none.
    pub fn unsubjected(&self) -> Option<&str> {
        let message = self.message.as_deref()?;
        message
            .strip_prefix(&self.subject_label())
            .and_then(|m| m.strip_prefix(' '))
            .filter(|_| !self.subject.is_empty())
    }

    /// Whether this check counts against the run: a fail no active waiver covers.
    pub fn is_failing(&self) -> bool {
        self.outcome == Outcome::Fail && !self.waiver.as_ref().is_some_and(|w| w.active)
    }
}

/// One segment of a fact path: a key, `*` binding a subject, or `{path}`, the key another fact’s value names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Key(String),
    Star,
    From(Vec<Segment>),
}

/// `text` split on `separator` outside braces.
fn split_outside_braces(text: &str, separator: char) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0usize, 0);
    for (i, c) in text.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            c if c == separator && depth == 0 => {
                parts.push(&text[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// A dotted path, or a JSON Pointer when it starts with `/`; a `*` segment binds a subject, a `{path}` segment reads its key from that fact.
pub fn parse_path(text: &str) -> Result<Vec<Segment>, String> {
    let raw: Vec<String> = match text.strip_prefix('/') {
        Some(pointer) => split_outside_braces(pointer, '/')
            .into_iter()
            .map(|s| match s.starts_with('{') {
                true => s.to_owned(),
                false => s.replace("~1", "/").replace("~0", "~"),
            })
            .collect(),
        None => split_outside_braces(text, '.')
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
    if text.is_empty() || raw.iter().any(String::is_empty) {
        return Err(format!("fact path {text:?} has an empty segment"));
    }
    raw.into_iter()
        .map(
            |s| match s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
                Some(inner) => parse_path(inner).map(Segment::From),
                None if s == "*" => Ok(Segment::Star),
                None if s.contains(['{', '}']) => Err(format!(
                    "fact path {text:?} has an unbalanced brace in {s:?}"
                )),
                None => Ok(Segment::Key(s)),
            },
        )
        .collect()
}

/// The `*`s a path binds: its own, or a `{path}` segment’s when that holds more.
fn stars(path: &[Segment]) -> usize {
    let own = path.iter().filter(|s| **s == Segment::Star).count();
    path.iter()
        .filter_map(|s| match s {
            Segment::From(inner) => Some(stars(inner)),
            _ => None,
        })
        .fold(own, usize::max)
}

fn joins(path: &[Segment]) -> bool {
    path.iter().any(|s| matches!(s, Segment::From(_)))
}

/// The keys of `path` on `bound`, each `{path}` replaced by the string or number at it; `Err` holds the keys of the first such fact that names no key.
fn resolve(
    document: &Value,
    path: &[Segment],
    bound: &[String],
) -> Result<Vec<String>, Vec<String>> {
    let mut stars = bound.iter();
    let mut keys = Vec::new();
    for segment in path {
        keys.push(match segment {
            Segment::Key(k) => k.clone(),
            Segment::Star => stars.next().cloned().unwrap_or_else(|| "*".to_owned()),
            Segment::From(inner) => {
                let at = resolve(document, inner, bound)?;
                match get(document, &at) {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Number(n)) => n.to_string(),
                    _ => {
                        log::trace!("{} names no key under {bound:?}", at.join("."));
                        return Err(at);
                    }
                }
            }
        });
    }
    Ok(keys)
}

/// The keys of a path without `{path}` segments on `bound`.
fn concrete(path: &[Segment], bound: &[String]) -> Vec<String> {
    let mut keys = bound.iter();
    path.iter()
        .map(|s| match s {
            Segment::Key(k) => k.clone(),
            Segment::Star => keys.next().cloned().unwrap_or_else(|| "*".to_owned()),
            Segment::From(_) => unreachable!("a binding path holds no {{path}} segment"),
        })
        .collect()
}

fn child<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        Value::Array(items) => key.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    }
}

fn get<'a>(document: &'a Value, keys: &[String]) -> Option<&'a Value> {
    keys.iter()
        .try_fold(document, |value, key| child(value, key))
}

fn children(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Object(map) => Some(map.keys().cloned().collect()),
        Value::Array(items) => Some((0..items.len()).map(|i| i.to_string()).collect()),
        _ => None,
    }
}

/// Every binding of the path’s `*`s present in `document` or owed by a collector, or `None` when the path is absent before its first `*`.
fn subjects(document: &Value, path: &[Segment]) -> Option<Vec<Vec<String>>> {
    let last = path.iter().rposition(|s| *s == Segment::Star);
    let prefix = last.map_or(&path[..0], |i| &path[..=i]);
    let mut found = Vec::new();
    walk(document, document, prefix, &[], Vec::new(), &mut found).then_some(found)
}

fn walk(
    document: &Value,
    value: &Value,
    path: &[Segment],
    at: &[String],
    bound: Vec<String>,
    found: &mut Vec<Vec<String>>,
) -> bool {
    let Some((segment, rest)) = path.split_first() else {
        found.push(bound);
        return true;
    };
    let keys = match segment {
        Segment::Key(key) => child(value, key).map(|_| vec![key.clone()]),
        Segment::From(_) => unreachable!("a binding path holds no {{path}} segment"),
        Segment::Star => children(value).map(|mut keys| {
            for owed in owed(document, at) {
                if !keys.contains(&owed) {
                    log::trace!(
                        "{} owes key {owed} under {}",
                        owed_by(document, at, &owed),
                        at.join(".")
                    );
                    keys.push(owed);
                }
            }
            keys.sort();
            keys
        }),
    };
    let Some(keys) = keys else {
        log::trace!("{} is absent under subject {bound:?}", at.join("."));
        if bound.is_empty() {
            return false;
        }
        found.push(bound);
        return true;
    };
    for key in keys {
        let next = if *segment == Segment::Star {
            [bound.clone(), vec![key.clone()]].concat()
        } else {
            bound.clone()
        };
        let present = walk(
            document,
            child(value, &key).unwrap_or(&Value::Null),
            rest,
            &[at, std::slice::from_ref(&key)].concat(),
            next,
            found,
        );
        // A key below a present parent may still be absent before the first `*`.
        if !present && *segment != Segment::Star {
            return false;
        }
    }
    true
}

/// The keys collectors’ `into` places directly under `at`, present or not, and the paths a collector into `at` could not read.
fn owed<'a>(document: &'a Value, at: &'a [String]) -> impl Iterator<Item = String> + 'a {
    document["collectors"]
        .as_object()
        .into_iter()
        .flatten()
        .flat_map(move |(_, outcome)| {
            let into: Vec<&str> = outcome["into"]
                .as_str()
                .unwrap_or_default()
                .split('.')
                .collect();
            let under = into.iter().zip(at).all(|(a, b)| a == b);
            let placed = (under && into.len() == at.len() + 1).then(|| into[at.len()].to_owned());
            let refused = outcome["unreadable"]
                .as_object()
                .filter(|_| under && into.len() == at.len())
                .into_iter()
                .flat_map(|paths| paths.keys().cloned());
            placed.into_iter().chain(refused)
        })
}

fn owed_by(document: &Value, at: &[String], key: &str) -> String {
    producer(document, &[at, &[key.to_owned()]].concat())
        .map_or_else(String::new, |(id, _)| format!("collector {id}"))
}

/// The collector whose `into` covers `keys`, with its outcome.
fn producer<'a>(document: &'a Value, keys: &[String]) -> Option<(&'a String, &'a Value)> {
    document["collectors"]
        .as_object()?
        .iter()
        .find(|(_, outcome)| {
            let into: Vec<&str> = outcome["into"]
                .as_str()
                .unwrap_or_default()
                .split('.')
                .collect();
            into.iter().zip(keys).all(|(a, b)| a == b) && !into[0].is_empty()
        })
}

/// Why the fact at `keys` is absent, naming the collector that should have produced it.
fn absent(document: &Value, keys: &[String]) -> (String, Option<String>) {
    let path = keys.join(".");
    let refused = producer(document, keys).and_then(|(id, outcome)| {
        let file = keys.get(outcome["into"].as_str()?.split('.').count())?;
        Some((id, file, outcome["unreadable"][file].as_str()?))
    });
    if let Some((id, file, why)) = refused {
        return (
            format!("{path} is absent: collector {id} can’t read {file}: {why}"),
            Some(id.clone()),
        );
    }
    match producer(document, keys) {
        Some((id, outcome)) if outcome["status"] == "ok" => (
            format!("{path} is absent from what collector {id} produced"),
            Some(id.clone()),
        ),
        Some((id, outcome)) => (
            format!(
                "{path} is absent: collector {id} {}: {}",
                outcome["status"].as_str().unwrap_or("did not finish"),
                outcome["reason"].as_str().unwrap_or("no reason given")
            ),
            Some(id.clone()),
        ),
        None => (
            format!("{path} is absent, and no collector produces it"),
            None,
        ),
    }
}

/// `x-version: {scheme, min, below}`: a version at or above `min` and below `below` in the scheme’s order.
struct XVersion {
    scheme: Scheme,
    min: Option<String>,
    below: Option<String>,
}

impl XVersion {
    fn holds(&self, instance: &Value) -> bool {
        let Some(version) = instance.as_str() else {
            return false;
        };
        let at_least = self.min.as_deref().is_none_or(|min| {
            self.scheme
                .compare(version, min)
                .is_ok_and(|o| o != Ordering::Less)
        });
        let under = self.below.as_deref().is_none_or(|below| {
            self.scheme
                .compare(version, below)
                .is_ok_and(|o| o == Ordering::Less)
        });
        at_least && under
    }
}

impl<'i> Keyword<'i> for XVersion {
    fn validate(&self, instance: &'i Value) -> Result<(), ValidationError<'i>> {
        if self.holds(instance) {
            return Ok(());
        }
        let bounds = [
            self.min.as_ref().map(|m| format!("at least {m}")),
            self.below.as_ref().map(|b| format!("below {b}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" and ");
        Err(ValidationError::custom(format!(
            "{instance} is not {} {bounds}",
            self.scheme.noun()
        )))
    }

    fn is_valid(&self, instance: &'i Value) -> bool {
        self.holds(instance)
    }
}

fn x_version<'a>(
    _parent: &'a Map<String, Value>,
    value: &'a Value,
    _path: Location,
) -> Result<Box<dyn for<'i> Keyword<'i>>, ValidationError<'a>> {
    let known = Scheme::ALL.map(Scheme::name).join(", ");
    let scheme = match value.get("scheme").and_then(Value::as_str) {
        Some(name) => Scheme::parse(name).ok_or_else(|| {
            ValidationError::custom(format!(
                "x-version scheme {name} is unknown; the known ones are {known}"
            ))
        })?,
        None => {
            return Err(ValidationError::custom(format!(
                "x-version needs a scheme: {known}"
            )));
        }
    };
    let bound = |name: &str| -> Result<Option<String>, ValidationError<'a>> {
        match value.get(name) {
            None => Ok(None),
            Some(Value::String(v)) => scheme
                .compare(v, v)
                .map(|_| Some(v.clone()))
                .map_err(ValidationError::custom),
            Some(other) => Err(ValidationError::custom(format!(
                "x-version {name} {other} is not a string"
            ))),
        }
    };
    if let Some(extra) = value.as_object().and_then(|o| {
        o.keys()
            .find(|k| !["scheme", "min", "below"].contains(&k.as_str()))
    }) {
        return Err(ValidationError::custom(format!(
            "x-version has unknown key {extra}"
        )));
    }
    Ok(Box::new(XVersion {
        scheme,
        min: bound("min")?,
        below: bound("below")?,
    }))
}

/// A validator for `schema`, with the `x-version` keyword.
pub fn schema(schema: &Map<String, Value>) -> Result<Validator, String> {
    jsonschema::options()
        .with_keyword("x-version", x_version)
        .build(&Value::Object(schema.clone()))
        .map_err(|e| e.to_string())
}

/// A `when` entry: a constant to equal, or a schema object to satisfy and the property names it reads.
enum Test {
    Equal(Value),
    Schema(Validator, Vec<String>),
}

/// Adds the property names `schema` reads or requires to `out`, its `anyOf`, `oneOf`, `allOf` and `not` branches included, first seen first.
fn named(schema: &Value, out: &mut Vec<String>) {
    let required = schema["required"].as_array().into_iter().flatten();
    for key in schema["properties"]
        .as_object()
        .into_iter()
        .flat_map(|p| p.keys().map(String::as_str))
        .chain(required.filter_map(Value::as_str))
    {
        if !out.iter().any(|o| o == key) {
            out.push(key.to_owned());
        }
    }
    for branch in ["anyOf", "oneOf", "allOf"]
        .iter()
        .filter_map(|k| schema[*k].as_array())
        .flatten()
        .chain(schema.get("not"))
    {
        named(branch, out);
    }
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
    keys: Option<Validator>,
    suggest: Option<(Vec<Segment>, String)>,
    same: Option<Vec<Segment>>,
    applies: Vec<(String, Vec<Vec<Guard>>)>,
    when: Vec<Vec<Guard>>,
    members: Vec<(Vec<Segment>, Validator)>,
    combine: Combine,
}

impl Rule {
    /// The value `up` keys above the fact a check of `subject` judged: 1 is the object holding it.
    pub fn subject_value<'a>(
        &self,
        document: &'a Value,
        subject: &[String],
        up: usize,
    ) -> Option<&'a Value> {
        let keys = concrete(&self.fact, subject);
        get(document, &keys[..keys.len().checked_sub(up)?])
    }
}

/// How a rule’s facts combine: every one must satisfy its schema, any one, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Combine {
    All,
    Any,
    None,
}

/// The branches of a `when`, each path holding at most `most` `*`s.
fn guards(when: Option<&When>, most: usize, over: &str) -> Result<Vec<Vec<Guard>>, String> {
    let branches = match when {
        None => vec![],
        Some(When::All(map)) => vec![map.clone()],
        Some(When::Any(list)) if list.is_empty() => return Err("when is an empty list".to_owned()),
        Some(When::Any(list)) => list.clone(),
    };
    let mut when = Vec::new();
    for branch in branches {
        let mut guards = Vec::new();
        for (path, expected) in branch {
            let parsed = parse_path(&path)?;
            if stars(&parsed) > most {
                return Err(format!(
                    "when {path} has more * than {over}, so it binds no subject"
                ));
            }
            let test = match &expected {
                Value::Object(map) => {
                    let mut names = Vec::new();
                    named(&expected, &mut names);
                    Test::Schema(schema(map).map_err(|e| format!("when {path}: {e}"))?, names)
                }
                other => Test::Equal(other.clone()),
            };
            guards.push(Guard { path: parsed, test });
        }
        when.push(guards);
    }
    Ok(when)
}

/// Compiles one selected rule, refusing a bad path, schema or `when`, its rulesets’ included.
pub fn compile(id: &str, spec: Spec) -> Result<Rule, String> {
    let fail = |e: String| format!("rule {id}: {e}");
    spec.remedy
        .as_ref()
        .map_or(Ok(()), crate::fix::Remedy::validate)
        .map_err(fail)?;
    let applies = spec
        .applies
        .iter()
        .map(|(name, when)| {
            guards(Some(when), 0, "a ruleset, which has no subject")
                .map(|g| (name.clone(), g))
                .map_err(|e| fail(format!("ruleset {name}: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if spec.manual {
        log::debug!("rule {id} is manual");
        return Ok(Rule {
            id: id.to_owned(),
            spec,
            fact: vec![],
            keys: None,
            suggest: None,
            same: None,
            applies,
            when: vec![],
            members: vec![],
            combine: Combine::All,
        });
    }
    if spec.unique && spec.facts.is_some() {
        return Err(fail(
            "is unique, which compares one fact across subjects, so it takes no facts".to_owned(),
        ));
    }
    if spec.same.is_some() && spec.facts.is_some() {
        return Err(fail(
            "has same, which compares its one fact to another, so it takes no facts".to_owned(),
        ));
    }
    let (combine, written): (Combine, Vec<Member>) = match (&spec.facts, &spec.fact, &spec.expect) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err(fail(
                "has facts, so it takes no fact or expect of its own".to_owned(),
            ));
        }
        (Some(Facts::All(m)), ..) => (Combine::All, m.clone()),
        (Some(Facts::Any(m)), ..) => (Combine::Any, m.clone()),
        (Some(Facts::None(m)), ..) => (Combine::None, m.clone()),
        (None, Some(fact), Some(expect)) => (
            Combine::All,
            vec![Member {
                fact: fact.clone(),
                expect: expect.clone(),
            }],
        ),
        (None, Some(fact), None) if spec.unique || spec.same.is_some() => (
            Combine::All,
            vec![Member {
                fact: fact.clone(),
                expect: Map::new(),
            }],
        ),
        (None, None, _) => return Err(fail("has no fact".to_owned())),
        (None, Some(_), None) => return Err(fail("has no expect".to_owned())),
    };
    let Some(fact_text) = written.first().map(|m| m.fact.clone()) else {
        return Err(fail("facts lists no fact".to_owned()));
    };
    let mut members = Vec::new();
    for m in &written {
        let path = parse_path(&m.fact).map_err(fail)?;
        let validator = schema(&m.expect).map_err(|e| {
            fail(if spec.facts.is_some() {
                format!("facts {}: expect {e}", m.fact)
            } else {
                format!("expect {e}")
            })
        })?;
        members.push((path, validator));
    }
    let fact = members[0].0.clone();
    if joins(&fact) {
        return Err(fail(format!(
            "fact {fact_text} binds the subjects, so it takes no {{path}} segment"
        )));
    }
    if spec.unique && stars(&fact) == 0 {
        return Err(fail(format!(
            "is unique across the subjects a * binds, and fact {fact_text} has no *"
        )));
    }
    if let Some(m) = written
        .iter()
        .zip(&members)
        .find(|(_, (p, _))| stars(p) > stars(&fact))
        .map(|(m, _)| m)
    {
        return Err(fail(format!(
            "facts {} has more * than the first fact {fact_text}, so it binds no subject",
            m.fact
        )));
    }
    let suggest = spec
        .suggest
        .as_ref()
        .map(|s| parse_path(&s.fact).map(|p| (p, s.otherwise.clone())))
        .transpose()
        .map_err(fail)?;
    if let Some((path, _)) = suggest.as_ref().filter(|(p, _)| stars(p) > stars(&fact)) {
        return Err(fail(format!(
            "suggest has {} * where fact {fact_text} has {}, so it binds no subject",
            stars(path),
            stars(&fact)
        )));
    }
    let same = spec
        .same
        .as_deref()
        .map(parse_path)
        .transpose()
        .map_err(fail)?;
    if let Some(path) = same.as_ref().filter(|p| stars(p) > stars(&fact)) {
        return Err(fail(format!(
            "same has {} * where fact {fact_text} has {}, so it binds no subject",
            stars(path),
            stars(&fact)
        )));
    }
    let when = guards(
        spec.when.as_ref(),
        stars(&fact),
        &format!("fact {fact_text}"),
    )
    .map_err(fail)?;
    let keys = match &spec.keys {
        Some(_) if stars(&fact) == 0 => {
            return Err(fail(format!(
                "keys filters the key a * binds, and fact {fact_text} has no *"
            )));
        }
        Some(keys) => Some(schema(keys).map_err(|e| fail(format!("keys {e}")))?),
        None => None,
    };
    log::debug!("rule {id} judges {} facts as {combine:?}", members.len());
    Ok(Rule {
        id: id.to_owned(),
        spec,
        fact,
        keys,
        suggest,
        same,
        applies,
        when,
        members,
        combine,
    })
}

enum Tri {
    True,
    False(String),
    Unknown(String, Option<String>),
}

/// `when` on `bound`; with `unproduced`, a fact no collector produces is false, as a ruleset’s guard reads it.
fn guard(when: &[Vec<Guard>], document: &Value, bound: &[String], unproduced: bool) -> Tri {
    if when.is_empty() {
        return Tri::True;
    }
    let mut unknown = None;
    let mut first_false = None;
    for branch in when {
        let mut result = Tri::True;
        for g in branch {
            let resolved = resolve(document, &g.path, bound);
            let (Ok(keys) | Err(keys)) = resolved.clone();
            let Some(actual) = resolved.ok().and_then(|_| get(document, &keys)) else {
                let (reason, collector) = absent(document, &keys);
                if unproduced && collector.is_none() {
                    log::debug!("when {} has no producer, so it is false", keys.join("."));
                    result = Tri::False(format!("when no collector produces {}", keys.join(".")));
                    break;
                }
                if matches!(result, Tri::True) {
                    result = Tri::Unknown(format!("when {reason}"), collector);
                }
                continue;
            };
            let holds = match &g.test {
                Test::Equal(expected) => actual == expected,
                Test::Schema(validator, _) => validator.is_valid(actual),
            };
            if !holds {
                let path = keys.join(".");
                let shown = match (&g.test, actual) {
                    (Test::Schema(_, names), Value::Object(map)) if !names.is_empty() => names
                        .iter()
                        .map(|n| format!("{path}.{n} is {}", describe(map.get(n))))
                        .collect::<Vec<_>>()
                        .join(" and "),
                    _ => format!("{path} is {}", describe(Some(actual))),
                };
                log::debug!("when {path} fails: {shown}");
                result = Tri::False(format!("when {shown}"));
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

const BANDS: [(Severity, f64, f64, f64); 4] = [
    (Severity::Error, 6.6, 9.9, 8.0),
    (Severity::Warning, 3.3, 6.5, 5.0),
    (Severity::Info, 1.0, 3.2, 2.0),
    (Severity::Advice, 0.0, 0.9, 0.5),
];

/// A score on the one-decimal grid, 0.0 to 9.9.
pub fn round(score: f64) -> f64 {
    ((score * 10.0).round() / 10.0).clamp(0.0, 9.9)
}

/// The level whose band holds the score.
pub fn level_of(score: f64) -> Severity {
    let tenths = round(score);
    BANDS
        .iter()
        .find(|(_, min, _, _)| tenths >= *min)
        .map_or(Severity::Advice, |b| b.0)
}

/// A level’s band: lowest score, highest score, base.
pub fn band(level: Severity) -> (f64, f64, f64) {
    BANDS
        .iter()
        .find(|b| b.0 == level)
        .map_or((3.3, 6.5, 5.0), |b| (b.1, b.2, b.3))
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
    let (Some(first), Some(last)) = (points.first(), points.last()) else {
        return 0.0;
    };
    let at = value.clamp(first.0, last.0);
    let index = points
        .iter()
        .position(|p| p.0 >= at)
        .unwrap_or(0)
        .max(1)
        .min(points.len() - 1);
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
    if spec.pinned {
        pin(level, raw)
    } else {
        round(raw)
    }
}

fn elide(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 200 {
        return text.to_owned();
    }
    format!(
        "{}…{}",
        chars[..100].iter().collect::<String>(),
        chars[chars.len() - 99..].iter().collect::<String>()
    )
}

/// An offending value as a finding shows it: a string quoted, a list of scalars as words, absent, null or empty as none.
pub fn describe(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "none".to_owned(),
        Some(Value::String(s)) => format!("“{}”", elide(s)),
        Some(Value::Array(items)) if items.is_empty() => "none".to_owned(),
        Some(Value::Array(items)) if items.iter().all(|i| i.is_string() || i.is_number()) => elide(
            &items
                .iter()
                .map(|i| describe(Some(i)))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Some(Value::Array(items)) => format!("{} items", items.len()),
        Some(other) => {
            let json = other.to_string();
            if json.chars().count() > 80 {
                format!("{}…", json.chars().take(77).collect::<String>())
            } else {
                json
            }
        }
    }
}

fn fill(template: &str, variables: &BTreeMap<String, String>) -> String {
    variables
        .iter()
        .fold(template.to_owned(), |text, (name, value)| {
            text.replace(&format!("{{{name}}}"), value)
        })
}

fn base(rule: &Rule, outcome: Outcome, bound: &[String]) -> Check {
    Check {
        rule: rule.id.clone(),
        title: rule.spec.title.clone(),
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
        remedy: None,
        docs: rule.spec.docs.clone(),
        rationale: rule.spec.rationale.clone(),
        references: rule.spec.references.clone(),
    }
}

/// One fact of a rule on a subject: its keys and value, with the failing pointer and error when its schema fails.
enum Judged<'a> {
    Holds(Vec<String>, &'a Value),
    Fails(Vec<String>, &'a Value, String, String),
    Unknown(String, Option<String>),
}

impl Judged<'_> {
    fn holds(&self) -> bool {
        matches!(self, Judged::Holds(..))
    }

    fn fails(&self) -> bool {
        matches!(self, Judged::Fails(..))
    }

    fn unknown(&self) -> bool {
        matches!(self, Judged::Unknown(..))
    }
}

fn member<'a>(
    document: &'a Value,
    path: &[Segment],
    expect: &Validator,
    bound: &[String],
) -> Judged<'a> {
    let keys = match resolve(document, path, bound) {
        Ok(keys) => keys,
        Err(at) => {
            let (reason, collector) = absent(document, &at);
            return Judged::Unknown(reason, collector);
        }
    };
    let Some(value) = get(document, &keys) else {
        let (reason, collector) = absent(document, &keys);
        return Judged::Unknown(reason, collector);
    };
    match expect.validate(value) {
        Ok(()) => Judged::Holds(keys, value),
        Err(error) => Judged::Fails(
            keys,
            value,
            error.instance_path().as_str().to_owned(),
            error.to_string(),
        ),
    }
}

/// The facts of a rule combined in three-valued logic: `None` when the rule passes, else the failing or unknown fact that decides.
fn verdict<'a>(combine: Combine, mut judged: Vec<Judged<'a>>) -> Option<Judged<'a>> {
    fn take<'a>(judged: &mut Vec<Judged<'a>>, kind: fn(&Judged<'a>) -> bool) -> Option<Judged<'a>> {
        judged.iter().position(kind).map(|i| judged.remove(i))
    }
    let (holds, fails, unknown) = (Judged::holds, Judged::fails, Judged::unknown);
    match combine {
        Combine::All => take(&mut judged, fails).or_else(|| take(&mut judged, unknown)),
        Combine::Any if judged.iter().any(holds) => None,
        Combine::Any => take(&mut judged, unknown).or_else(|| take(&mut judged, fails)),
        Combine::None => match take(&mut judged, holds) {
            Some(Judged::Holds(keys, value)) => Some(Judged::Fails(
                keys,
                value,
                String::new(),
                "satisfies its expect, which none of the facts may".to_owned(),
            )),
            _ => take(&mut judged, unknown),
        },
    }
}

/// One check of `rule` on `bound`; `unbound` stands for the first fact when its collection is absent, and then only the facts without `*` are judged beside it.
fn check(rule: &Rule, document: &Value, bound: &[String], unbound: Option<Judged<'_>>) -> Check {
    match guard(&rule.when, document, bound, false) {
        Tri::False(reason) => {
            return Check {
                reason: Some(reason),
                ..base(rule, Outcome::Skip, bound)
            };
        }
        Tri::Unknown(reason, collector) => {
            return Check {
                reason: Some(reason),
                collector,
                ..base(rule, Outcome::Unknown, bound)
            };
        }
        Tri::True => {}
    }
    let judged = match unbound {
        None => rule
            .members
            .iter()
            .map(|(path, expect)| member(document, path, expect, bound))
            .collect(),
        Some(first) => std::iter::once(first)
            .chain(
                rule.members[1..]
                    .iter()
                    .filter(|(path, _)| stars(path) == 0)
                    .map(|(path, expect)| member(document, path, expect, bound)),
            )
            .collect(),
    };
    let (keys, value, pointer, error) = match verdict(rule.combine, judged) {
        None => return same(rule, document, bound),
        Some(Judged::Unknown(reason, collector)) => {
            return Check {
                reason: Some(reason),
                collector,
                ..base(rule, Outcome::Unknown, bound)
            };
        }
        Some(Judged::Fails(keys, value, pointer, error)) => (keys, value, pointer, error),
        Some(Judged::Holds(..)) => unreachable!("a verdict is never a holding fact"),
    };
    failure(rule, document, bound, &keys, value, &pointer, &error, &[])
}

/// A check whose facts hold, judged against `same`: unknown when that fact is absent, a fail when it differs.
fn same(rule: &Rule, document: &Value, bound: &[String]) -> Check {
    let Some(path) = &rule.same else {
        return base(rule, Outcome::Pass, bound);
    };
    let keys = concrete(&rule.fact, bound);
    let other = resolve(document, path, bound);
    let (Ok(at) | Err(at)) = other.clone();
    let (Some(value), Some(expected)) = (
        get(document, &keys),
        other.ok().and_then(|_| get(document, &at)),
    ) else {
        let (reason, collector) = absent(document, &at);
        log::debug!("rule {} has no same on {bound:?}: {reason}", rule.id);
        return Check {
            reason: Some(reason),
            collector,
            ..base(rule, Outcome::Unknown, bound)
        };
    };
    if value == expected {
        log::debug!("rule {} finds {} equal on {bound:?}", rule.id, at.join("."));
        return base(rule, Outcome::Pass, bound);
    }
    let shown = describe(Some(expected));
    let error = format!("differs from {}, which is {shown}", at.join("."));
    failure(
        rule,
        document,
        bound,
        &keys,
        value,
        "",
        &error,
        &[("same", shown)],
    )
}

/// The failing check of `rule` on `bound` for `value` at `keys`, its message filled, `extra` adding placeholders (`others`, `same`).
#[allow(clippy::too_many_arguments)]
fn failure(
    rule: &Rule,
    document: &Value,
    bound: &[String],
    keys: &[String],
    value: &Value,
    pointer: &str,
    error: &str,
    extra: &[(&str, String)],
) -> Check {
    let got = describe(value.pointer(pointer));
    let field = pointer
        .rsplit('/')
        .next()
        .filter(|f| !f.is_empty())
        .map_or_else(|| keys.last().cloned().unwrap_or_default(), str::to_owned);
    let subject = bound.last().cloned().unwrap_or_default();
    let mut variables: BTreeMap<String, String> = [
        ("got", got),
        ("field", field),
        ("fact", keys.join(".")),
        (
            "subject",
            if subject.is_empty() {
                "<subject>".to_owned()
            } else {
                subject
            },
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    for (name, text) in extra {
        variables.insert((*name).to_owned(), text.clone());
    }
    if let Some((path, otherwise)) = &rule.suggest {
        let value = resolve(document, path, bound)
            .ok()
            .and_then(|keys| get(document, &keys))
            .filter(|v| {
                !matches!(v, Value::Null)
                    && v.as_array().is_none_or(|a| !a.is_empty())
                    && v.as_str().is_none_or(|s| !s.is_empty())
            });
        let suggested = value.map_or_else(|| otherwise.clone(), |v| describe(Some(v)));
        log::debug!("rule {} suggests {suggested} for {:?}", rule.id, bound);
        variables.insert("suggested".to_owned(), suggested);
    }
    let message = match &rule.spec.message {
        Some(template) => fill(template, &variables),
        None => format!("{}{pointer}: {error}", keys.join(".")),
    };
    let score = score(&rule.spec, value.pointer(pointer));
    log::debug!("rule {} fails on {:?} with score {score}", rule.id, bound);
    Check {
        severity: Some(level_of(score)),
        score: Some(score),
        message: Some(message),
        fix: rule.spec.fix.as_ref().map(|f| fill(f, &variables)),
        remedy: rule
            .spec
            .remedy
            .as_ref()
            .zip(bound.last().filter(|p| p.starts_with('/')))
            .filter(|(r, _)| {
                !matches!(r, crate::fix::Remedy::DisableLine(_))
                    || rule
                        .subject_value(document, bound, 1)
                        .is_some_and(|v| v.get("line-sha256").is_some())
            })
            .map(|(r, path)| r.command(path)),
        text: rule.spec.message.clone(),
        variables: if rule.spec.message.is_some() {
            variables
        } else {
            BTreeMap::new()
        },
        value: Some(value.clone()),
        fact: keys.join("."),
        ..base(rule, Outcome::Fail, bound)
    }
}

/// Every check of `rule` on `document`: one not-applicable, unknown or manual check, else one per subject, none when its subjects exist and are empty.
pub fn judge(rule: &Rule, document: &Value) -> Vec<Check> {
    for (name, when) in &rule.applies {
        match guard(when, document, &[], true) {
            Tri::True => {}
            Tri::False(reason) => {
                log::debug!(
                    "rule {} is not applicable: ruleset {name} {reason}",
                    rule.id
                );
                return vec![Check {
                    reason: Some(format!("ruleset {name}: {reason}")),
                    ..base(rule, Outcome::NotApplicable, &[])
                }];
            }
            Tri::Unknown(reason, collector) => {
                log::debug!(
                    "rule {} applicability is unknown: ruleset {name} {reason}",
                    rule.id
                );
                return vec![Check {
                    reason: Some(format!("ruleset {name}: {reason}")),
                    collector,
                    ..base(rule, Outcome::Unknown, &[])
                }];
            }
        }
    }
    if rule.members.is_empty() {
        return vec![base(rule, Outcome::Manual, &[])];
    }
    let Some(bindings) = subjects(document, &rule.fact) else {
        let last = rule
            .fact
            .iter()
            .position(|s| *s == Segment::Star)
            .unwrap_or(rule.fact.len());
        let keys = concrete(&rule.fact[..last], &[]);
        let (reason, collector) = absent(document, &keys);
        log::debug!("rule {} has no subjects: {reason}", rule.id);
        if let Tri::False(skipped) = guard(&rule.when, document, &[], false) {
            log::debug!("rule {} skips its absent collection: {skipped}", rule.id);
            return vec![Check {
                reason: Some(skipped),
                ..base(rule, Outcome::Skip, &[])
            }];
        }
        if rule.members.len() > 1 {
            return vec![check(
                rule,
                document,
                &[],
                Some(Judged::Unknown(reason, collector)),
            )];
        }
        return vec![Check {
            reason: Some(reason),
            collector,
            ..base(rule, Outcome::Unknown, &[])
        }];
    };
    let bindings: Vec<Vec<String>> = bindings
        .into_iter()
        .filter(|bound| kept(rule, bound))
        .collect();
    log::debug!("rule {} judges {} subjects", rule.id, bindings.len());
    let mut checks: Vec<Check> = bindings
        .iter()
        .map(|bound| check(rule, document, bound, None))
        .collect();
    if rule.spec.unique {
        collide(rule, document, &bindings, &mut checks);
    }
    checks
}

/// Fails every passing check of a `unique` rule whose fact value another passing check holds too.
fn collide(rule: &Rule, document: &Value, bindings: &[Vec<String>], checks: &mut [Check]) {
    let mut holders: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, bound) in bindings.iter().enumerate() {
        let value = get(document, &concrete(&rule.fact, bound));
        if let Some(value) = value.filter(|_| checks[i].outcome == Outcome::Pass) {
            holders.entry(value.to_string()).or_default().push(i);
        }
    }
    for (value, held) in holders.iter().filter(|(_, held)| held.len() > 1) {
        log::debug!(
            "rule {} finds {value} held by {} subjects",
            rule.id,
            held.len()
        );
        for &i in held {
            let others = held
                .iter()
                .filter(|&&j| j != i)
                .map(|&j| bindings[j].last().cloned().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(", ");
            let keys = concrete(&rule.fact, &bindings[i]);
            let Some(value) = get(document, &keys) else {
                continue;
            };
            let error = format!("is also the value of {others}");
            checks[i] = failure(
                rule,
                document,
                &bindings[i],
                &keys,
                value,
                "",
                &error,
                &[("others", others)],
            );
        }
    }
}

/// Whether `keys` admits the key of the fact’s last `*`; a binding cut short by an absent fact is kept.
fn kept(rule: &Rule, bound: &[String]) -> bool {
    let Some(keys) = &rule.keys else { return true };
    let Some(key) = bound.last().filter(|_| bound.len() == stars(&rule.fact)) else {
        return true;
    };
    let admitted = keys.is_valid(&Value::from(key.as_str()));
    if !admitted {
        log::debug!(
            "rule {} leaves out subject {key}: keys does not admit it",
            rule.id
        );
    }
    admitted
}

/// Every check of every rule, with the first matching waiver attached to each failure, active through its `until` day.
pub fn lint(document: &Value, rules: &[Rule], waivers: &[Waiver], today: &str) -> Vec<Check> {
    let mut checks: Vec<Check> = rules
        .iter()
        .flat_map(|rule| judge(rule, document))
        .collect();
    contradict(&mut checks, rules);
    for check in checks.iter_mut().filter(|c| c.outcome == Outcome::Fail) {
        let (subject, label) = (check.subject_text(), check.subject_label());
        if let Some(waiver) = waivers.iter().find(|w| {
            glob(&w.rule, &check.rule)
                && w.subject
                    .as_deref()
                    .is_none_or(|s| glob(s, &subject) || glob(s, &label))
        }) {
            let active = today <= waiver.until.as_str();
            log::debug!(
                "rule {} on {subject:?} waived until {} (active {active})",
                check.rule,
                waiver.until
            );
            check.waiver = Some(Waived {
                reason: waiver.reason.clone(),
                until: waiver.until.clone(),
                active,
            });
        }
    }
    checks
}

/// Turns every judged check of a rule whose `conflicts` names another selected rule into a `conflict`, naming the pair and how to keep one.
fn contradict(checks: &mut [Check], rules: &[Rule]) {
    let selected: BTreeMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();
    for check in checks
        .iter_mut()
        .filter(|c| matches!(c.outcome, Outcome::Pass | Outcome::Fail | Outcome::Unknown))
    {
        let Some(rule) = selected.get(check.rule.as_str()) else {
            continue;
        };
        let mut side: Vec<&Rule> = rule
            .spec
            .conflicts
            .iter()
            .filter_map(|id| selected.get(id.as_str()).copied())
            .collect();
        if side.is_empty() {
            continue;
        }
        side.push(rule);
        side.sort_by(|a, b| a.id.cmp(&b.id));
        let named = |r: &Rule| {
            let controls: Vec<&str> = r
                .spec
                .tags
                .iter()
                .filter(|t| t.contains(':'))
                .map(String::as_str)
                .collect();
            if controls.is_empty() {
                r.id.clone()
            } else {
                format!("{} ({})", r.id, controls.join(", "))
            }
        };
        let names: Vec<String> = side.iter().map(|r| named(r)).collect();
        let keep: Vec<String> = side.iter().map(|r| format!("'!{}'", r.id)).collect();
        log::debug!(
            "rule {} on {:?} was {:?}, conflicts with {names:?}",
            check.rule,
            check.subject,
            check.outcome
        );
        check.reason = Some(format!(
            "{} contradict each other, so none of them counts; keep the standard you follow by leaving the other out with --tags {}",
            names.join(" and "),
            keep.join(" or ")
        ));
        check.outcome = Outcome::Conflict;
    }
}

/// Checks a waiver’s `until` is a `YYYY-MM-DD` day.
pub fn valid_day(day: &str) -> bool {
    let b = day.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}
