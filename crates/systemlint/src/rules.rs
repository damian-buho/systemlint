// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Rule specs, rulesets with `extends`, and the selector list that picks rules by ruleset, ID or tag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::discovery::{Refusal, Trust};

/// The ruleset directory relative to the core binary’s own directory.
pub const BESIDE: &str = "../share/systemlint/rulesets";

/// The tag a run selects when neither `--tags` nor `check.tags` names any.
pub const DEFAULT: &str = "default";

/// Rules by ID, as a selector picks them.
type Picks = BTreeMap<String, Spec>;

/// How bad a failed check is; `off` drops the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Advice,
    Info,
    Warning,
    Error,
    Off,
}

/// A fixed score, or a curve of `[value, score]` points read against the fact’s number.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Score {
    Fixed(f64),
    Curve(Vec<(f64, f64)>),
}

/// A `when` guard: a map is AND, a list of maps is OR.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum When {
    All(Map<String, Value>),
    Any(Vec<Map<String, Value>>),
}

/// A source a rule rests on: its title and link.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub title: String,
    pub url: String,
}

/// The fact that fills `{suggested}`, and the words used when it is absent or empty.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggest {
    pub fact: String,
    pub otherwise: String,
}

/// A rule’s fix: one sentence, or numbered steps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Fix {
    Text(String),
    Steps(Vec<Step>),
}

/// One step of a fix: words, or what the reader types or writes, shown alone under the words before it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Step {
    Say(String),
    Show(Shown),
}

/// A step shown alone: a command to run, or the lines to write in a file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Shown {
    Run(String),
    Lines(Vec<String>),
}

impl Shown {
    /// The lines shown: the command, or each file line.
    pub fn lines(&self) -> Vec<&str> {
        match self {
            Self::Run(command) => vec![command.as_str()],
            Self::Lines(lines) => lines.iter().map(String::as_str).collect(),
        }
    }
}

impl Fix {
    /// Every text of the fix passed through `f`, as the judge fills placeholders.
    pub fn map(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Text(text) => Self::Text(f(text)),
            Self::Steps(steps) => Self::Steps(
                steps
                    .iter()
                    .map(|step| match step {
                        Step::Say(text) => Step::Say(f(text)),
                        Step::Show(Shown::Run(command)) => Step::Show(Shown::Run(f(command))),
                        Step::Show(Shown::Lines(lines)) => {
                            Step::Show(Shown::Lines(lines.iter().map(|l| f(l)).collect()))
                        }
                    })
                    .collect(),
            ),
        }
    }

    /// The fix on one line, for formats with one cell for it: each step numbered, what it shows quoted after it.
    pub fn text(&self) -> String {
        let steps = match self {
            Self::Text(text) => return text.clone(),
            Self::Steps(steps) => steps,
        };
        let mut parts: Vec<String> = Vec::new();
        for step in steps {
            match (step, parts.last_mut()) {
                (Step::Say(text), _) => parts.push(text.clone()),
                (Step::Show(shown), last) => {
                    let quoted: Vec<String> =
                        shown.lines().iter().map(|l| format!("“{l}”")).collect();
                    match last {
                        Some(last) if last.ends_with(':') => last.push(' '),
                        Some(last) => last.push_str(": "),
                        None => parts.push(String::new()),
                    }
                    if let Some(last) = parts.last_mut() {
                        last.push_str(&quoted.join(", "));
                    }
                }
            }
        }
        parts
            .iter()
            .enumerate()
            .map(|(i, part)| match part.ends_with(['.', '!', '?', '…']) {
                true => format!("{}. {part}", i + 1),
                false => format!("{}. {part}.", i + 1),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A fix for the subjects whose key `keys` admits and on which `when` holds.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<When>,
    pub fix: Fix,
}

/// One fact of a several-fact rule and the schema it must satisfy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub fact: String,
    pub expect: Map<String, Value>,
}

/// Several facts judged together: the rule passes when all, any or none of them satisfy their schema.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Facts {
    All(Vec<Member>),
    Any(Vec<Member>),
    None(Vec<Member>),
}

/// One rule as a ruleset writes it, a definition when it has `fact` or `facts`, else an override.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<Facts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<When>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<Score>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Choice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<crate::fix::Remedy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggest: Option<Suggest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manual: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unique: bool,
    /// A fact, bound like `when`, the rule’s fact must equal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
    #[serde(skip)]
    pub pinned: bool,
    /// The `when` of every ruleset that defines or brings the rule, by ruleset name.
    #[serde(skip)]
    pub applies: Vec<(String, When)>,
}

impl Spec {
    /// Whether this entry defines a rule: it names a fact or several, or is a manual procedure.
    pub fn defines(&self) -> bool {
        self.fact.is_some() || self.facts.is_some() || self.manual
    }

    fn applies_in(&mut self, name: &str, when: Option<&When>) {
        if let Some(when) = when.filter(|_| !self.applies.iter().any(|(n, _)| n == name)) {
            self.applies.push((name.to_owned(), when.clone()));
        }
    }
}

/// One ruleset: its parents, then its own rule entries by ID.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ruleset {
    #[serde(default)]
    pub description: Option<String>,
    /// The book page that lists this ruleset’s rules, `Logging and auditing`; none puts them under `Other`.
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub when: Option<When>,
    #[serde(default)]
    pub vars: BTreeMap<String, crate::vars::Var>,
    #[serde(default)]
    pub rules: Map<String, Value>,
}

/// Every known ruleset by name, and every rule definition by ID.
#[derive(Debug, Default)]
pub struct Library {
    pub rulesets: BTreeMap<String, Ruleset>,
    pub definitions: BTreeMap<String, Spec>,
    /// The ruleset that defines each rule, by rule ID.
    pub owners: BTreeMap<String, String>,
}

/// What a selection runs, and how many rules it left out per defining ruleset.
#[derive(Debug, Default)]
pub struct Selected {
    pub rules: Picks,
    pub left_out: BTreeMap<String, usize>,
}

/// Whether `text` matches `pattern`, where `*` is any run of characters and `?` one.
pub fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            (pi, ti) = (pi + 1, ti + 1);
        } else if pi < p.len() && p[pi] == '*' {
            (star, mark, pi) = (Some(pi), ti, pi + 1);
        } else if let Some(s) = star {
            (pi, mark, ti) = (s + 1, mark + 1, mark + 1);
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// An entry as a spec: a number is a score, a level pins the score to its band, a map is a spec.
fn entry(raw: &Value) -> Result<Spec, String> {
    match raw {
        Value::Number(n) => Ok(Spec {
            score: n.as_f64().map(Score::Fixed),
            ..Spec::default()
        }),
        Value::String(_) => Ok(Spec {
            severity: Some(serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?),
            pinned: true,
            ..Spec::default()
        }),
        _ => {
            let spec: Spec = serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?;
            let pinned = spec.fact.is_none()
                && spec.facts.is_none()
                && spec.severity.is_some()
                && spec.score.is_none();
            Ok(Spec { pinned, ..spec })
        }
    }
}

/// `base` tags then `own`, where an own `!tag` drops that tag from `base`.
fn tagged(base: Vec<String>, own: Vec<String>) -> Vec<String> {
    let (drop, own): (Vec<_>, Vec<_>) = own.into_iter().partition(|t| t.starts_with('!'));
    let mut tags: Vec<String> = base
        .into_iter()
        .filter(|t| !drop.iter().any(|d| d[1..] == *t))
        .collect();
    for tag in own {
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    if !drop.is_empty() {
        log::debug!("tags {drop:?} dropped, leaving {tags:?}");
    }
    tags
}

/// A ruleset’s entry as a spec, a definition taking the ruleset’s own tags first.
fn defined(ruleset: &Ruleset, raw: &Value) -> Result<Spec, String> {
    let mut spec = entry(raw)?;
    if spec.defines() {
        spec.tags = tagged(ruleset.tags.clone(), std::mem::take(&mut spec.tags));
    }
    Ok(spec)
}

/// `over` on top of `base`: set fields win, `expect` merges keyword by keyword and drops the inherited message, tags and references add up, an `!tag` removing one.
fn merge(base: Spec, over: Spec) -> Spec {
    let expect_changed = over.expect.is_some();
    let subject_changed = over.fact.is_some() || over.facts.is_some();
    let expect = match (base.expect, over.expect) {
        (Some(mut b), Some(o)) => {
            b.extend(o);
            Some(b)
        }
        (b, o) => o.or(b),
    };
    let score_set = over.score.is_some();
    let tags = tagged(base.tags, over.tags);
    let mut references = base.references;
    references.extend(
        over.references
            .into_iter()
            .filter(|r| !references.contains(r))
            .collect::<Vec<_>>(),
    );
    let mut applies = base.applies;
    applies.extend(
        over.applies
            .into_iter()
            .filter(|(n, _)| !applies.iter().any(|(m, _)| m == n))
            .collect::<Vec<_>>(),
    );
    Spec {
        title: over.title.or(base.title),
        fact: over.fact.or(base.fact),
        expect,
        facts: over.facts.or(base.facts),
        keys: over.keys.or(base.keys),
        when: over.when.or(base.when),
        severity: if score_set && over.severity.is_none() {
            None
        } else {
            over.severity.or(base.severity)
        },
        score: over.score.or(base.score),
        message: over
            .message
            .or(if expect_changed { None } else { base.message }),
        fix: over.fix.or(base.fix),
        fixes: if over.fixes.is_empty() {
            base.fixes
        } else {
            over.fixes
        },
        remedy: if subject_changed {
            over.remedy
        } else {
            over.remedy.or(base.remedy)
        },
        suggest: over.suggest.or(base.suggest),
        docs: over.docs.or(base.docs),
        rationale: over.rationale.or(base.rationale),
        references,
        tags,
        manual: over.manual || base.manual,
        unique: over.unique || base.unique,
        same: over.same.or(base.same),
        conflicts: base.conflicts,
        pinned: over.pinned || (!score_set && base.pinned),
        applies,
    }
}

impl Library {
    /// The library of `rulesets`, refusing a rule defined twice or an invalid entry.
    pub fn new(rulesets: BTreeMap<String, Ruleset>) -> Result<Self, String> {
        let mut definitions: BTreeMap<String, Spec> = BTreeMap::new();
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        for (name, ruleset) in &rulesets {
            for (id, raw) in &ruleset.rules {
                let mut spec =
                    defined(ruleset, raw).map_err(|e| format!("ruleset {name}: rule {id}: {e}"))?;
                if !spec.defines() {
                    if !spec.conflicts.is_empty() {
                        return Err(format!(
                            "ruleset {name}: rule {id} overrides a rule, so it takes no conflicts; declare them where the rule is defined"
                        ));
                    }
                    continue;
                }
                if let Some(first) = owner.get(id) {
                    return Err(format!(
                        "ruleset {name}: rule {id} is already defined in ruleset {first}"
                    ));
                }
                if spec.manual
                    && (spec.fact.is_some() || spec.expect.is_some() || spec.facts.is_some())
                {
                    return Err(format!(
                        "ruleset {name}: rule {id} is manual, so it takes no fact, expect or facts"
                    ));
                }
                if !spec.manual
                    && !spec.unique
                    && spec.same.is_none()
                    && spec.facts.is_none()
                    && spec.expect.is_none()
                {
                    return Err(format!("ruleset {name}: rule {id} has fact but no expect"));
                }
                spec.applies_in(name, ruleset.when.as_ref());
                log::debug!("rule {id} defined in ruleset {name}");
                owner.insert(id.clone(), name.clone());
                definitions.insert(id.clone(), spec);
            }
        }
        for (id, spec) in &definitions {
            for other in &spec.conflicts {
                let named = definitions.get(other).map(|o| o.conflicts.contains(id));
                log::debug!(
                    "rule {id} conflicts with rule {other}, which names it back: {named:?}"
                );
                match named {
                    _ if other == id => {
                        return Err(format!(
                            "ruleset {}: rule {id} names itself in conflicts",
                            owner[id]
                        ));
                    }
                    None => {
                        return Err(format!(
                            "ruleset {}: rule {id} conflicts with rule {other}, which no ruleset defines",
                            owner[id]
                        ));
                    }
                    Some(false) => {
                        return Err(format!(
                            "ruleset {}: rule {id} conflicts with rule {other}, which does not name {id} in its conflicts; declare it on both",
                            owner[id]
                        ));
                    }
                    Some(true) => {}
                }
            }
        }
        Ok(Self {
            rulesets,
            definitions,
            owners: owner,
        })
    }

    /// Every trusted ruleset file in `dirs` by file stem, then `inline` ones, their vars filled from `vars`; a name given twice is refused.
    pub fn load(
        dirs: &[PathBuf],
        trust: &Trust,
        inline: &BTreeMap<String, Ruleset>,
        vars: &crate::vars::Supplied,
    ) -> (Result<Self, String>, Vec<Refusal>) {
        let (texts, mut refusals) = crate::discovery::yaml_files(dirs, trust);
        let mut rulesets = BTreeMap::new();
        for (path, text) in texts {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            match crate::yaml::from_str::<Ruleset>(&text) {
                Ok(_) if rulesets.contains_key(&name) => refusals.push(Refusal {
                    path,
                    reason: format!("ruleset {name} is already defined"),
                }),
                Ok(ruleset) => {
                    log::debug!(
                        "ruleset {name} from {} with {} rules",
                        path.display(),
                        ruleset.rules.len()
                    );
                    rulesets.insert(name, ruleset);
                }
                Err(e) => refusals.push(Refusal {
                    path,
                    reason: format!("not a valid ruleset: {e}"),
                }),
            }
        }
        for (name, ruleset) in inline {
            if rulesets.insert(name.clone(), ruleset.clone()).is_some() {
                return (
                    Err(format!(
                        "ruleset {name} in the config is also a file; give it another name"
                    )),
                    refusals,
                );
            }
        }
        (
            crate::vars::apply(&mut rulesets, vars).and_then(|()| Self::new(rulesets)),
            refusals,
        )
    }

    /// Every rule `name` holds: a ruleset flattened through `extends`, else the rules whose ID or a tag matches it as a glob.
    pub fn resolve(&self, name: &str) -> Result<BTreeMap<String, Spec>, String> {
        self.resolve_in(name, &mut Vec::new())
    }

    fn resolve_in(
        &self,
        name: &str,
        seen: &mut Vec<String>,
    ) -> Result<BTreeMap<String, Spec>, String> {
        if seen.iter().any(|s| s == name) {
            return Err(format!(
                "ruleset {name} extends itself through {}",
                seen.join(" → ")
            ));
        }
        let Some(ruleset) = self.rulesets.get(name) else {
            return self.matching(name);
        };
        seen.push(name.to_owned());
        let mut merged = BTreeMap::new();
        for parent in &ruleset.extends {
            merged.extend(self.resolve_in(parent, seen)?);
            if self.rulesets.contains_key(parent) {
                for (id, spec) in self.tagged(parent) {
                    merged.entry(id).or_insert(spec);
                }
            }
        }
        seen.pop();
        for (id, raw) in &ruleset.rules {
            let spec =
                defined(ruleset, raw).map_err(|e| format!("ruleset {name}: rule {id}: {e}"))?;
            let base = merged.remove(id).or_else(|| {
                if spec.defines() {
                    None
                } else {
                    self.definitions.get(id).cloned()
                }
            });
            let spec = match base {
                Some(base) => merge(base, spec),
                None if spec.defines() => spec,
                None => {
                    return Err(format!(
                        "ruleset {name}: rule {id} overrides a rule no ruleset defines"
                    ));
                }
            };
            merged.insert(id.clone(), spec);
        }
        for spec in merged.values_mut() {
            spec.applies_in(name, ruleset.when.as_ref());
        }
        log::debug!("ruleset {name} resolved to {} rules", merged.len());
        Ok(merged)
    }

    /// Every rule `pattern` matches by ID or tag, standard-only ones included, as a `!` selector removes them.
    fn matched(&self, pattern: &str) -> Result<BTreeMap<String, Spec>, String> {
        let matched: BTreeMap<String, Spec> = self
            .definitions
            .iter()
            .filter(|(id, spec)| glob(pattern, id) || spec.tags.iter().any(|t| glob(pattern, t)))
            .map(|(id, spec)| (id.clone(), spec.clone()))
            .collect();
        if matched.is_empty() {
            return Err(format!(
                "{pattern} is no ruleset, and no rule ID or tag matches it"
            ));
        }
        Ok(matched)
    }

    /// The rules `pattern` picks: what it matches, a standard-only rule only by its exact ID or a standard’s tag.
    fn matching(&self, pattern: &str) -> Result<BTreeMap<String, Spec>, String> {
        let matched = self.matched(pattern)?;
        let picked: BTreeMap<String, Spec> = matched
            .iter()
            .filter(|(id, spec)| {
                *id == pattern
                    || spec
                        .tags
                        .iter()
                        .any(|t| t.contains(':') && glob(pattern, t))
                    || !self.standard_only(id, spec)
            })
            .map(|(id, spec)| (id.clone(), spec.clone()))
            .collect();
        log::debug!(
            "selector {pattern} matches {} rules by ID or tag, {} of them standard-only and left out",
            matched.len(),
            matched.len() - picked.len()
        );
        if picked.is_empty() {
            let id = matched.keys().next().cloned().unwrap_or_default();
            return Err(format!(
                "{pattern} matches only rules a standard alone asks for: name each by its ID ({id}) or select its standard’s tag"
            ));
        }
        Ok(picked)
    }

    /// Whether `id` is a rule its `default` ruleset leaves out with `!default`, which only its ID or a standard’s tag selects.
    fn standard_only(&self, id: &str, spec: &Spec) -> bool {
        let owner_default = self
            .owners
            .get(id)
            .and_then(|o| self.rulesets.get(o))
            .is_some_and(|r| r.tags.iter().any(|t| t == DEFAULT));
        owner_default && !spec.tags.iter().any(|t| t == DEFAULT)
    }

    /// A selector’s rules as (overrides, plain picks): a ruleset’s own plus the rules its name matches by ID or tag, else the glob’s.
    fn named(&self, selector: &str) -> Result<(Picks, Picks), String> {
        let found = self.resolve(selector)?;
        if !self.rulesets.contains_key(selector) {
            return Ok((BTreeMap::new(), found));
        }
        let mut own = found;
        own.retain(|id, spec| {
            let defined = self.owners.get(id).is_some_and(|o| o == selector);
            let kept = !defined || !self.standard_only(id, spec);
            if !kept {
                log::debug!("ruleset {selector} leaves out standard-only rule {id}");
            }
            kept
        });
        Ok((own, self.tagged(selector)))
    }

    /// The rules a ruleset’s name matches by ID or tag, which naming it picks beside its own.
    fn tagged(&self, ruleset: &str) -> Picks {
        let tagged = self.matching(ruleset).unwrap_or_default();
        log::debug!(
            "ruleset {ruleset} also picks {} rules matching its name",
            tagged.len()
        );
        tagged
    }

    /// The rules a selector list picks: a union in order (the `default` tag when only `!` entries), a ruleset’s overrides beating a plain ID or tag pick, `!` removing, `off` dropped.
    pub fn select(&self, selectors: &[String]) -> Result<BTreeMap<String, Spec>, String> {
        Ok(Self::on(self.pick(selectors)?))
    }

    /// [`Library::select`] before `off` rules are dropped.
    fn pick(&self, selectors: &[String]) -> Result<Picks, String> {
        let mut picked: BTreeMap<String, Spec> = BTreeMap::new();
        let includes: Vec<&String> = selectors.iter().filter(|s| !s.starts_with('!')).collect();
        if includes.is_empty() {
            picked = self.matching(DEFAULT).unwrap_or_default();
            log::debug!(
                "selectors {selectors:?} only exclude, starting from {} rules tagged {DEFAULT}",
                picked.len()
            );
        }
        for selector in includes {
            let (overrides, plain) = self.named(selector)?;
            picked.extend(overrides);
            for (id, spec) in plain {
                picked.entry(id).or_insert(spec);
            }
        }
        for selector in selectors.iter().filter_map(|s| s.strip_prefix('!')) {
            let overrides = match self.rulesets.contains_key(selector) {
                true => self.resolve(selector)?,
                false => BTreeMap::new(),
            };
            let plain = match self.rulesets.contains_key(selector) {
                true => self.matched(selector).unwrap_or_default(),
                false => self.matched(selector)?,
            };
            log::debug!(
                "selector !{selector} removes {} rules",
                overrides.len() + plain.len()
            );
            picked.retain(|id, _| !overrides.contains_key(id) && !plain.contains_key(id));
        }
        Ok(picked)
    }

    /// `picked` without its `off` rules.
    fn on(mut picked: Picks) -> Picks {
        picked.retain(|id, spec| {
            let off = spec.severity == Some(Severity::Off);
            if off {
                log::debug!("rule {id} is off");
            }
            !off
        });
        picked
    }

    /// How many defined rules `picked` leaves out, per defining ruleset; an `off` definition is not counted.
    fn left_out(&self, picked: &Picks) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for (id, spec) in &self.definitions {
            if picked.contains_key(id) || spec.severity == Some(Severity::Off) {
                continue;
            }
            let owner = self.owners.get(id).cloned().unwrap_or_default();
            log::debug!("rule {id} of ruleset {owner} is not selected");
            *out.entry(owner).or_insert(0) += 1;
        }
        out
    }

    /// The rules `selectors` pick, and how many it leaves out per defining ruleset.
    pub fn select_for(&self, selectors: &[String]) -> Result<Selected, String> {
        let picked = self.pick(selectors)?;
        Ok(Selected {
            left_out: self.left_out(&picked),
            rules: Self::on(picked),
        })
    }
}

/// The directories to search, in order: beside the core binary, then the configured ones.
pub fn directories(exe: &Path, configured: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::directories(exe, BESIDE, configured)
}
