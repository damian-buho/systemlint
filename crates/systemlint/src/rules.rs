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

/// How bad a failed check is; `off` drops the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Hint,
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
    pub fix: Option<String>,
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
    #[serde(default)]
    pub extends: Vec<String>,
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

/// `over` on top of `base`: set fields win, `expect` merges keyword by keyword and drops the inherited message, tags and references add up.
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
    let mut tags = base.tags;
    tags.extend(
        over.tags
            .into_iter()
            .filter(|t| !tags.contains(t))
            .collect::<Vec<_>>(),
    );
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
                let mut spec = entry(raw).map_err(|e| format!("ruleset {name}: rule {id}: {e}"))?;
                if !spec.defines() {
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
                if !spec.manual && spec.facts.is_none() && spec.expect.is_none() {
                    return Err(format!("ruleset {name}: rule {id} has fact but no expect"));
                }
                spec.applies_in(name, ruleset.when.as_ref());
                log::debug!("rule {id} defined in ruleset {name}");
                owner.insert(id.clone(), name.clone());
                definitions.insert(id.clone(), spec);
            }
        }
        Ok(Self {
            rulesets,
            definitions,
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
                Err(_) if crate::yaml::from_str::<crate::comply::Catalog>(&text).is_ok() => {
                    log::debug!("{} is a standards catalog, not a ruleset", path.display())
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
        }
        seen.pop();
        for (id, raw) in &ruleset.rules {
            let spec = entry(raw).map_err(|e| format!("ruleset {name}: rule {id}: {e}"))?;
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

    fn matching(&self, pattern: &str) -> Result<BTreeMap<String, Spec>, String> {
        let picked: BTreeMap<String, Spec> = self
            .definitions
            .iter()
            .filter(|(id, spec)| glob(pattern, id) || spec.tags.iter().any(|t| glob(pattern, t)))
            .map(|(id, spec)| (id.clone(), spec.clone()))
            .collect();
        log::debug!(
            "selector {pattern} matches {} rules by ID or tag",
            picked.len()
        );
        if picked.is_empty() {
            return Err(format!(
                "{pattern} is no ruleset, and no rule ID or tag matches it"
            ));
        }
        Ok(picked)
    }

    /// The rules a selector list picks: a union in order (every rule when only `!` entries), a ruleset’s overrides beating a plain ID or tag pick, `!` removing, `off` dropped.
    pub fn select(&self, selectors: &[String]) -> Result<BTreeMap<String, Spec>, String> {
        let mut picked: BTreeMap<String, Spec> = BTreeMap::new();
        let every = ["*".to_owned()];
        let mut includes: Vec<&String> = selectors.iter().filter(|s| !s.starts_with('!')).collect();
        if includes.is_empty() {
            log::debug!("selectors {selectors:?} only exclude, starting from every rule");
            includes.extend(&every);
        }
        for selector in includes {
            let found = self.resolve(selector)?;
            let is_ruleset = self.rulesets.contains_key(selector.as_str());
            for (id, spec) in found {
                if is_ruleset {
                    picked.insert(id, spec);
                } else {
                    picked.entry(id).or_insert(spec);
                }
            }
        }
        for selector in selectors.iter().filter_map(|s| s.strip_prefix('!')) {
            let removed = self.resolve(selector)?;
            log::debug!("selector !{selector} removes {} rules", removed.len());
            picked.retain(|id, _| !removed.contains_key(id));
        }
        picked.retain(|id, spec| {
            let off = spec.severity == Some(Severity::Off);
            if off {
                log::debug!("rule {id} is off");
            }
            !off
        });
        Ok(picked)
    }

    /// The rules `base` picks plus every rule tagged `<standard>:*`; standards with nothing else to pick select nothing, never every rule.
    pub fn select_for(
        &self,
        base: &[String],
        standards: &[String],
    ) -> Result<BTreeMap<String, Spec>, String> {
        let mut selectors = base.to_vec();
        for standard in standards {
            let prefix = format!("{standard}:");
            if self
                .definitions
                .values()
                .any(|spec| spec.tags.iter().any(|t| t.starts_with(&prefix)))
            {
                selectors.push(format!("{standard}:*"));
            } else {
                log::debug!("no rule is tagged {prefix}*, so standard {standard} adds no rule");
            }
        }
        if !standards.is_empty() && selectors.iter().all(|s| s.starts_with('!')) {
            log::debug!("standards {standards:?} and selectors {base:?} pick no rule");
            return Ok(BTreeMap::new());
        }
        self.select(&selectors)
    }
}

/// The directories to search, in order: beside the core binary, then the configured ones.
pub fn directories(exe: &Path, configured: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::directories(exe, BESIDE, configured)
}
