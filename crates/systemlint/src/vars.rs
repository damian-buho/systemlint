// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Ruleset variables: `${name}` in a rule’s `expect`, `when` and `message`, filled from flags, the environment, the config or the default.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::rules::{Ruleset, When};

/// A variable a ruleset declares: its default and the environment variable that may set it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Var {
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default, rename = "from-env")]
    pub from_env: Option<String>,
}

/// The values given for variables: flag layers first, each named for errors, then the environment, then `lint.vars`.
pub struct Supplied {
    pub flags: Vec<(String, Map<String, Value>)>,
    pub config: Map<String, Value>,
    pub env: fn(&str) -> Option<String>,
}

impl Default for Supplied {
    fn default() -> Self {
        Self {
            flags: Vec::new(),
            config: Map::new(),
            env: |name| std::env::var(name).ok(),
        }
    }
}

/// The variables in the YAML map at `path`, as `--vars` reads them.
pub fn file(path: &Path) -> Result<Map<String, Value>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        crate::explain::io(
            "read vars",
            path,
            &e,
            &[
                (ErrorKind::NotFound, "Check the --vars path."),
                (
                    ErrorKind::IsADirectory,
                    "Name a YAML file of name: value pairs.",
                ),
            ],
        )
    })?;
    crate::yaml::from_str(&text).map_err(|e| {
        format!(
            "{} is not a YAML map of name: value pairs: {e}",
            path.display()
        )
    })
}

/// Fills every `${name}` in each ruleset from the values its own `vars` resolve to, refusing a value for a var no ruleset declares.
pub fn apply(rulesets: &mut BTreeMap<String, Ruleset>, supplied: &Supplied) -> Result<(), String> {
    let declared: BTreeSet<&String> = rulesets.values().flat_map(|r| r.vars.keys()).collect();
    let layers = supplied
        .flags
        .iter()
        .map(|(source, map)| (source.as_str(), map))
        .chain([("lint.vars", &supplied.config)]);
    for (source, map) in layers {
        if let Some(name) = map.keys().find(|n| !declared.contains(n)) {
            return Err(format!(
                "{source} sets var {name}, which no ruleset declares"
            ));
        }
    }
    for (name, ruleset) in rulesets.iter_mut() {
        let values = ruleset
            .vars
            .iter()
            .map(|(var, decl)| resolve(name, var, decl, supplied).map(|v| (var.clone(), v)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if let Some(when) = &mut ruleset.when {
            guard(when, &values).map_err(|e| format!("ruleset {name}: when: {e}"))?;
        }
        for (id, raw) in &mut ruleset.rules {
            let Value::Object(entry) = raw else { continue };
            for key in ["expect", "when", "message", "fix"] {
                if let Some(value) = entry.get_mut(key) {
                    fill(value, &values)
                        .map_err(|e| format!("ruleset {name}: rule {id}: {key}: {e}"))?;
                }
            }
            let members = entry
                .get_mut("facts")
                .and_then(Value::as_object_mut)
                .into_iter()
                .flat_map(|f| f.values_mut())
                .filter_map(Value::as_array_mut)
                .flatten();
            for expect in members.filter_map(|m| m.get_mut("expect")) {
                fill(expect, &values)
                    .map_err(|e| format!("ruleset {name}: rule {id}: facts expect: {e}"))?;
            }
        }
    }
    Ok(())
}

/// The value of `var` in `ruleset`: a flag, its `from-env`, `lint.vars`, then its default, typed like the default.
fn resolve(ruleset: &str, var: &str, decl: &Var, supplied: &Supplied) -> Result<Value, String> {
    if var.is_empty()
        || !var
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
    {
        return Err(format!(
            "ruleset {ruleset}: var “{var}” needs a name of letters, digits, _, - and ."
        ));
    }
    let found = supplied
        .flags
        .iter()
        .find_map(|(source, map)| map.get(var).map(|v| (source.clone(), v.clone())));
    let found = found.or_else(|| {
        decl.from_env
            .as_deref()
            .and_then(|env| (supplied.env)(env).map(|v| (format!("${env}"), Value::String(v))))
    });
    let found = found.or_else(|| {
        supplied
            .config
            .get(var)
            .map(|v| ("lint.vars".to_owned(), v.clone()))
    });
    let Some((source, value)) =
        found.or_else(|| decl.default.clone().map(|v| ("its default".to_owned(), v)))
    else {
        let env = decl
            .from_env
            .as_deref()
            .map_or_else(String::new, |e| format!(", set {e}"));
        return Err(format!(
            "ruleset {ruleset}: var {var} has no default and no value; pass --var {var}=VALUE{env} or set lint.vars.{var}"
        ));
    };
    log::debug!("ruleset {ruleset}: var {var} from {source}");
    match (&value, &decl.default) {
        (Value::String(text), Some(Value::Number(_))) => text.trim().parse().map(Value::Number).map_err(|_| format!("ruleset {ruleset}: var {var} from {source}: “{text}” is not a number like its default")),
        (Value::String(text), Some(Value::Bool(_))) => match text.trim() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(format!("ruleset {ruleset}: var {var} from {source}: “{text}” is not true or false like its default")),
        },
        _ => Ok(value),
    }
}

fn guard(when: &mut When, values: &BTreeMap<String, Value>) -> Result<(), String> {
    let maps = match when {
        When::All(map) => vec![map],
        When::Any(maps) => maps.iter_mut().collect(),
    };
    maps.into_iter()
        .flat_map(|m| m.values_mut())
        .try_for_each(|v| fill(v, values))
}

/// Every string under `value` with its `${name}`s filled; object keys stay as written.
fn fill(value: &mut Value, values: &BTreeMap<String, Value>) -> Result<(), String> {
    match value {
        Value::String(text) => *value = substitute(text, values)?,
        Value::Array(items) => items.iter_mut().try_for_each(|v| fill(v, values))?,
        Value::Object(map) => map.values_mut().try_for_each(|v| fill(v, values))?,
        _ => {}
    }
    Ok(())
}

/// `text` with `${name}` filled: a whole-string reference keeps the value’s type, `$${` writes a literal `${`.
fn substitute(text: &str, values: &BTreeMap<String, Value>) -> Result<Value, String> {
    let lookup = |name: &str| {
        values
            .get(name)
            .ok_or_else(|| format!("${{{name}}} is not a var this ruleset declares"))
    };
    if let Some(name) = text
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .filter(|n| !n.contains(['{', '}']))
    {
        return lookup(name).cloned();
    }
    let (mut out, mut rest) = (String::new(), text);
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("$${") {
            out.push_str("${");
            rest = after;
        } else if let Some(after) = rest.strip_prefix("${") {
            let end = after
                .find('}')
                .ok_or_else(|| format!("“{text}” opens ${{ without a closing }}"))?;
            match lookup(&after[..end])? {
                Value::String(s) => out.push_str(s),
                v @ (Value::Number(_) | Value::Bool(_)) => out.push_str(&v.to_string()),
                _ => {
                    return Err(format!(
                        "var {} is not a string, number or boolean, so it fills only a whole value",
                        &after[..end]
                    ));
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push('$');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    Ok(Value::String(out))
}
