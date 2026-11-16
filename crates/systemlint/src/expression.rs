// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `x-cel` schema keyword: a CEL expression over `self`, `facts`, `vars` and `bound` that must be true.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use ::cel::objects::{Key, Map as CelMap};
use ::cel::{Context, Env, Program, RuntimeOptions, Value as Cel};
use jsonschema::paths::Location;
use jsonschema::{Keyword, ValidationError};
use serde_json::{Map, Value};

/// The longest expression a rule may give, in characters.
pub const MAX_LENGTH: usize = 1000;

/// The comprehension iterations (`all`, `exists`, `map`, `filter`) one evaluation may take.
pub const MAX_ITERATIONS: u64 = 10_000;

/// The names an expression may read: its bindings and CEL’s type names.
const NAMES: &[&str] = &[
    "self",
    "facts",
    "vars",
    "bound",
    "int",
    "uint",
    "double",
    "bool",
    "string",
    "bytes",
    "list",
    "map",
    "null_type",
    "type",
    "dyn",
];

/// The document and subject the expressions of one check read, and the first that could not decide.
struct Scope {
    facts: Option<Cel>,
    bound: Cel,
    unknown: Option<String>,
}

thread_local! {
    static SCOPE: RefCell<Scope> = const { RefCell::new(Scope { facts: None, bound: Cel::Null, unknown: None }) };
}

/// The one environment every expression compiles and runs in: the standard library under the iteration budget.
fn env() -> &'static Arc<Env> {
    static ENV: OnceLock<Arc<Env>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Env::stdlib();
        env.set_options(RuntimeOptions::default().with_max_iterations(MAX_ITERATIONS));
        Arc::new(env)
    })
}

/// Runs `f` with `document` as every expression’s `facts`.
pub fn with_facts<T>(document: &Value, f: impl FnOnce() -> T) -> T {
    let facts = convert(document);
    let before = SCOPE.with(|s| s.borrow_mut().facts.replace(facts));
    let out = f();
    SCOPE.with(|s| {
        let mut scope = s.borrow_mut();
        scope.facts = before;
        scope.unknown = None;
    });
    out
}

/// Runs `f` with `bound` as every expression’s `bound`, returning why an expression could not decide, if one could not.
pub fn deciding<T>(bound: &[String], f: impl FnOnce() -> T) -> (T, Option<String>) {
    let list = Cel::List(Arc::new(
        bound.iter().map(|k| Cel::from(k.as_str())).collect(),
    ));
    let before = SCOPE.with(|s| {
        let mut scope = s.borrow_mut();
        (
            std::mem::replace(&mut scope.bound, list),
            scope.unknown.take(),
        )
    });
    let out = f();
    let unknown = SCOPE.with(|s| {
        let mut scope = s.borrow_mut();
        scope.bound = before.0;
        std::mem::replace(&mut scope.unknown, before.1)
    });
    (out, unknown)
}

/// A JSON value as CEL reads it: an integer that fits stays an `int`, so `self * 2` never meets a `uint`.
fn convert(value: &Value) -> Cel {
    match value {
        Value::Null => Cel::Null,
        Value::Bool(b) => Cel::Bool(*b),
        Value::Number(n) => n
            .as_i64()
            .map(Cel::Int)
            .or_else(|| n.as_u64().map(Cel::UInt))
            .unwrap_or_else(|| Cel::Float(n.as_f64().unwrap_or(f64::NAN))),
        Value::String(s) => Cel::from(s.as_str()),
        Value::Array(items) => Cel::List(Arc::new(items.iter().map(convert).collect())),
        Value::Object(map) => Cel::Map(CelMap {
            map: Arc::new(
                map.iter()
                    .map(|(k, v)| (Key::String(Arc::new(k.clone())), convert(v)))
                    .collect::<HashMap<_, _>>(),
            ),
        }),
    }
}

/// One compiled `x-cel` keyword and the vars it reads.
struct XCel {
    source: String,
    program: Program,
    vars: Cel,
}

impl XCel {
    /// `Some(answer)` when the expression decides on `instance`, else `None` with the reason noted for the check.
    fn decide(&self, instance: &Value) -> Option<bool> {
        let mut context = Context::with_env(Arc::clone(env()));
        let (facts, bound) = SCOPE.with(|s| {
            let scope = s.borrow();
            (scope.facts.clone(), scope.bound.clone())
        });
        context.add_variable_from_value("self", convert(instance));
        context.add_variable_from_value(
            "facts",
            facts.unwrap_or(Cel::Map(CelMap {
                map: Arc::default(),
            })),
        );
        context.add_variable_from_value("vars", self.vars.clone());
        context.add_variable_from_value("bound", bound);
        let reason = match self.program.execute(&context) {
            Ok(Cel::Bool(answer)) => return Some(answer),
            Ok(other) => format!("x-cel {:?} gives {other:?}, not true or false", self.source),
            Err(error) => format!("x-cel {:?} could not decide: {error}", self.source),
        };
        log::debug!("{reason}");
        SCOPE.with(|s| {
            s.borrow_mut().unknown.get_or_insert(reason);
        });
        None
    }
}

impl<'i> Keyword<'i> for XCel {
    fn validate(&self, instance: &'i Value) -> Result<(), ValidationError<'i>> {
        match self.decide(instance) {
            Some(false) => Err(ValidationError::custom(format!(
                "{instance} does not satisfy {}",
                self.source
            ))),
            _ => Ok(()),
        }
    }

    fn is_valid(&self, instance: &'i Value) -> bool {
        self.decide(instance) != Some(false)
    }
}

/// Compiles `x-cel`: the expression text, or `{expr, vars}` as `vars::apply` writes it, refusing one too long, unparsable or reading an unknown name.
pub fn keyword<'a>(
    _parent: &'a Map<String, Value>,
    value: &'a Value,
    _path: Location,
) -> Result<Box<dyn for<'i> Keyword<'i>>, ValidationError<'a>> {
    let refuse = |message: String| ValidationError::custom(format!("x-cel {message}"));
    let (source, vars) = match value {
        Value::String(source) => (source, Map::new()),
        Value::Object(map) => match (map.get("expr"), map.get("vars"), map.len()) {
            (Some(Value::String(source)), Some(Value::Object(vars)), 2) => (source, vars.clone()),
            _ => {
                return Err(refuse(
                    "is neither an expression nor {expr, vars}".to_owned(),
                ));
            }
        },
        _ => return Err(refuse(format!("{value} is not an expression"))),
    };
    if source.chars().count() > MAX_LENGTH {
        return Err(refuse(format!("is longer than {MAX_LENGTH} characters")));
    }
    let program = env()
        .compile(source)
        .map_err(|e| refuse(format!("{source:?} does not parse: {e}")))?;
    if let Some(name) = program
        .references()
        .variables()
        .into_iter()
        .find(|n| !NAMES.contains(n))
    {
        return Err(refuse(format!(
            "{source:?} reads {name}; it may read self, facts, vars and bound"
        )));
    }
    Ok(Box::new(XCel {
        source: source.clone(),
        program,
        vars: convert(&Value::Object(vars)),
    }))
}
