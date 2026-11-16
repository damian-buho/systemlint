// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `parse:` steps the core runs around a plugin op: text steps on its inputs, tree steps on its facts.

use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, scalar};

use crate::collector::{Shape, Text, Tree};

/// Each input’s text (a file’s content, a command’s stdout) through `steps`, in order.
pub fn text(steps: &[Text], inputs: &mut [Input]) {
    for input in inputs {
        let name = input.name();
        let content = match input {
            Input::File(file) => file.content.as_mut(),
            Input::Exec(run) => Some(&mut run.stdout),
            Input::Probe(_) => None,
        };
        let Some(content) = content else { continue };
        for step in steps {
            let before = content.len();
            *content = match step {
                Text::Section(header) => section(content, header),
                Text::Skip(lines) => content.split_inclusive('\n').skip(*lines).collect(),
            };
            log::trace!(
                "text step {step:?} on {name}: {before} bytes to {}",
                content.len()
            );
        }
    }
}

/// The indented lines under each line starting with `header`, up to a blank or unindented line.
fn section(content: &str, header: &str) -> String {
    let (mut kept, mut inside) = (String::new(), false);
    for line in content.split_inclusive('\n') {
        if line.starts_with(header) {
            inside = true;
        } else if line.trim().is_empty() || !line.starts_with(char::is_whitespace) {
            inside = false;
        } else if inside {
            kept.push_str(line);
        }
    }
    kept
}

/// `facts` through `steps`, in order, each problem a diagnostic naming its fact path.
pub fn tree(steps: &[Tree], facts: &mut Value, diagnostics: &mut Vec<Diagnostic>) {
    for step in steps {
        let segments: Vec<&str> = step
            .at
            .as_deref()
            .map_or_else(Vec::new, |at| at.split('.').collect());
        let mut matched = 0;
        visit(facts, &segments, String::new(), &mut |value, path| {
            matched += 1;
            shape(&step.shape, value, path, diagnostics);
        });
        log::debug!(
            "tree step {:?} at {:?} matched {matched} facts",
            step.shape,
            step.at
        );
    }
}

/// Calls `f` on every value at `segments` under `value`, `*` matching each key of a map.
fn visit(value: &mut Value, segments: &[&str], path: String, f: &mut dyn FnMut(&mut Value, &str)) {
    let Some((first, rest)) = segments.split_first() else {
        return f(value, &path);
    };
    let Value::Object(map) = value else {
        return log::trace!(
            "tree step path ends at {path:?}, a value, with {} segments left",
            segments.len()
        );
    };
    for (key, child) in map.iter_mut().filter(|(k, _)| *first == "*" || k == first) {
        visit(child, rest, join(&path, key), f);
    }
}

/// `key` appended to the dotted `path`.
fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// One step on the value at `path`: a key step on a map, a value step on each scalar at or below it.
fn shape(step: &Shape, value: &mut Value, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let mut diagnose = |at: &str, message: String| {
        diagnostics.push(Diagnostic {
            path: at.to_owned(),
            line: None,
            message,
        })
    };
    match step {
        Shape::Nest(separator) | Shape::Flatten(separator) => {
            let Value::Object(map) = value else {
                return diagnose(path, format!("{step:?} takes a map, not {value}"));
            };
            let mut out = Map::new();
            for (key, child) in std::mem::take(map) {
                let placed = match step {
                    Shape::Nest(_) => nest(&mut out, &key, *separator, child),
                    _ => flatten(&mut out, key, *separator, child),
                };
                if let Err(message) = placed {
                    diagnose(path, message);
                }
            }
            *map = out;
        }
        _ => leaves(value, path, &mut |leaf, at| {
            if let Err(message) = convert(step, leaf) {
                diagnose(at, message);
            }
        }),
    }
}

/// Calls `f` on every scalar at or below `value`.
fn leaves(value: &mut Value, path: &str, f: &mut dyn FnMut(&mut Value, &str)) {
    match value {
        Value::Object(map) => map
            .iter_mut()
            .for_each(|(k, v)| leaves(v, &join(path, k), f)),
        Value::Array(items) => items
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| leaves(v, &join(path, &i.to_string()), f)),
        _ => f(value, path),
    }
}

/// Places `value` at `key` split on `separator` in `map`, refusing a key that crosses a value.
fn nest(
    map: &mut Map<String, Value>,
    key: &str,
    separator: char,
    value: Value,
) -> Result<(), String> {
    let segments: Vec<&str> = key.split(separator).collect();
    let (last, parents) = segments.split_last().ok_or("empty key")?;
    let mut at = map;
    for segment in parents {
        at = at
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| format!("{key} crosses {segment}, which holds a value"))?;
    }
    if at.get(*last).is_some_and(Value::is_object) {
        return Err(format!("{key} holds both a value and keys below it"));
    }
    at.insert((*last).to_owned(), value);
    Ok(())
}

/// Places every value below `value` in `out` under its keys joined on `separator`, refusing a key already there.
fn flatten(
    out: &mut Map<String, Value>,
    key: String,
    separator: char,
    value: Value,
) -> Result<(), String> {
    match value {
        Value::Object(map) if !map.is_empty() => map
            .into_iter()
            .try_for_each(|(k, v)| flatten(out, format!("{key}{separator}{k}"), separator, v)),
        value if out.contains_key(&key) => Err(format!("{key} is already a key; {value} not kept")),
        value => {
            out.insert(key, value);
            Ok(())
        }
    }
}

/// One scalar through a value step, left unchanged with the reason when it does not fit.
fn convert(step: &Shape, leaf: &mut Value) -> Result<(), String> {
    let text = match leaf {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Ok(()),
    };
    *leaf = match step {
        Shape::Split(by, fields) => split(&text, by.as_deref(), fields.as_deref())?,
        Shape::Bytes if leaf.is_number() => return Ok(()),
        Shape::Bytes => bytes(&text)?,
        Shape::Ranges(by) => ranges(&text, by)?,
        Shape::Nest(_) | Shape::Flatten(_) => return Ok(()),
    };
    Ok(())
}

/// `text` split on blanks or a literal into typed words, as a list or a map of `fields`.
fn split(text: &str, by: Option<&str>, fields: Option<&[String]>) -> Result<Value, String> {
    let words: Vec<Value> = match by {
        None => text.split_whitespace().map(scalar).collect(),
        Some(literal) => text.split(literal).map(|w| scalar(w.trim())).collect(),
    };
    let Some(fields) = fields else {
        return Ok(Value::Array(words));
    };
    if words.len() != fields.len() {
        return Err(format!(
            "{text:?} holds {} fields, not the {} named",
            words.len(),
            fields.len()
        ));
    }
    Ok(Value::Object(fields.iter().cloned().zip(words).collect()))
}

/// The binary multiple each unit names, as the kernel prints `kB` for 1024 bytes.
const UNITS: &[(&str, u32)] = &[
    ("b", 0),
    ("k", 1),
    ("kb", 1),
    ("kib", 1),
    ("m", 2),
    ("mb", 2),
    ("mib", 2),
    ("g", 3),
    ("gb", 3),
    ("gib", 3),
    ("t", 4),
    ("tb", 4),
    ("tib", 4),
];

/// `<integer> <unit>` as a number of bytes; an integer with no unit stays as it is.
fn bytes(text: &str) -> Result<Value, String> {
    let text = text.trim();
    let digits = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(digits);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("{text:?} is not an integer and a unit"))?;
    let unit = unit.trim().to_ascii_lowercase();
    if unit.is_empty() {
        return Ok(scalar(text));
    }
    let power = UNITS
        .iter()
        .find(|(name, _)| *name == unit)
        .map(|(_, p)| *p)
        .ok_or_else(|| format!("{text:?} has unit {unit:?}, none of B, K, M, G, T (binary)"))?;
    1024_u64
        .checked_pow(power)
        .and_then(|m| number.checked_mul(m))
        .filter(|n| i64::try_from(*n).is_ok())
        .map(Value::from)
        .ok_or_else(|| format!("{text:?} is too many bytes to count"))
}

/// `a-b` and `a` items between `by` as `[{from, to}]`, an empty text none.
fn ranges(text: &str, by: &str) -> Result<Value, String> {
    let mut out = Vec::new();
    for item in text.split(by).map(str::trim).filter(|i| !i.is_empty()) {
        let (from, to) = item.split_once('-').unwrap_or((item, item));
        let parse = |n: &str| {
            n.trim()
                .parse::<u64>()
                .map_err(|_| format!("{item:?} is not a number or a-b range"))
        };
        let (from, to) = (parse(from)?, parse(to)?);
        if from > to {
            return Err(format!("{item:?} runs backwards"));
        }
        out.push(serde_json::json!({"from": from, "to": to}));
    }
    Ok(Value::Array(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::Parse;
    use serde_json::json;
    use systemlint_protocol::FileInput;

    fn parse(steps: Value) -> Parse {
        serde_json::from_value(steps).unwrap()
    }

    fn shaped(steps: Value, facts: Value) -> (Value, Vec<String>) {
        let (mut facts, mut diagnostics) = (facts, Vec::new());
        tree(&parse(steps).tree, &mut facts, &mut diagnostics);
        (
            facts,
            diagnostics
                .into_iter()
                .map(|d| format!("{}: {}", d.path, d.message))
                .collect(),
        )
    }

    fn texted(steps: Value, content: &str) -> String {
        let mut inputs = [Input::File(FileInput {
            path: "/f".into(),
            content: Some(content.into()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        })];
        text(&parse(steps).text, &mut inputs);
        match &inputs[0] {
            Input::File(f) => f.content.clone().unwrap(),
            _ => unreachable!(),
        }
    }

    const OP: &str = r#"{"plugin": "formats", "op": "kv"}"#;

    fn op() -> Value {
        serde_json::from_str(OP).unwrap()
    }

    #[test]
    fn section_keeps_the_indented_lines_under_each_header_only() {
        let steps = json!([{"section": "Matching"}, op()]);
        assert_eq!(
            texted(
                steps.clone(),
                "Matching a:\n    x=1\n  y=2\n\n    z=3\nMatching b:\n    w=4\nOther:\n    v=5\n"
            ),
            "    x=1\n  y=2\n    w=4\n"
        );
        assert_eq!(texted(steps, "no header\n    x=1\n"), "");
    }

    #[test]
    fn skip_drops_the_first_lines_and_past_the_end_leaves_nothing() {
        assert_eq!(texted(json!([{"skip": 0}, op()]), "a\nb\n"), "a\nb\n");
        assert_eq!(texted(json!([{"skip": 1}, op()]), "a\nb"), "b");
        assert_eq!(texted(json!([{"skip": 3}, op()]), "a\nb\n"), "");
    }

    #[test]
    fn nest_and_flatten_undo_each_other_and_name_a_collision() {
        let flat = json!({"a.b": 1, "a.c.d": 2, "e": {}});
        let (nested, said) = shaped(json!([op(), {"nest": "."}]), flat.clone());
        assert_eq!(nested, json!({"a": {"b": 1, "c": {"d": 2}}, "e": {}}));
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(
            shaped(json!([op(), {"flatten": "."}]), nested).0,
            flat,
            "an empty map stays a value"
        );
        let (crossed, said) = shaped(json!([op(), {"nest": "."}]), json!({"a": 1, "a.b": 2}));
        assert_eq!((crossed, said.len()), (json!({"a": 1}), 1));
        let (kept, said) = shaped(
            json!([op(), {"flatten": "."}]),
            json!({"a.b": 1, "a": {"b": 2}}),
        );
        assert_eq!(
            (kept, said.len()),
            (json!({"a.b": 2}), 1),
            "the first key in order wins"
        );
    }

    #[test]
    fn split_types_each_field_and_leaves_a_miscount_named() {
        let at = |s: Value| json!([op(), s]);
        assert_eq!(
            shaped(
                at(json!({"split": "whitespace", "fields": ["min", "max"]})),
                json!({"r": "2000\t65535"})
            )
            .0,
            json!({"r": {"min": 2000, "max": 65535}})
        );
        assert_eq!(
            shaped(at(json!({"split": ","})), json!({"r": "a,,0644"})).0,
            json!({"r": ["a", "", "0644"]}),
            "an empty field is kept"
        );
        assert_eq!(
            shaped(at(json!({"split": "whitespace"})), json!({"r": "", "n": 7})).0,
            json!({"r": [], "n": [7]})
        );
        let (kept, said) = shaped(
            at(json!({"split": "whitespace", "fields": ["a", "b"]})),
            json!({"r": "1 2 3"}),
        );
        assert_eq!(
            (kept, said),
            (
                json!({"r": "1 2 3"}),
                vec![r#"r: "1 2 3" holds 3 fields, not the 2 named"#.to_owned()]
            )
        );
    }

    #[test]
    fn bytes_counts_binary_units_and_leaves_a_bare_number() {
        let (facts, said) = shaped(
            json!([op(), {"unit": "bytes"}]),
            json!({"MemTotal": "31943104 kB", "H": 0, "G": "1G", "B": "0 B", "Z": "0644"}),
        );
        assert_eq!(
            facts,
            json!({"MemTotal": 32_709_738_496_u64, "H": 0, "G": 1_073_741_824, "B": 0, "Z": "0644"})
        );
        assert!(said.is_empty(), "{said:?}");
        let (facts, said) = shaped(
            json!([op(), {"unit": "bytes"}]),
            json!({"x": "3 XB", "y": "9007199254740993 T", "z": "kB"}),
        );
        assert_eq!(
            (facts.clone(), said.len()),
            (
                json!({"x": "3 XB", "y": "9007199254740993 T", "z": "kB"}),
                3
            ),
            "{said:?}"
        );
    }

    #[test]
    fn ranges_read_a_port_list_and_refuse_one_that_runs_backwards() {
        let at = json!([op(), {"ranges": ",", "at": "p"}]);
        assert_eq!(
            shaped(at.clone(), json!({"p": "8080, 9000-9010"})).0,
            json!({"p": [{"from": 8080, "to": 8080}, {"from": 9000, "to": 9010}]})
        );
        assert_eq!(
            shaped(at.clone(), json!({"p": "", "q": 1})).0,
            json!({"p": [], "q": 1}),
            "at names p alone"
        );
        assert_eq!(
            shaped(at.clone(), json!({"p": 22})).0,
            json!({"p": [{"from": 22, "to": 22}]})
        );
        let (kept, said) = shaped(at, json!({"p": "9010-9000"}));
        assert_eq!((kept, said.len()), (json!({"p": "9010-9000"}), 1));
    }

    #[test]
    fn at_matching_nothing_changes_nothing_and_a_star_matches_each_key() {
        let facts = json!({"a": {"x": "1 2", "y": "3 4"}, "b": "5 6"});
        assert_eq!(
            shaped(
                json!([op(), {"split": "whitespace", "at": "c.*"}]),
                facts.clone()
            )
            .0,
            facts
        );
        assert_eq!(
            shaped(
                json!([op(), {"split": "whitespace", "at": "b.x"}]),
                facts.clone()
            )
            .0,
            facts,
            "a value has no keys below it"
        );
        assert_eq!(
            shaped(json!([op(), {"split": "whitespace", "at": "a.*"}]), facts).0,
            json!({"a": {"x": [1, 2], "y": [3, 4]}, "b": "5 6"})
        );
    }

    #[test]
    fn a_parse_list_takes_one_op_text_before_it_and_shapes_after_it() {
        assert_eq!(parse(op()).tree, Vec::new(), "a bare op is a list of one");
        for (steps, says) in [
            (json!([]), "names no plugin op"),
            (json!([op(), op()]), "second op"),
            (json!([op(), {"skip": 1}]), "goes before the op"),
            (json!([{"nest": "."}, op()]), "goes after the op"),
            (json!([op(), {"nest": ".", "flatten": "."}]), "exactly one"),
            (json!([op(), {"split": ""}]), "split is empty"),
            (json!([op(), {"fields": ["a"]}]), "exactly one"),
            (json!([op(), {"nest": ".", "fields": ["a"]}]), "give split"),
            (json!([op(), {"unit": "watts"}]), "not bytes"),
            (json!([op(), {"ranges": ""}]), "ranges is empty"),
            (json!([op(), {"nest": ".", "at": "a.b*"}]), "whole segments"),
            (
                json!([op(), {"nest": ".", "with": {"x": 1}}]),
                "belongs to the op",
            ),
            (
                json!([{"plugin": "formats", "op": "kv", "at": "a"}]),
                "belongs to a tree step",
            ),
            (json!([{"op": "kv"}]), "go together"),
            (json!([{"section": ""}, op()]), "section is empty"),
            (json!([op(), {"sort": true}]), "unknown field"),
            (json!("kv"), "neither an op nor a list"),
        ] {
            let error = serde_json::from_value::<Parse>(steps.clone())
                .unwrap_err()
                .to_string();
            assert!(error.contains(says), "{steps}: {error}");
        }
    }
}
