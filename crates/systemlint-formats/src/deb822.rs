// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! deb822 paragraphs as apt reads them: `Name: value`, continuation lines, `#` comments, blank-line separators.

use serde_json::{Map, Value};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::text;

/// Every input’s paragraphs in order under its path, each `{line, fields}` with its values as text, a clear-signed text read inside its signature.
pub fn deb822(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, content)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let (stanzas, problems) = parse(&unsign(content));
        reply
            .diagnostics
            .extend(problems.into_iter().map(|(line, message)| Diagnostic {
                path: path.to_owned(),
                line: Some(line),
                message,
            }));
        let paragraphs = stanzas.into_iter().map(|stanza| {
            let mut fields = Map::new();
            for field in stanza.fields {
                fields.entry(field.name).or_insert(Value::from(field.value));
            }
            Value::Object(Map::from_iter([
                ("line".to_owned(), Value::from(stanza.line)),
                ("fields".to_owned(), Value::Object(fields)),
            ]))
        });
        reply
            .facts
            .insert(path.to_owned(), Value::Array(paragraphs.collect()));
    }
    reply
}

/// One `Name: value` field, continuation lines joined by `\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: String,
}

/// One paragraph and the line it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stanza {
    pub line: u64,
    pub fields: Vec<Field>,
}

impl Stanza {
    /// The first value of field `name`, compared case-insensitively as apt does.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value.as_str())
    }
}

/// Every paragraph of `text`, and `(line, message)` for each line that is no field.
pub fn parse(text: &str) -> (Vec<Stanza>, Vec<(u64, String)>) {
    let (mut stanzas, mut problems) = (Vec::<Stanza>::new(), Vec::new());
    let mut open = false;
    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        if line.trim().is_empty() {
            open = false;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            match stanzas
                .last_mut()
                .filter(|_| open)
                .and_then(|s| s.fields.last_mut())
            {
                Some(field) => {
                    let more = line.trim();
                    field.value.push('\n');
                    field.value.push_str(if more == "." { "" } else { more });
                }
                None => problems.push((
                    number,
                    "a continuation line with no field above it".to_owned(),
                )),
            }
            continue;
        }
        let Some((name, value)) = line
            .split_once(':')
            .filter(|(n, _)| !n.is_empty() && !n.contains(char::is_whitespace))
        else {
            problems.push((number, format!("no Name: value in {line:?}")));
            continue;
        };
        if !open {
            stanzas.push(Stanza {
                line: number,
                fields: Vec::new(),
            });
            open = true;
        }
        if let Some(stanza) = stanzas.last_mut() {
            stanza.fields.push(Field {
                name: name.to_owned(),
                value: value.trim().to_owned(),
            });
        }
    }
    (stanzas, problems)
}

/// The signed text inside a PGP clear-signed message, dash-escapes removed; other text as is.
pub fn unsign(text: &str) -> String {
    if !text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        return text.to_owned();
    }
    let body = text
        .split_once("\n\n")
        .or_else(|| text.split_once("\r\n\r\n"))
        .map_or("", |(_, b)| b);
    let body = body
        .split("\n-----BEGIN PGP SIGNATURE-----")
        .next()
        .unwrap_or_default();
    body.lines()
        .map(|l| l.strip_prefix("- ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// apt’s boolean reading of `value`, or `None` when it is no boolean word.
pub fn boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "with" | "on" | "enable" | "1" => Some(true),
        "no" | "false" | "without" | "off" | "disable" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use systemlint_protocol::FileInput;

    #[test]
    fn the_op_lists_paragraphs_per_path_as_text_reading_inside_a_signature() {
        let release = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nVersion: 26.04\nInstalled-Size: 12\n- Description: x\n\nPackage: a\nPackage: b\nbad line\n-----BEGIN PGP SIGNATURE-----\nabc\n";
        let reply = deb822(&[Input::File(FileInput {
            path: "/var/lib/apt/lists/x_InRelease".into(),
            content: Some(release.into()),
            content_base64: None,
            stat: None,
            statfs: None,
            absent: false,
        })]);
        assert_eq!(
            reply.facts["/var/lib/apt/lists/x_InRelease"],
            json!([
                {"line": 1, "fields": {"Origin": "Ubuntu", "Version": "26.04", "Installed-Size": "12", "Description": "x"}},
                {"line": 6, "fields": {"Package": "a"}},
            ])
        );
        assert_eq!(reply.diagnostics[0].line, Some(8));
    }

    #[test]
    fn paragraphs_split_on_blank_lines_and_skip_comments() {
        let (stanzas, problems) = parse(
            "# head\nTypes: deb\n# inside\nURIs: https://a/\n  \nTypes: deb-src\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n abc\n",
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(stanzas.iter().map(|s| s.line).collect::<Vec<_>>(), [2, 6]);
        assert_eq!(stanzas[0].get("uris"), Some("https://a/"));
        assert_eq!(
            stanzas[1].get("Signed-By"),
            Some("\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc")
        );
    }

    #[test]
    fn stray_lines_are_named() {
        let (stanzas, problems) = parse(" orphan\nTypes deb\nTypes: deb\n");
        assert_eq!(stanzas.len(), 1);
        assert_eq!(problems.iter().map(|p| p.0).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn unsign_keeps_only_the_signed_text() {
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSuite: x\n- -dash\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n";
        assert_eq!(unsign(signed), "Suite: x\n-dash");
        assert_eq!(unsign("Suite: y\n"), "Suite: y\n");
    }

    #[test]
    fn booleans_follow_apt() {
        assert_eq!(
            (boolean("Yes"), boolean("no"), boolean("maybe")),
            (Some(true), Some(false), None)
        );
    }
}
