// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The `rainerscript` family: rsyslog’s configuration, its legacy `$` directives, objects and selector lines.

use serde_json::{Map, Value, json};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::text;

/// Every input’s `legacy` directives, `objects` and `selectors`, keyed by its path.
pub fn rainerscript(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, content)) = text(input, &mut reply.diagnostics) else {
            continue;
        };
        let mut scan = Scan {
            chars: content.chars().collect(),
            at: 0,
            line: 1,
            legacy: Map::new(),
            objects: Vec::new(),
            selectors: Vec::new(),
            unread: Vec::new(),
        };
        scan.statements();
        for line in scan.unread {
            reply.diagnostics.push(Diagnostic {
                path: path.to_owned(),
                line: Some(line),
                message: "no statement rsyslog reads, skipped".to_owned(),
            });
        }
        reply.facts.insert(
            path.to_owned(),
            json!({"legacy": scan.legacy, "objects": scan.objects, "selectors": scan.selectors}),
        );
    }
    reply
}

/// A cursor over one file and what it has read so far.
struct Scan {
    chars: Vec<char>,
    at: usize,
    line: u64,
    legacy: Map<String, Value>,
    objects: Vec<Value>,
    selectors: Vec<Value>,
    unread: Vec<u64>,
}

impl Scan {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        self.line += u64::from(c == '\n');
        Some(c)
    }

    /// Skips blanks, `#` and `/* */` comments, and line ends when `newlines` is set.
    fn skip(&mut self, newlines: bool) {
        while let Some(c) = self.peek() {
            match c {
                '\n' if !newlines => return,
                ' ' | '\t' | '\r' | '\n' => drop(self.bump()),
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                '/' if self.chars.get(self.at + 1) == Some(&'*') => {
                    self.at += 2;
                    while self.peek().is_some()
                        && !(self.peek() == Some('*') && self.chars.get(self.at + 1) == Some(&'/'))
                    {
                        self.bump();
                    }
                    self.at = (self.at + 2).min(self.chars.len());
                }
                _ => return,
            }
        }
    }

    /// The text up to the line end or a `#`, trimmed.
    fn rest_of_line(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek().filter(|c| *c != '\n' && *c != '#') {
            out.push(c);
            self.bump();
        }
        out.trim().to_owned()
    }

    /// One word up to a blank, `(`, `{`, `}` or `#`, a `\` at a line end joining the next line.
    fn word(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            match c {
                '\\' if self.chars.get(self.at + 1) == Some(&'\n') => {
                    self.at += 1;
                    self.bump();
                    self.skip(false);
                }
                ' ' | '\t' | '\r' | '\n' | '(' | '{' | '}' | '#' => break,
                _ => {
                    out.push(c);
                    self.bump();
                }
            }
        }
        out
    }

    /// Every statement to the end of the file.
    fn statements(&mut self) {
        loop {
            self.skip(true);
            let Some(c) = self.peek() else { return };
            let line = self.line;
            match c {
                '{' | '}' => drop(self.bump()),
                '$' => {
                    self.bump();
                    let name = self.word().to_lowercase();
                    let value = self.rest_of_line();
                    let kept = self
                        .legacy
                        .entry(name)
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Value::Array(values) = kept {
                        values.push(json!({"value": value, "line": line}));
                    }
                }
                '&' => {
                    self.bump();
                    let filters = self
                        .selectors
                        .last()
                        .map_or(json!([]), |s| s["filters"].clone());
                    self.selector(json!({"filters": filters}), line);
                }
                ':' => {
                    let mut expression = String::new();
                    while let Some(c) = self.peek().filter(|c| *c != '"' && *c != '\n') {
                        expression.push(c);
                        self.bump();
                    }
                    expression.push_str(&format!("{:?}", self.quoted()));
                    self.selector(json!({"filters": [], "expression": expression}), line);
                }
                _ => self.keyword(line),
            }
        }
    }

    /// A statement opening with a word: a control word, an object, or a selector.
    fn keyword(&mut self, line: u64) {
        let word = self.word();
        match word.as_str() {
            "" => {
                self.bump();
                self.unread.push(line);
            }
            "if" => {
                let expression = self.until("then");
                self.selector(json!({"filters": [], "expression": expression}), line);
            }
            "else" => self.selector(json!({"filters": [], "expression": "else"}), line),
            "foreach" => drop(self.until("do")),
            "stop" | "continue" => {}
            "call" | "call_indirect" | "reload_lookup_table" => drop(self.rest_of_line()),
            "set" | "unset" => while self.bump().is_some_and(|c| c != ';') {},
            _ if self.peek() == Some('(') => {
                let object = self.object(&word, line);
                self.objects.push(object);
            }
            _ if word.contains('.') => {
                let filters: Vec<Value> = word
                    .split(';')
                    .filter(|f| !f.is_empty())
                    .map(|f| {
                        let (facilities, priority) = f.rsplit_once('.').unwrap_or((f, ""));
                        let facilities: Vec<String> =
                            facilities.split(',').map(str::to_lowercase).collect();
                        json!({"facilities": facilities, "priority": priority.to_lowercase()})
                    })
                    .collect();
                self.selector(json!({"filters": filters}), line);
            }
            _ => {
                self.rest_of_line();
                self.unread.push(line);
            }
        }
    }

    /// The text up to the word `stop`, outside quotes, which is consumed.
    fn until(&mut self, stop: &str) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == '"' || c == '\'' {
                out.push_str(&format!("{:?}", self.quoted()));
                continue;
            }
            let ahead: String = self.chars[self.at..].iter().take(stop.len() + 1).collect();
            let before = out
                .chars()
                .last()
                .is_none_or(|b| b.is_whitespace() || b == ')');
            if before
                && ahead.starts_with(stop)
                && ahead[stop.len()..]
                    .chars()
                    .all(|a| a.is_whitespace() || a == '{')
            {
                self.at += stop.len();
                break;
            }
            out.push(c);
            self.bump();
        }
        out.trim().to_owned()
    }

    /// Records the action after a filter as a selector, unless it is a block, `stop` or a discard.
    fn selector(&mut self, mut selector: Value, line: u64) {
        self.skip(true);
        let start = self.line;
        let action = match self.peek() {
            Some('{') | None => return,
            _ => {
                let at = self.at;
                let word = self.word();
                if self.peek() == Some('(')
                    && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    let object = self.object(&word, start);
                    self.objects.push(object.clone());
                    object
                } else {
                    self.at = at;
                    Value::from(self.rest_of_line())
                }
            }
        };
        if matches!(action.as_str(), Some("" | "~" | "stop")) {
            return;
        }
        selector["action"] = action;
        selector["line"] = Value::from(line);
        self.selectors.push(selector);
    }

    /// One `name(key="value" …)` object, its keys lowercased as rsyslog compares them.
    fn object(&mut self, name: &str, line: u64) -> Value {
        self.bump();
        let mut params = Map::new();
        loop {
            self.skip(true);
            match self.peek() {
                Some(')') => {
                    self.bump();
                    break;
                }
                None => {
                    self.unread.push(line);
                    break;
                }
                _ => {}
            }
            let mut key = String::new();
            while let Some(c) = self
                .peek()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                key.push(c);
                self.bump();
            }
            if key.is_empty() {
                self.bump();
                self.unread.push(self.line);
                continue;
            }
            self.skip(true);
            if self.peek() == Some('=') {
                self.bump();
                self.skip(true);
            }
            let value = self.value();
            params.insert(key.to_lowercase(), value);
        }
        json!({"type": name.to_lowercase(), "params": params, "line": line})
    }

    /// A quoted string, a `[…]` list of values, or a bare word.
    fn value(&mut self) -> Value {
        match self.peek() {
            Some('"' | '\'') => Value::from(self.quoted()),
            Some('[') => {
                self.bump();
                let mut items = Vec::new();
                loop {
                    self.skip(true);
                    match self.peek() {
                        Some(']') | None => {
                            self.bump();
                            break;
                        }
                        Some(',') => drop(self.bump()),
                        _ => items.push(self.value()),
                    }
                }
                Value::from(items)
            }
            _ => {
                let mut out = String::new();
                while let Some(c) = self
                    .peek()
                    .filter(|c| !c.is_whitespace() && !matches!(c, ')' | ',' | ']'))
                {
                    out.push(c);
                    self.bump();
                }
                Value::from(out)
            }
        }
    }

    /// The text between a pair of the quote at the cursor, `\` escaping the next character.
    fn quoted(&mut self) -> String {
        let Some(quote) = self.bump() else {
            return String::new();
        };
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '\\' => out.extend(self.bump()),
                c if c == quote => break,
                c => out.push(c),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> (Value, Vec<Option<u64>>) {
        let file = serde_json::from_value(json!({"path": "/f", "content": text})).unwrap();
        let reply = rainerscript(&[Input::File(file)]);
        (
            reply.facts["/f"].clone(),
            reply.diagnostics.iter().map(|d| d.line).collect(),
        )
    }

    #[test]
    fn ubuntus_stock_files_read_whole() {
        let (facts, unread) = run(concat!(
            "module(load=\"imuxsock\") # local logging\n",
            "module(load=\"imklog\" permitnonkernelfacility=\"on\")\n",
            "$FileCreateMode 0640\n",
            "$IncludeConfig /etc/rsyslog.d/*.conf\n",
            ":msg,contains,\"[UFW \" /var/log/ufw.log\n",
            "auth,authpriv.*\t\t\t/var/log/auth.log\n",
            "*.*;auth,authpriv.none\t\t-/var/log/syslog\n",
            "*.emerg\t\t\t\t:omusrmsg:*\n",
            "#mail.info -/var/log/mail.info\n",
        ));
        assert_eq!(unread, Vec::<Option<u64>>::new());
        assert_eq!(
            facts["legacy"]["filecreatemode"],
            json!([{"value": "0640", "line": 3}])
        );
        assert_eq!(
            facts["objects"][1],
            json!({"type": "module", "params": {"load": "imklog", "permitnonkernelfacility": "on"}, "line": 2})
        );
        assert_eq!(
            facts["selectors"][0],
            json!({"filters": [], "expression": ":msg,contains,\"[UFW \"", "action": "/var/log/ufw.log", "line": 5})
        );
        assert_eq!(
            facts["selectors"][2],
            json!({"filters": [{"facilities": ["*"], "priority": "*"}, {"facilities": ["auth", "authpriv"], "priority": "none"}], "action": "-/var/log/syslog", "line": 7})
        );
        assert_eq!(facts["selectors"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn objects_span_lines_and_an_if_records_its_action() {
        let (facts, unread) = run(concat!(
            "/* forward */ if $programname == 'then x' then {\n",
            "  action(type=\"omfwd\" Target=\"logs.example\"\n",
            "         Protocol=\"tcp\" StreamDriverMode=\"1\" queue.filename=[\"a\", \"b\"])\n",
            "  stop\n",
            "}\n",
            "else @logs.example:514\n",
            "mail.*;\\\n  news.none @@host\n",
            "& stop\n",
            "set $!x = \"y\";\n",
            "if $programname == 'then x' then /var/log/x\n",
        ));
        assert_eq!(unread, Vec::<Option<u64>>::new());
        assert_eq!(
            facts["objects"][0],
            json!({"type": "action", "params": {"type": "omfwd", "target": "logs.example", "protocol": "tcp", "streamdrivermode": "1", "queue.filename": ["a", "b"]}, "line": 2})
        );
        assert_eq!(
            facts["selectors"][0],
            json!({"filters": [], "expression": "else", "action": "@logs.example:514", "line": 6})
        );
        assert_eq!(
            facts["selectors"][1]["filters"][1],
            json!({"facilities": ["news"], "priority": "none"})
        );
        assert_eq!(facts["selectors"][1]["action"], "@@host");
        assert_eq!(
            facts["selectors"][2],
            json!({"filters": [], "expression": "$programname == \"then x\"", "action": "/var/log/x", "line": 11})
        );
        assert_eq!(facts["selectors"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_line_it_cannot_read_is_named_and_the_next_still_read() {
        let (facts, unread) = run("bogus line here\n$Umask 0022\nmodule(load=\"x\"\n");
        assert_eq!(unread, [Some(1), Some(3)]);
        assert_eq!(facts["legacy"]["umask"][0]["value"], "0022");
    }
}
