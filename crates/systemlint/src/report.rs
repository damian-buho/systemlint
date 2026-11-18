// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Check output in every format and the `--fail-on` threshold.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::str::FromStr;

use serde_json::{Value, json};

use crate::judge::{Check, Outcome, band};
use crate::rules::{Fix, Severity, Step};

/// The failures that make `check` exit 1: at or above a level, at or above a score, or never.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FailOn {
    Level(Severity),
    Score(f64),
    Never,
}

impl FromStr for FailOn {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "never" => Ok(Self::Never),
            "error" => Ok(Self::Level(Severity::Error)),
            "warning" => Ok(Self::Level(Severity::Warning)),
            "info" => Ok(Self::Level(Severity::Info)),
            "advice" => Ok(Self::Level(Severity::Advice)),
            _ => match text.parse::<f64>() {
                Ok(score) if (0.1..=9.9).contains(&score) => Ok(Self::Score(score)),
                _ => Err(format!(
                    "fail-on {text:?} is not error, warning, info, advice, never or a score from 0.1 to 9.9"
                )),
            },
        }
    }
}

impl FailOn {
    /// Whether any check fails at or above this threshold; advice only under `advice` itself.
    pub fn reached(self, checks: &[Check]) -> bool {
        checks
            .iter()
            .filter(|c| {
                c.is_failing()
                    && (c.severity != Some(Severity::Advice)
                        || self == Self::Level(Severity::Advice))
            })
            .any(|c| match self {
                Self::Never => false,
                Self::Level(level) => c.severity >= Some(level),
                Self::Score(score) => c.score.unwrap_or_default() >= score,
            })
    }
}

/// The count of each outcome, waived failures apart.
pub fn summary(checks: &[Check]) -> Value {
    let count = |o: Outcome| checks.iter().filter(|c| c.outcome == o).count();
    let waived = checks
        .iter()
        .filter(|c| c.outcome == Outcome::Fail && !c.is_failing())
        .count();
    json!({"checks": checks.len(), "pass": count(Outcome::Pass), "fail": count(Outcome::Fail) - waived, "waived": waived, "unknown": count(Outcome::Unknown), "skip": count(Outcome::Skip), "not-applicable": count(Outcome::NotApplicable), "manual": count(Outcome::Manual), "conflict": count(Outcome::Conflict)})
}

/// The lowest share passed, in tenths, each grade still reaches, best first; F takes the rest.
const FLOORS: [(f64, char); 5] = [(9.0, 'A'), (7.0, 'B'), (6.0, 'C'), (4.0, 'D'), (2.0, 'E')];

/// Columns a wrapped human line fills at most.
const WIDTH: usize = 80;

/// A run’s grade, S to F, and the share of judged checks it rests on.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Rating {
    pub grade: char,
    pub score: f64,
}

/// What a failure costs the rating: 1 at the warning base, rising with the square of its score.
pub fn weight(score: f64) -> f64 {
    (score / band(Severity::Warning).2).powi(2)
}

/// The grade as spiderlint gives it: S with no failure, else the share passed after costs; an error caps it at B, nothing judged gives none.
pub fn rate(checks: &[Check]) -> Option<Rating> {
    let judged: Vec<&Check> = checks
        .iter()
        .filter(|c| c.outcome == Outcome::Pass || c.is_failing())
        .collect();
    if judged.is_empty() {
        log::debug!("no rating: none of {} checks was judged", checks.len());
        return None;
    }
    let failing: Vec<&&Check> = judged.iter().filter(|c| c.is_failing()).collect();
    let cost: f64 = failing
        .iter()
        .map(|c| weight(c.score.unwrap_or_default()))
        .sum();
    let total = judged.len() as f64;
    let kept = (total - cost).max(0.0);
    let floors = if failing.iter().any(|c| c.severity == Some(Severity::Error)) {
        &FLOORS[1..]
    } else {
        &FLOORS[..]
    };
    let grade = if failing.is_empty() {
        'S'
    } else {
        floors
            .iter()
            .find(|(tenths, _)| kept * 10.0 >= tenths * total)
            .map_or('F', |f| f.1)
    };
    log::debug!(
        "rating {grade}: {} failing of {total} judged cost {cost}",
        failing.len()
    );
    Some(Rating {
        grade,
        score: (kept / total * 10_000.0).round() / 10_000.0,
    })
}

/// Whether to colour the report: `--color` when not auto, else the environment, else whether the stream is a terminal.
pub fn colour(choice: Colour, var: impl Fn(&str) -> Option<String>, terminal: bool) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    let decided = match choice {
        Colour::Always => true,
        Colour::Never => false,
        Colour::Auto if set("SYSTEMLINT_NO_COLOR") || set("NO_COLOR") => false,
        Colour::Auto if set("FORCE_COLOR") => var("FORCE_COLOR").as_deref() != Some("0"),
        Colour::Auto => var("TERM").as_deref() != Some("dumb") && terminal,
    };
    log::debug!("colour {decided} from --color {choice:?}, terminal {terminal}");
    decided
}

/// The `--color` choice, also `check.color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Colour {
    Auto,
    Always,
    Never,
}

/// `text` in an SGR style from the 16-colour palette, or as it is.
fn paint(on: bool, code: &str, text: &str) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// The colour of a value the report names: a path, a quoted word, a container or image.
const VALUE: &str = "36";

/// The style of a line the reader types or writes, shown alone.
const SHOWN: &str = "1";

/// `text` with each “quoted” span and absolute path painted as a value, or as it is.
fn values(on: bool, text: &str) -> String {
    if !on {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('“') {
        out.push_str(&paths(&rest[..open]));
        let after = &rest[open..];
        let close = after.find('”').map_or(after.len(), |c| c + '”'.len_utf8());
        out.push_str(&paint(true, VALUE, &after[..close]));
        rest = &after[close..];
    }
    out + &paths(rest)
}

/// `text` with each word starting with `/` painted as a value, its trailing punctuation left out.
fn paths(text: &str) -> String {
    let mut out = String::new();
    for (i, word) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let start = word.trim_start_matches('(');
        let lead = &word[..word.len() - start.len()];
        let core = start.trim_end_matches(['.', ',', ';', ':', ')']);
        match core.starts_with('/') && core.len() > 1 {
            true => out.push_str(&format!(
                "{lead}{}{}",
                paint(true, VALUE, core),
                &start[core.len()..]
            )),
            false => out.push_str(word),
        }
    }
    out
}

/// A fix’s lines under `indent`: one `Fix:` sentence, or `Fix:` over its numbered steps, each command or file line alone below its step.
fn fix_text(fix: &Fix, indent: &str, on: bool) -> String {
    let steps = match fix {
        Fix::Text(text) => return format!("{indent}Fix: {}\n", values(on, &sentence(text))),
        Fix::Steps(steps) => steps,
    };
    let mut out = format!("{indent}Fix:\n");
    let mut number = 0;
    for step in steps {
        match step {
            Step::Say(text) => {
                number += 1;
                let _ = writeln!(out, "{indent}  {number}. {}", values(on, &sentence(text)));
            }
            Step::Show(shown) => {
                for line in shown.lines() {
                    let _ = writeln!(out, "{indent}       {}", paint(on, SHOWN, line));
                }
            }
        }
    }
    log::debug!("fix of {number} steps");
    out
}

/// The capitalised level word and its colour code: red error, yellow warning, dim info and advice.
fn level_word(severity: Option<Severity>) -> (&'static str, &'static str) {
    match severity {
        Some(Severity::Error) => ("Error", "31"),
        Some(Severity::Warning) => ("Warning", "33"),
        Some(Severity::Info) => ("Info", "2"),
        _ => ("Advice", "2"),
    }
}

/// The skip reason of the collector an `unknown` check waited on, when that collector was skipped.
fn skip_reason<'a>(document: &'a Value, check: &Check) -> Option<&'a str> {
    let outcome = &document["collectors"][check.collector.as_deref()?];
    outcome["reason"]
        .as_str()
        .filter(|_| check.outcome == Outcome::Unknown && outcome["status"] == "skipped")
}

/// Why the collector an `unknown` check waited on failed, when it did.
fn failed<'a>(document: &'a Value, check: &Check) -> Option<&'a str> {
    let outcome = &document["collectors"][check.collector.as_deref()?];
    outcome["reason"]
        .as_str()
        .filter(|_| check.outcome == Outcome::Unknown && outcome["status"] == "error")
}

/// Like [`skip_reason`], unless the collector is an opt-in the user left off, which only the counts show.
fn shown_skip<'a>(document: &'a Value, check: &Check) -> Option<&'a str> {
    let opt_in = document["collectors"][check.collector.as_deref()?]["opt-in"] == true;
    skip_reason(document, check).filter(|_| !opt_in)
}

/// The collector, path and reason of the unreadable path an `unknown` check stands on, when a `partial` collector could not read it.
fn unread<'a>(document: &'a Value, check: &'a Check) -> Option<(&'a str, &'a str, &'a str)> {
    let collector = check.collector.as_deref()?;
    let paths = document["collectors"][collector]["unreadable"].as_object()?;
    check
        .subject
        .iter()
        .filter(|_| check.outcome == Outcome::Unknown)
        .find_map(|key| Some((collector, key.as_str(), paths.get(key)?.as_str()?)))
}

/// Whether `value` is `text` or a list holding it.
fn names(value: Option<&Value>, text: &str) -> bool {
    match value {
        Some(Value::String(s)) => s == text,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(text)),
        _ => false,
    }
}

/// Whether two failures of one rule point at each other, as the two sides of a duplicate do.
fn mirrored(a: &Check, b: &Check) -> bool {
    names(a.value.as_ref(), &b.subject_label()) && names(b.value.as_ref(), &a.subject_label())
}

/// The failures of one rule in clusters, each cluster one problem: a failure alone, or every subject pointing at another.
fn clusters<'a>(checks: &[&'a Check]) -> Vec<Vec<&'a Check>> {
    let mut out: Vec<Vec<&Check>> = Vec::new();
    for check in checks {
        match out
            .iter_mut()
            .find(|cluster| cluster.iter().any(|c| mirrored(c, check)))
        {
            Some(cluster) => cluster.push(check),
            None => out.push(vec![check]),
        }
    }
    log::debug!("{} failures fold into {} problems", checks.len(), out.len());
    out
}

/// What one location adds to its rule’s title: the message without a title, else the field and offending value the message names.
fn detail(check: &Check) -> Option<String> {
    let Some(template) = check.text.as_deref().filter(|_| check.title.is_some()) else {
        return check.message.clone();
    };
    let var = |name: &str| {
        check
            .variables
            .get(name)
            .filter(|_| template.contains(&format!("{{{name}}}")))
            .cloned()
    };
    let got = var("got").filter(|g| g != "none");
    match (var("field"), got) {
        (Some(field), Some(got)) => Some(format!("{field} {got}")),
        (field, got) => field.or(got),
    }
}

/// `text` ended as a sentence: the full stop of its last letter’s script added unless it is empty or already ends with sentence punctuation.
fn sentence(text: &str) -> String {
    match text.chars().last() {
        None | Some('.' | ':' | '!' | '?' | '…' | '。' | '！' | '？' | '؟' | '।' | '॥') => {
            text.to_owned()
        }
        Some(c) => format!("{text}{}", full_stop(c)),
    }
}

/// The full stop of `c`’s script: ideographic for Han and kana, danda for Devanagari, else ASCII.
fn full_stop(c: char) -> char {
    match c {
        '\u{3040}'..='\u{30ff}'
        | '\u{3400}'..='\u{4dbf}'
        | '\u{4e00}'..='\u{9fff}'
        | '\u{f900}'..='\u{faff}' => '。',
        '\u{0900}'..='\u{097f}' => '।',
        _ => '.',
    }
}

/// One `- ` line: the subject painted as a value, then what it adds, either alone when the other is missing.
fn location(subject: &str, detail: Option<&str>, on: bool) -> String {
    let named = paint(on, VALUE, subject);
    match (subject.is_empty(), detail.map(|d| values(on, d))) {
        (false, Some(d)) => format!("- {named}: {d}"),
        (true, Some(d)) => format!("- {d}"),
        (_, None) => format!("- {named}"),
    }
}

/// The log a path was rotated from: its `.N` or dateext `-N` suffix cut, after a compression suffix; none for any other path.
fn rotated_from(path: &str) -> Option<&str> {
    let name = path.rfind('/')? + 1;
    let bare = [".gz", ".xz", ".zst", ".bz2"]
        .iter()
        .find_map(|z| path.strip_suffix(z))
        .unwrap_or(path);
    let (head, tail) = bare.rsplit_once(['.', '-'])?;
    let numbered = !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit());
    (numbered && head.len() > name).then_some(head)
}

/// The header of one rule’s block: label, rule ID in bold, and the title when the rule has one.
fn header(label: &str, check: &Check, on: bool) -> String {
    let id = paint(on, "1", &format!("[{}]", check.rule));
    check.title.as_deref().map_or_else(
        || format!("{label}: {id}"),
        |title| format!("{label}: {id} {}", values(on, title)),
    )
}

/// The image a container’s failing file subject (a `path` or `path:line`) comes from unchanged: absent from the writable layer `meta.subject.changed` lists, and not read from running state.
fn shipped<'a>(document: &'a Value, check: &Check) -> Option<&'a str> {
    let subject = &document["meta"]["subject"];
    let changed = subject["changed"].as_array()?;
    let keys: Vec<String> = check.fact.split('.').map(str::to_owned).collect();
    if crate::judge::producer(document, &keys).is_some_and(|(_, o)| o["live"] == true) {
        log::debug!(
            "{} {}: running state, not the image’s",
            check.rule,
            check.fact
        );
        return None;
    }
    let subject_path = check.subject.last().filter(|p| p.starts_with('/'))?;
    let path = subject_path
        .rsplit_once(':')
        .filter(|(_, line)| line.parse::<u64>().is_ok())
        .map_or(subject_path.as_str(), |(path, _)| path);
    let kept = changed
        .binary_search_by(|p| p.as_str().unwrap_or_default().cmp(path))
        .is_err();
    log::debug!("{} {path}: in the writable layer {}", check.rule, !kept);
    kept.then(|| subject["image"].as_str().unwrap_or("the image"))
}

/// Where a shipped file’s remedy belongs in its image’s build, worded over `{them}`, and the file’s path: set where the file enters the image, never a layer over it.
fn build_step(command: &str, check: &Check) -> (String, String) {
    let subject = check.subject.last().map_or("", String::as_str);
    let path = crate::fix::line_of(subject).map_or(subject, |(path, _)| path);
    let mut words = command.split(' ');
    let advice = match (words.next(), words.next()) {
        (Some("chown" | "chgrp"), _) => "add {them} owned by root, with “COPY --chown=0:0” or “install --owner=root --group=root”".to_owned(),
        (Some("chmod"), Some(spec)) => match target_mode(check, spec) {
            Some(mode) => format!("add {{them}} with mode {mode}, with “COPY --chmod={mode}” or “install --mode={mode}”"),
            None => format!("add {{them}} without the bits “chmod {spec}” clears, with “COPY --chmod=” or “install --mode=”"),
        },
        _ => "leave the line out where it writes {them}".to_owned(),
    };
    log::debug!(
        "rule {} {path}: shipped, {command} becomes a build step",
        check.rule
    );
    (advice, path.to_owned())
}

/// The mode a shipped file should enter its image with: its own, less the bits `spec` clears.
fn target_mode(check: &Check, spec: &str) -> Option<String> {
    let mode = match check.value.as_ref()? {
        Value::String(text) => u32::from_str_radix(text.trim(), 8).ok()?,
        _ => return None,
    };
    let cleared = crate::fix::cleared(spec).ok()?;
    (mode <= 0o7777).then(|| format!("{:04o}", mode & !cleared))
}

/// One failing subject of a block: its line around the image phrase, the lines under it, whether its image ships it, and its build step.
#[derive(PartialEq)]
struct Item {
    line: String,
    waiver: String,
    under: String,
    shipped: bool,
    step: Option<(String, String)>,
}

/// What a group of `items` shares, as words for its heading (“as … ships them”, empty when they differ), then its lines and one build step per advice, worded for `many` images.
fn item_text(items: &[(&Item, Option<&str>)], many: bool, on: bool) -> (String, String, String) {
    let images: BTreeSet<Option<&str>> = items.iter().map(|(_, image)| *image).collect();
    let together = items.iter().all(|(item, _)| item.shipped) && images.len() == 1;
    let them = if items.len() == 1 { "it" } else { "them" };
    let ships = |image: Option<&str>, them: &str| match image {
        Some(image) => format!("as {} ships {them}", paint(on, VALUE, image)),
        None => format!("as each image ships {them}"),
    };
    let heading = match together {
        true => ships(items[0].1, them),
        false => String::new(),
    };
    let mut out = String::new();
    let mut built: Vec<(&str, Vec<&str>)> = Vec::new();
    for (item, image) in items {
        let phrase = match item.shipped && !together {
            true => format!(", {}", ships(*image, "it")),
            false => String::new(),
        };
        let _ = writeln!(
            out,
            "{}",
            sentence(&format!("{}{phrase}{}", item.line, item.waiver))
        );
        out.push_str(&item.under);
        if let Some((advice, path)) = &item.step {
            match built.iter_mut().find(|(a, _)| a == advice) {
                Some((_, paths)) => paths.push(path),
                None => built.push((advice, vec![path])),
            }
        }
    }
    let whose = if many {
        "each image’s"
    } else {
        "the image’s"
    };
    let mut steps = String::new();
    for (advice, paths) in &built {
        let pronoun = if paths.len() == 1 { "it" } else { "them" };
        let named = match (built.len(), together) {
            (1, true) => them.to_owned(),
            _ => paths
                .iter()
                .map(|p| paint(on, VALUE, &format!("“{p}”")))
                .collect::<Vec<_>>()
                .join(", "),
        };
        log::debug!("{advice}: {} paths for {whose} build", paths.len());
        let advice = values(on, &advice.replace("{them}", pronoun));
        let _ = writeln!(
            steps,
            "Fix where {whose} build adds {named}: {advice}, then rebuild it."
        );
    }
    (heading, out, steps)
}

/// The failing checks of one rule as a block: level and highest score, why, a line per location and its remedy command, the fix once when every location shares it, then the references when `verbose`.
/// Failing subjects with a remedy from which, unless verbose, one `systemlint fix` line stands for their `Run:` lines.
const FOLD_REMEDIES: usize = 3;

fn failure_block(
    out: &mut String,
    document: &Value,
    group: &[&Check],
    verbose: bool,
    on: bool,
) -> (Vec<Item>, String, String) {
    let worst = group
        .iter()
        .copied()
        .max_by(|a, b| {
            a.score
                .unwrap_or_default()
                .total_cmp(&b.score.unwrap_or_default())
        })
        .unwrap_or(group[0]);
    let (word, code) = level_word(worst.severity);
    let label = format!(
        "{} ({:.1})",
        paint(on, code, word),
        worst.score.unwrap_or_default()
    );
    let _ = writeln!(out, "{}", header(&label, worst, on));
    if let Some(why) = &worst.rationale {
        let _ = writeln!(out, "Why: {}", sentence(why));
    }
    let problems = clusters(group);
    let contained = document["meta"]["subject"]["kind"] == "container";
    let images: Vec<Option<&str>> = group.iter().map(|c| shipped(document, c)).collect();
    let image_of = |check: &Check| {
        group
            .iter()
            .position(|c| std::ptr::eq(*c, check))
            .and_then(|i| images[i])
    };
    let remedied = group
        .iter()
        .filter(|c| c.remedy.is_some() && c.is_failing() && image_of(c).is_none())
        .count();
    let folded = !verbose && !contained && remedied >= FOLD_REMEDIES;
    let mut items: Vec<Item> = Vec::new();
    let shared = problems.iter().all(|p| p[0].fix == problems[0][0].fix);
    let commanded = |checks: &[&Check]| {
        checks
            .iter()
            .all(|c| c.remedy.as_deref().is_some_and(|r| !crate::fix::writes(r)))
    };
    let written = group
        .iter()
        .any(|c| c.remedy.as_deref().is_some_and(crate::fix::writes));
    let family = |c: &Check| {
        let subject = c.subject_label();
        rotated_from(&subject).map_or(subject.clone(), str::to_owned)
    };
    let mut families: BTreeMap<String, usize> = BTreeMap::new();
    for check in group.iter().filter(|_| !verbose) {
        *families.entry(family(check)).or_default() += 1;
    }
    let mut shown: BTreeSet<String> = BTreeSet::new();
    for problem in &problems {
        for check in problem {
            let kin = families.get(&family(check)).copied().unwrap_or(1);
            if kin > 1 && !shown.insert(family(check)) {
                continue;
            }
            let (subject, said) = (
                check.subject_label(),
                if problem.len() > 1 {
                    None
                } else {
                    detail(check)
                },
            );
            let said = if subject.is_empty() {
                said.or_else(|| check.message.clone())
            } else {
                said
            };
            let named =
                check.title.is_none() && said.as_deref().is_some_and(|m| m.contains(&subject));
            let shipped = image_of(check).is_some();
            let waiver = check.waiver.as_ref().map_or_else(String::new, |w| {
                format!(" (waiver expired on {}: {})", w.until, w.reason)
            });
            let mut line = location(if named { "" } else { &subject }, said.as_deref(), on);
            if kin > 1 {
                let own = family(check) == subject;
                log::debug!("{subject}: {kin} rotations folded, base failing {own}");
                let copies = if kin == 2 { "copy" } else { "copies" };
                line += &match own {
                    true => format!(", and its {} rotated {copies}", kin - 1),
                    false => format!(", and {} more rotated {copies}", kin - 1),
                };
            }
            let mut item = Item {
                line,
                waiver,
                under: String::new(),
                shipped,
                step: None,
            };
            match (
                check
                    .remedy
                    .as_deref()
                    .filter(|r| check.is_failing() && !crate::fix::writes(r)),
                shipped,
            ) {
                (Some(command), true) => item.step = Some(build_step(command, check)),
                (Some(command), false) if !folded => {
                    item.under = format!("  Run: {}\n", paint(on, SHOWN, command));
                }
                _ => {}
            }
            items.push(item);
        }
        if let Some((fix, last)) = problem[0]
            .fix
            .as_ref()
            .filter(|_| !shared && !commanded(problem))
            .zip(items.last_mut())
        {
            last.under.push_str(&fix_text(fix, "  ", on));
        }
    }
    let mut mid = String::new();
    if let Some(fix) = problems[0][0]
        .fix
        .as_ref()
        .filter(|_| shared && !commanded(group))
    {
        mid.push_str(&fix_text(fix, "", on));
    }
    let mut tail = String::new();
    if (folded || remedied > 1 || written) && !contained {
        let lead = match (folded, remedied > 1) {
            (true, _) => "To make every change, run:",
            (false, true) => "Or make every change at once:",
            (false, false) => "Or let systemlint make the change:",
        };
        log::debug!("rule {}: {remedied} remedies, folded {folded}", worst.rule);
        let command = format!("systemlint fix --tags {}", worst.rule);
        let _ = writeln!(tail, "{lead}\n  {}", paint(on, SHOWN, &command));
    }
    for reference in worst.references.iter().filter(|_| verbose) {
        let _ = writeln!(tail, "See: {} <{}>", reference.title, reference.url);
    }
    out.push('\n');
    (items, mid, tail)
}

/// `items` joined by commas into lines of at most `WIDTH` columns, each indented by two spaces.
fn wrap(items: &[String], on: bool) -> String {
    let (mut out, mut width) = (String::new(), 0);
    for item in items {
        let length = item.chars().count();
        if width > 0 && width + 2 + length > WIDTH {
            out.push_str(",\n");
            width = 0;
        } else if width > 0 {
            out.push_str(", ");
            width += 2;
        }
        if width == 0 {
            out.push_str("  ");
            width = 2;
        }
        out.push_str(&paint(on, "1", item));
        width += length;
    }
    out + "\n"
}

/// The checks grouped by rule, in rule order.
fn by_rule<'a>(checks: impl Iterator<Item = &'a Check>) -> BTreeMap<&'a str, Vec<&'a Check>> {
    let mut groups: BTreeMap<&str, Vec<&Check>> = BTreeMap::new();
    for check in checks {
        groups.entry(&check.rule).or_default().push(check);
    }
    groups
}

/// The failing groups, worst first: highest level, then highest score, then rule.
fn ranked(checks: &[Check]) -> Vec<Vec<&Check>> {
    let mut groups: Vec<Vec<&Check>> = by_rule(checks.iter().filter(|c| c.is_failing()))
        .into_values()
        .collect();
    let worst = |g: &Vec<&Check>| {
        (
            g.iter().filter_map(|c| c.severity).max(),
            g.iter()
                .map(|c| c.score.unwrap_or_default())
                .fold(0.0, f64::max),
        )
    };
    groups.sort_by(|a, b| {
        let ((level_a, score_a), (level_b, score_b)) = (worst(a), worst(b));
        level_b
            .cmp(&level_a)
            .then_with(|| score_b.total_cmp(&score_a))
            .then_with(|| a[0].rule.cmp(&b[0].rule))
    });
    groups
}

/// One summary row: the label padded to a column, then its value.
fn row(label: &str, value: &str) -> String {
    format!("{label:<18}{value}\n")
}

/// The summary counts as label, count and what the count means: each level’s failures, the passes, the other outcomes, then what did not run, split into what the user can turn on and what this host has nothing for; zero counts left out but the levels and the passes.
fn counts(
    document: &Value,
    checks: &[Check],
    left_out: usize,
) -> Vec<(&'static str, usize, &'static str, Option<Severity>)> {
    let failing = |level: Severity| {
        checks
            .iter()
            .filter(|c| c.is_failing() && c.severity == Some(level))
            .count()
    };
    let s = summary(checks);
    let n = |key: &str| s[key].as_u64().unwrap_or_default() as usize;
    let not_run = checks
        .iter()
        .filter(|c| skip_reason(document, c).is_some())
        .count();
    let level = |label, l| (label, failing(l), "", Some(l));
    [
        level("Errors", Severity::Error),
        level("Warnings", Severity::Warning),
        level("Info", Severity::Info),
        level("Advice", Severity::Advice),
        ("Passed", n("pass"), "", None),
        ("Waived", n("waived"), "", None),
        ("Unknown", n("unknown") - not_run, "", None),
        ("Manual", n("manual"), ", for a person to check", None),
        ("Conflict", n("conflict"), "", None),
        (
            "Not selected",
            left_out,
            ", run them by naming their ruleset in --tags",
            None,
        ),
        (
            "Not run",
            not_run,
            ", they need root, an opt-in flag or fresher facts",
            None,
        ),
        (
            "Nothing to check",
            n("skip") + n("not-applicable"),
            ", the host has nothing these rules judge",
            None,
        ),
    ]
    .into_iter()
    .filter(|(label, count, _, level)| {
        log::debug!("{count} {label}");
        *count > 0 || *label == "Passed" || level.is_some_and(|l| l != Severity::Advice)
    })
    .collect()
}

/// The closing rows: the rating, then one row per count, a level’s failures in its colour.
fn summary_rows(document: &Value, checks: &[Check], left_out: usize, on: bool) -> String {
    let rating = rate(checks).map_or_else(
        || "none, since no check was judged".to_owned(),
        |r| {
            let code = match r.grade {
                'S' | 'A' => "32",
                'B' | 'C' => "33",
                _ => "31",
            };
            paint(on, &format!("1;{code}"), &r.grade.to_string())
        },
    );
    let mut out = row("Rating", &rating);
    for (label, count, why, level) in counts(document, checks, left_out) {
        let shown = match level.filter(|_| count > 0) {
            Some(l) => paint(on, level_word(Some(l)).1, &count.to_string()),
            None => count.to_string(),
        };
        out += &row(label, &format!("{shown}{why}"));
    }
    out
}

/// One line naming every ruleset none of whose checks applies to this host, after the summary.
fn not_applicable(checks: &[Check]) -> Option<String> {
    let mut rulesets: BTreeMap<&str, bool> = BTreeMap::new();
    for check in checks {
        let owner = check
            .rule
            .split_once('/')
            .map_or(check.rule.as_str(), |(owner, _)| owner);
        *rulesets.entry(owner).or_insert(true) &= check.outcome == Outcome::NotApplicable;
    }
    let names: Vec<&str> = rulesets
        .into_iter()
        .filter(|(_, all)| *all)
        .map(|(name, _)| name)
        .collect();
    log::debug!("{} rulesets not applicable: {names:?}", names.len());
    (!names.is_empty()).then(|| format!("\nNot applicable to this host: {}.\n", names.join(", ")))
}

/// The rules of `checks` grouped by their reason, each reason once.
fn by_reason<'a>(checks: impl Iterator<Item = &'a Check>) -> BTreeMap<&'a str, BTreeSet<&'a str>> {
    let mut groups: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for check in checks {
        groups
            .entry(check.reason.as_deref().unwrap_or_default())
            .or_default()
            .insert(&check.rule);
    }
    groups
}

/// Collectors and rules under each heading.
type Grouped<'a> = BTreeMap<String, (BTreeSet<&'a str>, BTreeSet<&'a str>)>;

/// One `<label> (collectors): heading` block per heading of `entries` (heading, collector, rule), its rules wrapped under it.
fn collector_blocks<'a>(
    out: &mut String,
    label: &str,
    entries: impl Iterator<Item = (String, &'a str, &'a str)>,
    on: bool,
) {
    let mut groups: Grouped = BTreeMap::new();
    for (heading, collector, rule) in entries {
        let (collectors, rules) = groups.entry(heading).or_default();
        collectors.insert(collector);
        rules.insert(rule);
    }
    for (heading, (collectors, rules)) in &groups {
        log::debug!(
            "{label}: {} rules, collectors {collectors:?}: {heading}",
            rules.len()
        );
        let _ = writeln!(
            out,
            "{label} ({}): {heading}",
            collectors.iter().copied().collect::<Vec<_>>().join(", ")
        );
        out.push_str(&wrap(
            &rules.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>(),
            on,
        ));
        out.push('\n');
    }
}

/// One block per rule: not run reasons, unreadable paths, unknowns, manual rules, waivers, failures worst first (with references when `verbose`), each with where it sorts.
fn blocks(document: &Value, checks: &[Check], verbose: bool, on: bool) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut out = String::new();
    collector_blocks(
        &mut out,
        "Not run",
        checks.iter().filter_map(|c| {
            Some((
                shown_skip(document, c)?.to_owned(),
                c.collector.as_deref()?,
                c.rule.as_str(),
            ))
        }),
        on,
    );
    split(&mut blocks, &mut out, (0, Reverse(None), 0));
    collector_blocks(
        &mut out,
        "Not read",
        checks.iter().filter_map(|c| {
            let (collector, path, reason) = unread(document, c)?;
            Some((format!("{path}, {reason}"), collector, c.rule.as_str()))
        }),
        on,
    );
    split(&mut blocks, &mut out, (1, Reverse(None), 0));
    collector_blocks(
        &mut out,
        "Unknown",
        checks.iter().filter_map(|c| {
            let reason = failed(document, c)?;
            let reason = if verbose {
                reason
            } else {
                reason.lines().next().unwrap_or_default()
            };
            Some((sentence(reason), c.collector.as_deref()?, c.rule.as_str()))
        }),
        on,
    );
    split(&mut blocks, &mut out, (2, Reverse(None), 0));
    for group in by_rule(checks.iter().filter(|c| {
        c.outcome == Outcome::Unknown
            && skip_reason(document, c).is_none()
            && unread(document, c).is_none()
            && failed(document, c).is_none()
    }))
    .values()
    {
        let _ = writeln!(out, "{}", header("Unknown", group[0], on));
        group.iter().for_each(|c| {
            let _ = writeln!(
                out,
                "{}",
                sentence(&location(&c.subject_label(), c.reason.as_deref(), on))
            );
        });
        out.push('\n');
    }
    split(&mut blocks, &mut out, (3, Reverse(None), 0));
    for (reason, rules) in by_reason(checks.iter().filter(|c| c.outcome == Outcome::Conflict)) {
        log::debug!("{} rules in conflict: {reason}", rules.len());
        let _ = writeln!(out, "Conflict: {}", sentence(reason));
        out.push('\n');
    }
    split(&mut blocks, &mut out, (4, Reverse(None), 0));
    for check in checks.iter().filter(|c| c.outcome == Outcome::Manual) {
        let _ = writeln!(out, "{}", header("Manual", check, on));
        if let Some(why) = &check.rationale {
            let _ = writeln!(out, "Why: {}", sentence(why));
        }
        out.push('\n');
    }
    split(&mut blocks, &mut out, (5, Reverse(None), 0));
    for group in by_rule(
        checks
            .iter()
            .filter(|c| c.outcome == Outcome::Fail && !c.is_failing()),
    )
    .values()
    {
        let _ = writeln!(out, "{}", header("Waived", group[0], on));
        for (check, w) in group.iter().filter_map(|c| Some((c, c.waiver.as_ref()?))) {
            let _ = writeln!(
                out,
                "{}",
                sentence(&location(
                    &check.subject_label(),
                    Some(&format!("{} (until {})", w.reason, w.until)),
                    on
                ))
            );
        }
        out.push('\n');
    }
    split(&mut blocks, &mut out, (6, Reverse(None), 0));
    for group in ranked(checks) {
        let (items, mid, tail) = failure_block(&mut out, document, &group, verbose, on);
        let level = group.iter().filter_map(|c| c.severity).max();
        let score = group
            .iter()
            .map(|c| c.score.unwrap_or_default())
            .fold(0.0, f64::max);
        split(
            &mut blocks,
            &mut out,
            (7, Reverse(level), -(score * 1000.0) as i64),
        );
        if let Some(block) = blocks.last_mut() {
            (block.items, block.mid, block.tail) = (items, mid, tail);
        }
    }
    blocks
}

/// Where a human block sorts: its section, then a failure’s level and score, worst first.
type Order = (u8, Reverse<Option<Severity>>, i64);

/// One human block: its first line, the lines below it, a failure’s subjects and closing lines (`mid` before the build steps), and where it sorts.
struct Block {
    order: Order,
    head: String,
    rest: String,
    items: Vec<Item>,
    mid: String,
    tail: String,
}

/// Moves each empty-line-ended block of `out` into `blocks` at `order`.
fn split(blocks: &mut Vec<Block>, out: &mut String, order: Order) {
    for text in out.split_terminator("\n\n") {
        let (head, rest) = text.split_once('\n').unwrap_or((text, ""));
        blocks.push(Block {
            order,
            head: head.to_owned(),
            rest: rest.to_owned(),
            items: Vec::new(),
            mid: String::new(),
            tail: String::new(),
        });
    }
    out.clear();
}

/// `text` as lines ending in a newline, or nothing when empty.
fn lines(text: &str) -> String {
    match text.is_empty() || text.ends_with('\n') {
        true => text.to_owned(),
        false => format!("{text}\n"),
    }
}

/// Every block, then unless `quiet` the summary rows, `left_out` among them, and the rulesets not applicable.
pub fn lint_human(
    document: &Value,
    checks: &[Check],
    left_out: usize,
    quiet: bool,
    verbose: bool,
    on: bool,
) -> String {
    let image = document["meta"]["subject"]["image"]
        .as_str()
        .unwrap_or("the image");
    let mut out: String = blocks(document, checks, verbose, on)
        .into_iter()
        .map(|b| {
            let items: Vec<(&Item, Option<&str>)> =
                b.items.iter().map(|i| (i, Some(image))).collect();
            let (heading, subjects, steps) = item_text(&items, false, on);
            let heading = match heading.is_empty() {
                true => heading,
                false => format!("{}:\n", capitalised(&heading)),
            };
            format!(
                "{}\n{}{heading}{subjects}{}{steps}{}\n",
                b.head,
                lines(&b.rest),
                b.mid,
                b.tail
            )
        })
        .collect();
    if !quiet {
        out.push_str(&summary_rows(document, checks, left_out, on));
        out.extend(not_applicable(checks));
    }
    out
}

/// One block across targets: each distinct rest, failing subject (with each target’s image) and closing text, with the targets holding it.
#[derive(Default)]
struct Joined<'a> {
    rests: Vec<(String, Vec<&'a str>)>,
    items: Vec<(Item, Vec<(&'a str, &'a str)>)>,
    ends: Vec<(String, Vec<&'a str>)>,
}

/// Each block by where it sorts and its first line, joined across targets.
type Merged<'a> = BTreeMap<(Order, String), Joined<'a>>;

/// Adds `key` to the group equal to `value`, or a new group for it.
fn join<T: PartialEq, K>(groups: &mut Vec<(T, Vec<K>)>, value: T, key: K) {
    match groups.iter_mut().find(|(v, _)| *v == value) {
        Some((_, keys)) => keys.push(key),
        None => groups.push((value, vec![key])),
    }
}

/// The key standing for the host among the targets.
const HOST: &str = "";

/// One block per rule across the host and `targets`, each followed by the targets it holds for unless only the host has blocks, then unless `quiet` one summary row per target.
pub fn lint_human_targets(
    document: &Value,
    checks: &[Check],
    left_out: usize,
    targets: &[Target],
    flags: (bool, bool, bool),
) -> String {
    let (quiet, verbose, on) = flags;
    let every: Vec<Target> = std::iter::once((HOST, document, checks))
        .chain(targets.iter().copied())
        .collect();
    let mut merged: Merged = BTreeMap::new();
    for (key, doc, judged) in &every {
        let image = doc["meta"]["subject"]["image"]
            .as_str()
            .unwrap_or("the image");
        for block in blocks(doc, judged, verbose, on) {
            let joined = merged.entry((block.order, block.head)).or_default();
            join(&mut joined.rests, block.rest, *key);
            if block.items.is_empty() {
                continue;
            }
            block
                .items
                .into_iter()
                .for_each(|item| join(&mut joined.items, item, (*key, image)));
            join(&mut joined.ends, block.mid + &block.tail, *key);
        }
    }
    let containers: Vec<&str> = targets.iter().map(|(key, _, _)| *key).collect();
    let mut out = String::new();
    for ((_, head), joined) in &merged {
        let _ = writeln!(out, "{head}");
        if joined.items.is_empty() {
            log::debug!("{head}: {} groups of targets", joined.rests.len());
            for (n, (rest, keys)) in joined.rests.iter().enumerate() {
                if n > 0 {
                    out.push('\n');
                }
                if !containers.is_empty() {
                    let _ = writeln!(out, "In {}:", place(keys, &containers, on));
                }
                out.push_str(&lines(rest));
            }
            out.push('\n');
            continue;
        }
        out.push_str(&lines(&joined.rests[0].0));
        let mut sets = Vec::new();
        for (item, held) in &joined.items {
            let keys: Vec<&str> = held.iter().map(|(k, _)| *k).collect();
            let images: BTreeSet<&str> = held.iter().map(|(_, i)| *i).collect();
            let image = images.first().copied().filter(|_| images.len() == 1);
            join(&mut sets, keys, (item, image));
        }
        log::debug!(
            "{head}: {} subjects in {} groups of targets",
            joined.items.len(),
            sets.len()
        );
        let holding = joined.rests.iter().map(|(_, k)| k.len()).sum::<usize>();
        let mut told = vec![false; joined.ends.len()];
        for (n, (keys, items)) in sets.iter().enumerate() {
            if n > 0 {
                out.push('\n');
            }
            let many = items.iter().any(|(_, i)| i.is_none());
            let (heading, subjects, steps) = item_text(items, many, on);
            match (containers.is_empty(), heading.is_empty()) {
                (false, true) => {
                    let _ = writeln!(out, "In {}:", place(keys, &containers, on));
                }
                (false, false) => {
                    let _ = writeln!(out, "In {}, {heading}:", place(keys, &containers, on));
                }
                (true, false) => {
                    let _ = writeln!(out, "{}:", capitalised(&heading));
                }
                (true, true) => {}
            }
            out.push_str(&subjects);
            out.push_str(&steps);
            for (i, (end, held)) in joined.ends.iter().enumerate() {
                if !end.is_empty() && held.len() < holding && held == keys {
                    log::debug!("{head}: closing text kept with its {} targets", held.len());
                    out.push_str(end);
                    told[i] = true;
                }
            }
        }
        for (i, (end, keys)) in joined.ends.iter().enumerate() {
            if end.is_empty() || told[i] {
                continue;
            }
            if sets.len() > 1 {
                out.push('\n');
            }
            if !containers.is_empty() && keys.len() < holding {
                let _ = writeln!(out, "In {}:", place(keys, &containers, on));
            }
            out.push_str(end);
        }
        out.push('\n');
    }
    if !quiet {
        out.push_str(&target_rows(&every, on));
        if left_out > 0 {
            out += &row(
                "Not selected",
                &format!("{left_out}, run them by naming their ruleset in --tags"),
            );
        }
    }
    out
}

/// `text` with its first letter capitalised.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

/// Where a block holds: the host and the containers among `keys`, each painted as a value, naming the containers left out instead when fewer.
fn place(keys: &[&str], containers: &[&str], on: bool) -> String {
    let host = keys.contains(&HOST);
    let named = |k: &&str| paint(on, VALUE, k);
    let inside: Vec<String> = keys.iter().filter(|k| **k != HOST).map(named).collect();
    let missing: Vec<String> = containers
        .iter()
        .filter(|c| !keys.contains(c))
        .map(named)
        .collect();
    let lead = if host { "the host" } else { "" };
    let rest = match (inside.len(), missing.len()) {
        (0, _) => String::new(),
        (_, 0) => "every container".to_owned(),
        (n, m) if m < n && m <= 3 => format!("every container except {}", missing.join(", ")),
        _ => inside.join(", "),
    };
    match (lead, rest.as_str()) {
        (lead, "") => lead.to_owned(),
        ("", rest) => rest.to_owned(),
        (lead, rest) if rest.starts_with("every") => format!("{lead} and {rest}"),
        (lead, rest) => format!("{lead}, {rest}"),
    }
}

/// One summary row per target: its rating and the counts of each level, unknowns and checks not run.
fn target_rows(every: &[Target], on: bool) -> String {
    let labels = ["Errors", "Warnings", "Info", "Unknown", "Not run"];
    let name = |key: &str| {
        if key == HOST {
            "host".to_owned()
        } else {
            key.to_owned()
        }
    };
    let width = every
        .iter()
        .map(|(k, _, _)| name(k).chars().count())
        .max()
        .unwrap_or(0)
        .max(6);
    let mut out = format!("{:<width$}  Rating  {}\n", "Target", labels.join("  "));
    for (key, doc, judged) in every {
        let grade = rate(judged).map_or('-', |r| r.grade);
        let _ = write!(
            out,
            "{:<width$}  {}",
            name(key),
            paint(on, "1", &format!("{grade:<6}"))
        );
        let counts = counts(doc, judged, 0);
        for label in labels {
            let count = counts.iter().find(|c| c.0 == label).map_or(0, |c| c.1);
            let shown = format!("{count:<w$}", w = label.chars().count());
            let level = counts
                .iter()
                .find(|c| c.0 == label)
                .and_then(|c| c.3)
                .filter(|_| count > 0);
            let _ = write!(
                out,
                "  {}",
                level.map_or_else(
                    || shown.clone(),
                    |l| paint(on, level_word(Some(l)).1, &shown)
                )
            );
        }
        out = out.trim_end().to_owned() + "\n";
    }
    out
}

/// `text` as one tab-separated field: tabs and newlines become spaces.
fn field(text: &str) -> String {
    text.replace(['\t', '\n'], " ")
}

/// A check’s message without the subject it opens with, since the subject column already says it.
fn unsubjected(check: &Check) -> &str {
    check
        .unsubjected()
        .or(check.message.as_deref())
        .unwrap_or_default()
}

/// One plain row: the last two cells ended as sentences, the last one capitalised.
fn plain_row(cells: [&str; 6]) -> String {
    let spoken = |i: usize, c: &str| match (i, c.chars().next()) {
        (4, _) => sentence(c),
        (5, Some(first)) => {
            sentence(&(first.to_uppercase().collect::<String>() + &c[first.len_utf8()..]))
        }
        _ => c.to_owned(),
    };
    cells
        .iter()
        .enumerate()
        .map(|(i, c)| field(&spoken(i, c)))
        .collect::<Vec<_>>()
        .join("\t")
}

/// One finding per tab-separated line, in the human order and undecorated, a rule not run once per reason: outcome or level, score, rule, subject, message, fix.
pub fn lint_plain(document: &Value, checks: &[Check], quiet: bool) -> String {
    let mut out = String::new();
    let mut row = |cells: [&str; 6]| {
        let _ = writeln!(out, "{}", plain_row(cells));
    };
    let not_run: BTreeSet<(&str, &str)> = checks
        .iter()
        .filter_map(|c| Some((c.rule.as_str(), shown_skip(document, c)?)))
        .collect();
    log::debug!("{} rule and reason pairs not run", not_run.len());
    for (rule, reason) in not_run {
        row(["not-run", "", rule, "", reason, ""]);
    }
    for check in checks
        .iter()
        .filter(|c| c.outcome == Outcome::NotApplicable)
    {
        row([
            "not-applicable",
            "",
            &check.rule,
            "",
            check.reason.as_deref().unwrap_or_default(),
            "",
        ]);
    }
    let conflicts: BTreeSet<(&str, &str)> = checks
        .iter()
        .filter(|c| c.outcome == Outcome::Conflict)
        .map(|c| (c.rule.as_str(), c.reason.as_deref().unwrap_or_default()))
        .collect();
    for (rule, reason) in conflicts {
        row(["conflict", "", rule, "", reason, ""]);
    }
    for check in checks
        .iter()
        .filter(|c| c.outcome == Outcome::Unknown && skip_reason(document, c).is_none())
    {
        row([
            "unknown",
            "",
            &check.rule,
            &check.subject_label(),
            check.reason.as_deref().unwrap_or_default(),
            "",
        ]);
    }
    for check in checks.iter().filter(|c| c.outcome == Outcome::Manual) {
        row([
            "manual",
            "",
            &check.rule,
            "",
            check.title.as_deref().unwrap_or_default(),
            check.rationale.as_deref().unwrap_or_default(),
        ]);
    }
    for check in checks
        .iter()
        .filter(|c| c.outcome == Outcome::Fail && !c.is_failing())
    {
        let until = check
            .waiver
            .as_ref()
            .map(|w| format!("waived until {}: {}", w.until, w.reason))
            .unwrap_or_default();
        row([
            "waived",
            &format!("{:.1}", check.score.unwrap_or_default()),
            &check.rule,
            &check.subject_label(),
            unsubjected(check),
            &until,
        ]);
    }
    for check in ranked(checks).into_iter().flatten() {
        row([
            &name(check.severity),
            &format!("{:.1}", check.score.unwrap_or_default()),
            &check.rule,
            &check.subject_label(),
            unsubjected(check),
            &check.fix.as_ref().map(Fix::text).unwrap_or_default(),
        ]);
    }
    if !quiet {
        let grade = rate(checks).map_or_else(|| "-".to_owned(), |r| r.grade.to_string());
        let counts: Vec<String> = counts(document, checks, 0)
            .into_iter()
            .map(|(label, count, _, _)| format!("{label} {count}"))
            .collect();
        let _ = writeln!(out, "rating\t{grade}\t\t\t{}\t", counts.join(", "));
    }
    out
}

/// The `meta` of the facts, every check, the counts and the rating, as indented JSON.
pub fn lint_json(document: &Value, checks: &[Check]) -> String {
    let report = json!({"meta": document["meta"], "checks": checks, "summary": summary(checks), "rating": rate(checks)});
    serde_json::to_string_pretty(&report).unwrap_or_default() + "\n"
}

/// The SARIF level of a failure: error, warning, or note for info and advice.
fn level(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::Error) => "error",
        Some(Severity::Warning) => "warning",
        _ => "note",
    }
}

/// `text` with the characters a URI path cannot hold percent-encoded.
fn uri_path(text: &str) -> String {
    text.chars().fold(String::new(), |mut out, c| {
        match c {
            '%' | ' ' | '#' | '?' | '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}' => {
                let mut bytes = [0; 4];
                c.encode_utf8(&mut bytes)
                    .bytes()
                    .for_each(|b| out.push_str(&format!("%{b:02X}")));
            }
            _ => out.push(c),
        }
        out
    })
}

/// The file a check is about: its last subject key that is an absolute path, with a trailing `:line`.
fn file_of(check: &Check) -> Option<(String, Option<u64>)> {
    let key = check.subject.iter().rev().find(|k| k.starts_with('/'))?;
    match key.rsplit_once(':') {
        Some((path, line)) if line.parse::<u64>().is_ok_and(|n| n > 0) => {
            Some((path.to_owned(), line.parse().ok()))
        }
        _ => Some((key.clone(), None)),
    }
}

/// The SARIF location of a check: the subject file under `ROOT` when there is one, always the fact path.
fn locations(check: &Check) -> Value {
    let logical = json!([{"fullyQualifiedName": if check.subject.is_empty() { check.fact.clone() } else { format!("{} {}", check.fact, check.subject_text()) }, "kind": "object"}]);
    let Some((path, line)) = file_of(check) else {
        return json!([{"logicalLocations": logical}]);
    };
    let mut physical = json!({"artifactLocation": {"uri": uri_path(path.trim_start_matches('/')), "uriBaseId": "ROOT"}});
    if let Some(line) = line {
        physical["region"] = json!({"startLine": line});
    }
    json!([{"physicalLocation": physical, "logicalLocations": logical}])
}

/// The SARIF result of a failure, an unknown, a rule not applicable or one to review by hand; none for pass and skip.
fn result(check: &Check) -> Option<Value> {
    let mut out = match check.outcome {
        Outcome::Fail => {
            json!({"ruleId": check.rule, "kind": "fail", "level": level(check.severity), "message": {"text": check.message.as_deref().unwrap_or(&check.rule)}})
        }
        Outcome::Unknown => {
            json!({"ruleId": check.rule, "kind": "open", "level": "none", "message": {"text": check.reason.as_deref().unwrap_or("unknown")}})
        }
        Outcome::NotApplicable => {
            json!({"ruleId": check.rule, "kind": "notApplicable", "level": "none", "message": {"text": check.reason.as_deref().unwrap_or("not applicable")}})
        }
        Outcome::Manual => {
            json!({"ruleId": check.rule, "kind": "review", "level": "none", "message": {"text": check.title.as_deref().unwrap_or(&check.rule)}})
        }
        Outcome::Conflict => {
            json!({"ruleId": check.rule, "kind": "review", "level": "none", "message": {"text": check.reason.as_deref().unwrap_or("conflict")}})
        }
        Outcome::Pass | Outcome::Skip => return None,
    };
    if !check.fact.is_empty() {
        out["locations"] = locations(check);
    }
    out["partialFingerprints"] =
        json!({"systemlintSubject/v1": format!("{}|{}", check.rule, check.subject_text())});
    if let Some(waiver) = check
        .waiver
        .as_ref()
        .filter(|w| w.active && check.outcome == Outcome::Fail)
    {
        out["suppressions"] = json!([{"kind": "external", "status": "accepted", "justification": format!("{} (until {})", waiver.reason, waiver.until)}]);
    }
    if let Some(fix) = &check.fix {
        out["properties"] = json!({"fix": fix});
    }
    Some(out)
}

/// A rule’s rationale and references as SARIF `help`, in plain text and markdown, or `None` when it has neither.
fn help(check: &Check) -> Option<Value> {
    let (mut text, mut markdown) = (
        check.rationale.clone().into_iter().collect::<Vec<_>>(),
        check.rationale.clone().into_iter().collect::<Vec<_>>(),
    );
    text.extend(
        check
            .references
            .iter()
            .map(|r| format!("{}: {}", r.title, r.url)),
    );
    markdown.extend(
        check
            .references
            .iter()
            .map(|r| format!("- [{}]({})", r.title.replace(']', "\\]"), r.url)),
    );
    (!text.is_empty()).then(|| json!({"text": text.join("\n"), "markdown": markdown.join("\n\n")}))
}

/// The descriptor of every rule the checks name: title, tags, docs, rationale and references, default level and `security-severity` from the score.
fn descriptors(checks: &[Check]) -> Vec<Value> {
    let mut seen = std::collections::BTreeMap::new();
    for check in checks {
        seen.entry(check.rule.as_str()).or_insert(check);
    }
    seen.into_iter()
        .map(|(id, check)| {
            let mut rule = json!({"id": id, "defaultConfiguration": {"level": level(check.severity)}, "properties": {"tags": check.tags}});
            if let Some(title) = &check.title {
                rule["shortDescription"] = json!({"text": title});
            }
            if let Some(docs) = check.docs.as_ref().or(check.references.first().map(|r| &r.url)) {
                rule["helpUri"] = json!(docs);
            }
            if let Some(help) = help(check) {
                rule["help"] = help;
            }
            if let Some(score) = check.score {
                rule["properties"]["security-severity"] = json!(format!("{score:.1}"));
            }
            rule
        })
        .collect()
}

/// The checks as a SARIF 2.1.0 log: failures, waived failures as suppressed, unknowns as `open`, collector errors as notifications.
pub fn lint_sarif(document: &Value, checks: &[Check]) -> String {
    let meta = &document["meta"];
    let root = match meta["subject"]["kind"].as_str() {
        Some("root") => meta["subject"]["path"]
            .as_str()
            .filter(|p| p.starts_with('/'))
            .map(|p| format!("file://{}/", uri_path(p.trim_end_matches('/')))),
        _ => Some("file:///".to_owned()),
    };
    let base = root.map_or_else(
        || json!({"description": {"text": "The root filesystem systemlint read"}}),
        |uri| json!({"uri": uri}),
    );
    let errors: Vec<Value> = document["collectors"].as_object().into_iter().flatten().filter(|(_, o)| o["status"] == "error").map(|(id, o)| json!({"level": "error", "message": {"text": format!("collector {id}: {}", o["reason"].as_str().unwrap_or_default())}})).collect();
    let log = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "systemlint", "version": systemlint_protocol::VERSION, "informationUri": "https://kiota.ch/damian-buho/systemlint", "rules": descriptors(checks)}},
            "originalUriBaseIds": {"ROOT": base},
            "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": errors, "properties": {"collected-at": meta["collected-at"], "privileged": meta["privileged"]}}],
            "results": checks.iter().filter_map(result).collect::<Vec<_>>(),
            "properties": {"rating": rate(checks)},
        }],
    });
    serde_json::to_string_pretty(&log).unwrap_or_default() + "\n"
}

/// `text` as a Prometheus label value: backslash, quote and newline escaped.
fn label(text: &str) -> String {
    text.replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', r"\n")
}

/// The serialised name of an outcome or severity, empty for none.
fn name(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The run as node-exporter textfile metrics: counts by outcome, by rule, failures by severity, collector status and privilege.
pub fn lint_textfile(document: &Value, checks: &[Check]) -> String {
    let mut out = String::new();
    let s = summary(checks);
    out.push_str("# HELP systemlint_checks Checks of the last check by outcome.\n# TYPE systemlint_checks gauge\n");
    for outcome in [
        "pass",
        "fail",
        "waived",
        "unknown",
        "skip",
        "not-applicable",
        "manual",
        "conflict",
    ] {
        let _ = writeln!(
            out,
            "systemlint_checks{{outcome=\"{outcome}\"}} {}",
            s[outcome]
        );
    }
    let mut per_rule = std::collections::BTreeMap::new();
    for check in checks {
        let outcome = if check.outcome == Outcome::Fail && !check.is_failing() {
            "waived".to_owned()
        } else {
            name(check.outcome)
        };
        *per_rule
            .entry((check.rule.as_str(), outcome))
            .or_insert(0_usize) += 1;
    }
    out.push_str("# HELP systemlint_rule_checks Checks of the last check by rule and outcome.\n# TYPE systemlint_rule_checks gauge\n");
    for ((rule, outcome), count) in &per_rule {
        let _ = writeln!(
            out,
            "systemlint_rule_checks{{rule=\"{}\",outcome=\"{outcome}\"}} {count}",
            label(rule)
        );
    }
    out.push_str("# HELP systemlint_failures Failing checks of the last check by severity, waived ones apart.\n# TYPE systemlint_failures gauge\n");
    for severity in [
        Severity::Error,
        Severity::Warning,
        Severity::Info,
        Severity::Advice,
    ] {
        let _ = writeln!(
            out,
            "systemlint_failures{{severity=\"{}\"}} {}",
            name(severity),
            checks
                .iter()
                .filter(|c| c.is_failing() && c.severity == Some(severity))
                .count()
        );
    }
    if let Some(rating) = rate(checks) {
        out.push_str("# HELP systemlint_rating Share of judged checks the last check kept after failure costs, labelled with its grade.\n# TYPE systemlint_rating gauge\n");
        let _ = writeln!(
            out,
            "systemlint_rating{{grade=\"{}\"}} {}",
            rating.grade, rating.score
        );
    }
    out.push_str("# HELP systemlint_collector_status Whether each collector ended ok, error or skipped.\n# TYPE systemlint_collector_status gauge\n");
    for (id, outcome) in document["collectors"].as_object().into_iter().flatten() {
        for status in ["ok", "error", "skipped"] {
            let _ = writeln!(
                out,
                "systemlint_collector_status{{collector=\"{}\",status=\"{status}\"}} {}",
                label(id),
                u8::from(outcome["status"] == status)
            );
        }
    }
    out.push_str("# HELP systemlint_privileged Whether the facts were collected as root.\n# TYPE systemlint_privileged gauge\n");
    let _ = writeln!(
        out,
        "systemlint_privileged {}",
        u8::from(document["meta"]["privileged"] == true)
    );
    out
}

/// How `check` prints its report, the `--format` choice, also `check.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Human,
    Json,
    Sarif,
    Textfile,
}

/// One container’s report beside the host’s: its key under `targets`, facts and checks.
pub type Target<'a> = (&'a str, &'a Value, &'a [Check]);

/// [`lint_json`] of the host, each container’s under `targets.<key>`.
pub fn lint_json_targets(document: &Value, checks: &[Check], targets: &[Target]) -> String {
    let parsed = |text: String| serde_json::from_str::<Value>(&text).unwrap_or_default();
    let mut report = parsed(lint_json(document, checks));
    if !targets.is_empty() {
        report["targets"] = targets
            .iter()
            .map(|(key, doc, checks)| ((*key).to_owned(), parsed(lint_json(doc, checks))))
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    serde_json::to_string_pretty(&report).unwrap_or_default() + "\n"
}

/// [`lint_sarif`] with one more run per container, named by its key in `automationDetails.id`.
pub fn lint_sarif_targets(document: &Value, checks: &[Check], targets: &[Target]) -> String {
    let parsed = |text: String| serde_json::from_str::<Value>(&text).unwrap_or_default();
    let mut log = parsed(lint_sarif(document, checks));
    for (key, doc, checks) in targets {
        let mut run = parsed(lint_sarif(doc, checks))["runs"][0].take();
        run["automationDetails"] = json!({"id": key});
        if let Some(runs) = log["runs"].as_array_mut() {
            runs.push(run);
        }
    }
    serde_json::to_string_pretty(&log).unwrap_or_default() + "\n"
}

/// [`lint_textfile`] of the host, then each container’s samples with a `target` label, every metric family under one `HELP` and `TYPE`.
pub fn lint_textfile_targets(document: &Value, checks: &[Check], targets: &[Target]) -> String {
    let mut families: Vec<(String, Vec<String>)> = Vec::new();
    let texts = std::iter::once((None, lint_textfile(document, checks))).chain(
        targets
            .iter()
            .map(|(key, doc, checks)| (Some(*key), lint_textfile(doc, checks))),
    );
    for (key, text) in texts {
        for line in text.lines() {
            let family = line
                .strip_prefix("# HELP ")
                .or_else(|| line.strip_prefix("# TYPE "))
                .unwrap_or(line)
                .split(['{', ' '])
                .next()
                .unwrap_or_default()
                .to_owned();
            let at = match families.iter().position(|(f, _)| *f == family) {
                Some(at) => at,
                None => {
                    families.push((family, Vec::new()));
                    families.len() - 1
                }
            };
            let lines = &mut families[at].1;
            match key {
                _ if line.starts_with('#') && lines.iter().any(|l| l == line) => {}
                Some(key) if !line.starts_with('#') => lines.push(targeted(line, key)),
                _ => lines.push(line.to_owned()),
            }
        }
    }
    families
        .into_iter()
        .flat_map(|(_, lines)| lines)
        .map(|l| l + "\n")
        .collect()
}

/// A textfile sample with `target="key"` as its first label.
fn targeted(line: &str, key: &str) -> String {
    let target = format!("target=\"{}\"", label(key));
    match line.split_once('{') {
        Some((name, rest)) => format!("{name}{{{target},{rest}"),
        None => line.replacen(' ', &format!("{{{target}}} "), 1),
    }
}
