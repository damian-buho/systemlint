// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Keeps the recent debug records of each collector or plugin, to print under the error they lead to.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use log::{Level, LevelFilter, Log, Metadata, Record};

/// How many records one scope keeps, the oldest dropped first.
pub const KEEP: usize = 50;

static KEPT: Mutex<BTreeMap<String, VecDeque<String>>> = Mutex::new(BTreeMap::new());

thread_local! {
    static SCOPE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The scope of the configuration, rulesets and catalogs, whose errors exit 5.
pub const CONFIG: &str = "config";

/// The scope of the plugin and collector trust walk, whose refusals exit 4.
pub const DISCOVERY: &str = "discovery";

/// The scope of the root and the facts document read, whose errors exit 6.
pub const INPUT: &str = "input";

/// The scope of a collector, also how its error line starts.
pub fn collector(id: &str) -> String {
    format!("collector {id}")
}

/// The scope of a plugin, also how its error line starts.
pub fn plugin(name: &str) -> String {
    format!("plugin {name}")
}

/// Runs `body` with every record it logs on this thread kept under `tag`.
pub fn scoped<T>(tag: &str, body: impl FnOnce() -> T) -> T {
    let outer = SCOPE.with(|s| s.replace(Some(tag.to_owned())));
    let result = body();
    SCOPE.with(|s| *s.borrow_mut() = outer);
    result
}

/// The scope records on this thread go to, if any.
pub fn current() -> Option<String> {
    SCOPE.with(|s| s.borrow().clone())
}

struct Trail {
    verbose: Option<env_logger::Logger>,
}

impl Log for Trail {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug && (self.verbose.is_some() || current().is_some())
    }

    fn log(&self, record: &Record) {
        if let Some(logger) = &self.verbose {
            if logger.matches(record) {
                logger.log(record);
            }
            return;
        }
        if let Some(tag) = current().filter(|_| record.level() <= Level::Debug) {
            keep(&tag, record.args().to_string());
        }
    }

    fn flush(&self) {
        if let Some(logger) = &self.verbose {
            logger.flush();
        }
    }
}

/// Installs the logger: every debug record to stderr when `verbose`, else the last [`KEEP`] of each scope.
pub fn install(verbose: bool) {
    let verbose = verbose.then(|| env_logger::Builder::new().filter_level(LevelFilter::Debug).build());
    if log::set_boxed_logger(Box::new(Trail { verbose })).is_ok() {
        log::set_max_level(LevelFilter::Debug);
    }
}

/// Keeps `line` under `tag`, dropping the oldest past [`KEEP`].
pub fn keep(tag: &str, line: String) {
    let mut kept = KEPT.lock().unwrap_or_else(PoisonError::into_inner);
    let lines = kept.entry(tag.to_owned()).or_default();
    if lines.len() == KEEP {
        lines.pop_front();
    }
    lines.push_back(line);
}

/// Takes the records kept under `tag`, oldest first.
pub fn take(tag: &str) -> Vec<String> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner).remove(tag).map(Vec::from).unwrap_or_default()
}

/// Every kept record under a heading, each led by its scope, for a crash report; empty when none or the store is busy.
pub fn dump() -> String {
    let Ok(kept) = KEPT.try_lock() else { return String::new() };
    let heading = if kept.is_empty() { String::new() } else { "\nlast debug records:\n".to_owned() };
    kept.iter().flat_map(|(tag, lines)| lines.iter().map(move |line| (tag, line))).fold(heading, |mut out, (tag, line)| {
        let _ = writeln!(out, "{tag}: {line}");
        out
    })
}
