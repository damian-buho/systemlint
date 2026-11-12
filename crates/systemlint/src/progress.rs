// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! What a collection tells the user while it runs and once it ends.

use std::time::Duration;

use serde_json::Value;

use crate::collector::Collector;

/// A run shorter than this ends without a closing line.
pub const SLOW: Duration = Duration::from_secs(1);

/// The commands a live collection ran: each `exec` of a collector that ended `ok` on the host.
pub fn commands(document: &Value, collectors: &[Collector]) -> Vec<String> {
    let live = document.pointer("/meta/subject/kind").and_then(Value::as_str) == Some("host");
    let ok = |c: &&Collector| document["collectors"][&c.id]["status"] == "ok";
    collectors.iter().filter(|_| live).filter(ok).filter_map(|c| c.read.exec.as_ref().map(|argv| argv.join(" "))).collect()
}

/// The closing line of a run that took `SLOW` or longer: the time spent, then the commands run.
pub fn finished(elapsed: Duration, commands: &[String]) -> Option<String> {
    let ran = if commands.is_empty() { String::new() } else { format!("; ran {}", commands.join(", ")) };
    (elapsed >= SLOW).then(|| format!("Collected in {:.1} s{ran}.", elapsed.as_secs_f64()))
}
