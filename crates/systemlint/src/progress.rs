// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! What a collection tells the user while it runs and once it ends.

use std::time::Duration;

use serde_json::Value;

use crate::collector::Collector;

/// A run shorter than this ends without a closing line.
pub const SLOW: Duration = Duration::from_secs(1);

/// The commands a live collection ran: each `exec`, and each `exec-from` per entry, of a collector that ended `ok` on the host.
pub fn commands(document: &Value, collectors: &[Collector]) -> Vec<String> {
    let live = document
        .pointer("/meta/subject/kind")
        .and_then(Value::as_str)
        == Some("host");
    let ok = |c: &&Collector| document["collectors"][&c.id]["status"] == "ok";
    collectors
        .iter()
        .filter(|_| live)
        .filter(ok)
        .flat_map(|c| {
            let each = c
                .read
                .exec_from
                .as_ref()
                .map(|e| format!("{} per {} entry", e.argv.join(" "), e.each));
            c.read
                .exec
                .as_ref()
                .map(|argv| argv.join(" "))
                .into_iter()
                .chain(each)
        })
        .collect()
}

/// Every network target a collection asked: each `addr`, `dns` name or nameserver probed, and `http` of a collector that ran.
pub fn reached(document: &Value, collectors: &[Collector]) -> Vec<String> {
    let ran = |c: &&Collector| document["collectors"][&c.id]["status"] != "skipped";
    let dns = |c: &Collector| match c.read.dns_server_from.is_empty() {
        true => c.read.dns.clone(),
        false => document
            .as_object()
            .and_then(|facts| crate::collect::lookup(facts, &format!("{}.nameserver", c.into)))
            .and_then(Value::as_object)
            .map(|servers| servers.keys().cloned().collect())
            .unwrap_or_default(),
    };
    collectors
        .iter()
        .filter(|c| c.network)
        .filter(ran)
        .flat_map(|c| {
            let read = &c.read;
            read.addr
                .iter()
                .cloned()
                .chain(dns(c))
                .chain(read.http.iter().map(|h| h.url.clone()))
        })
        .collect()
}

/// The closing line of a run that took `SLOW` or longer, or reached the network: the time spent, the commands run, the targets asked.
pub fn finished(elapsed: Duration, commands: &[String], reached: &[String]) -> Option<String> {
    let list = |verb: &str, items: &[String]| match items.is_empty() {
        true => String::new(),
        false => format!("; {verb} {}", items.join(", ")),
    };
    (elapsed >= SLOW || !reached.is_empty()).then(|| {
        format!(
            "Collected in {:.1} s{}{}.",
            elapsed.as_secs_f64(),
            list("ran", commands),
            list("asked the network about", reached)
        )
    })
}
