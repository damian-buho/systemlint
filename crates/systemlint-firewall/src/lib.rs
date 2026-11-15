// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! firewall: the filter each address family and netfilter hook gets from every base chain on it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use systemlint_formats::text;
use systemlint_protocol::{Describe, Input, Reply, Request, Result};

/// The netfilter hooks an IPv4 or IPv6 packet passes, in order.
pub const HOOKS: [&str; 5] = ["prerouting", "input", "forward", "output", "postrouting"];

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("firewall", &[("nftables", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "nftables" => nftables(&request.inputs),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// A chain by family, table and name.
type Chain = (String, String, String);

/// Per `ipv4` and `ipv6`, per hook: the base chains on it, `drop` when any has that policy, and whether a rule they reach drops or rejects.
pub fn nftables(inputs: &[Input]) -> Result<Reply> {
    let mut reply = Reply::default();
    let Some((name, output)) = inputs.iter().find_map(|i| text(i, &mut reply.diagnostics)) else {
        return Err(format!("no nft output: {:?}", reply.diagnostics).into());
    };
    let document: Value =
        serde_json::from_str(output).map_err(|e| format!("{name} printed no JSON: {e}"))?;
    let entries = document["nftables"]
        .as_array()
        .ok_or_else(|| format!("{name} printed no nftables list"))?;
    let mut bases = Vec::new();
    let mut rules: BTreeMap<Chain, Vec<&Value>> = BTreeMap::new();
    for entry in entries {
        if let Some(chain) = entry.get("chain").filter(|c| c.get("hook").is_some()) {
            bases.push(chain);
        } else if let Some(rule) = entry.get("rule") {
            rules
                .entry(key(rule, "chain"))
                .or_default()
                .push(&rule["expr"]);
        }
    }
    let mut hooks: BTreeMap<&str, Map<String, Value>> = ["ipv4", "ipv6"]
        .into_iter()
        .map(|af| {
            let open = HOOKS.map(|h| {
                (
                    h.to_owned(),
                    json!({"policy": "accept", "drops": false, "chains": []}),
                )
            });
            (af, open.into_iter().collect())
        })
        .collect();
    for chain in bases {
        let families: &[&str] = match chain["family"].as_str() {
            Some("ip") => &["ipv4"],
            Some("ip6") => &["ipv6"],
            Some("inet") => &["ipv4", "ipv6"],
            _ => &[],
        };
        let at = key(chain, "name");
        let drops = reaches(&rules, &at, &mut BTreeSet::new());
        for family in families {
            let Some(hook) = chain["hook"]
                .as_str()
                .and_then(|h| hooks.get_mut(family)?.get_mut(h))
            else {
                continue;
            };
            if chain["policy"] == "drop" {
                hook["policy"] = json!("drop");
            }
            hook["drops"] = json!(hook["drops"] == true || drops);
            if let Some(list) = hook["chains"].as_array_mut() {
                list.push(json!(format!("{} {} {}", at.0, at.1, at.2)));
            }
        }
    }
    reply.facts = hooks
        .into_iter()
        .map(|(af, h)| (af.to_owned(), Value::Object(h)))
        .collect();
    Ok(reply)
}

/// The family, table and the chain named by `field` of a chain or rule entry.
fn key(entry: &Value, field: &str) -> Chain {
    let part = |f: &str| entry[f].as_str().unwrap_or_default().to_owned();
    (part("family"), part("table"), part(field))
}

/// Whether a rule in `chain`, or in a chain it jumps or goes to, drops or rejects; each chain visited once.
fn reaches(
    rules: &BTreeMap<Chain, Vec<&Value>>,
    chain: &Chain,
    seen: &mut BTreeSet<Chain>,
) -> bool {
    if !seen.insert(chain.clone()) {
        return false;
    }
    let mut targets = Vec::new();
    let drops = rules
        .get(chain)
        .into_iter()
        .flatten()
        .any(|expr| verdicts(expr, &mut targets));
    drops
        || targets
            .into_iter()
            .any(|t| reaches(rules, &(chain.0.clone(), chain.1.clone(), t), seen))
}

/// Whether `value` holds a drop or reject verdict anywhere, a verdict map’s included; collects the chains it jumps or goes to.
fn verdicts(value: &Value, targets: &mut Vec<String>) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(k, v)| match k.as_str() {
            "drop" | "reject" => true,
            "xt" => v["type"] == "target" && matches!(v["name"].as_str(), Some("DROP" | "REJECT")),
            "jump" | "goto" => {
                targets.extend(v["target"].as_str().map(str::to_owned));
                false
            }
            _ => verdicts(v, targets),
        }),
        Value::Array(items) => items.iter().any(|v| verdicts(v, targets)),
        _ => false,
    }
}
