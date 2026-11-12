// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Cached `*_InRelease` and `*_Release` files from `/var/lib/apt/lists`, with ages against the collection time.

use serde_json::{Map, Value, json};
use systemlint_protocol::{Diagnostic, Input, Reply};

use crate::deb822;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// One fact per cached Release file, keyed by its path: origin, suite, codename, dates, age and expiry.
pub fn lists(inputs: &[Input], now: Option<i64>) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Input::File(file) = input else { continue };
        let mut diagnose = |line: Option<u64>, message: String| reply.diagnostics.push(Diagnostic { path: file.path.clone(), line, message });
        let Some(text) = file.content.as_deref() else {
            diagnose(None, "not UTF-8 text, skipped".to_owned());
            continue;
        };
        let (stanzas, _) = deb822::parse(&deb822::unsign(text));
        let Some(stanza) = stanzas.first() else {
            diagnose(None, "holds no Release fields".to_owned());
            continue;
        };
        let mut fact = Map::new();
        for (name, key) in [("Origin", "origin"), ("Label", "label"), ("Suite", "suite"), ("Codename", "codename"), ("Version", "version")] {
            if let Some(value) = stanza.get(name) {
                fact.insert(key.to_owned(), Value::from(value));
            }
        }
        fact.insert("signed-inline".to_owned(), Value::from(file.path.ends_with("InRelease")));
        let mut date = |name: &str, key: &str| match stanza.get(name).map(|v| (v, parse_date(v))) {
            Some((_, Some(seconds))) => {
                fact.insert(key.to_owned(), Value::from(rfc3339(seconds)));
                Some(seconds)
            }
            Some((raw, None)) => {
                diagnose(None, format!("{name} {raw:?} is not an RFC 2822 date"));
                None
            }
            None => None,
        };
        let published = date("Date", "date");
        let valid_until = date("Valid-Until", "valid-until");
        if let Some(now) = now {
            if let Some(published) = published {
                fact.insert("age-days".to_owned(), json!((now - published).div_euclid(86_400)));
            }
            fact.insert("expired".to_owned(), Value::from(valid_until.is_some_and(|until| until < now)));
        }
        reply.facts.insert(file.path.clone(), Value::Object(fact));
    }
    reply
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Unix seconds as RFC 3339 UTC.
pub fn rfc3339(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn clock(text: &str) -> Option<i64> {
    let parts: Vec<i64> = text.split(':').map(str::parse).collect::<Result<_, _>>().ok()?;
    match parts[..] {
        [h, m, s] if h < 24 && m < 60 && s <= 60 => Some(h * 3600 + m * 60 + s),
        _ => None,
    }
}

/// Unix seconds of a Release date such as `Thu, 23 Apr 2026 17:07:15 UTC` or `… +0000`.
pub fn parse_date(text: &str) -> Option<i64> {
    let words: Vec<&str> = text.split_whitespace().skip_while(|w| w.ends_with(',')).collect();
    let [day, month, year, time, zone] = words[..] else { return None };
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(month))? as i64 + 1;
    let (day, year): (i64, i64) = (day.parse().ok()?, year.parse().ok()?);
    if !(1..=31).contains(&day) {
        return None;
    }
    let offset = match zone {
        "UTC" | "GMT" | "Z" => 0,
        signed if signed.len() == 5 && signed.starts_with(['+', '-']) => {
            let (hours, minutes): (i64, i64) = (signed[1..3].parse().ok()?, signed[3..].parse().ok()?);
            let magnitude = hours * 3600 + minutes * 60;
            if signed.starts_with('-') { -magnitude } else { magnitude }
        }
        _ => return None,
    };
    Some(days_from_civil(year, month, day) * 86_400 + clock(time)? - offset)
}

/// Unix seconds of the request’s `now`, RFC 3339 UTC as the core writes it.
pub fn parse_now(text: &str) -> Option<i64> {
    let (date, time) = text.strip_suffix('Z')?.split_once('T')?;
    let parts: Vec<i64> = date.split('-').map(str::parse).collect::<Result<_, _>>().ok()?;
    let [year, month, day] = parts[..] else { return None };
    Some(days_from_civil(year, month, day) * 86_400 + clock(time)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::FileInput;

    fn file(path: &str, content: &str) -> Input {
        Input::File(FileInput { path: path.to_owned(), content: Some(content.to_owned()), content_base64: None, stat: None })
    }

    #[test]
    fn dates_round_trip_through_rfc3339() {
        let now = parse_now("2026-11-11T12:00:00Z").unwrap();
        assert_eq!(now, 1_794_398_400);
        assert_eq!(rfc3339(now), "2026-11-11T12:00:00Z");
        assert_eq!(parse_date("Thu, 23 Apr 2026 17:07:15 UTC").map(rfc3339).as_deref(), Some("2026-04-23T17:07:15Z"));
        assert_eq!(parse_date("Wed, 11 Nov 2026 11:05:48 -0130").map(rfc3339).as_deref(), Some("2026-11-11T12:35:48Z"));
        assert_eq!(parse_date("29 Feb 2024 00:00:00 GMT").map(rfc3339).as_deref(), Some("2024-02-29T00:00:00Z"));
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn bad_dates_are_none() {
        for bad in ["", "Thu, 23 Foo 2026 17:07:15 UTC", "Thu, 32 Apr 2026 17:07:15 UTC", "Thu, 23 Apr 2026 24:00:00 UTC", "Thu, 23 Apr 2026 17:07:15 CEST", "23 Apr 2026 17:07 UTC"] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert_eq!(parse_now("2026-11-11 12:00:00"), None);
    }

    #[test]
    fn a_release_gives_age_and_expiry_against_now() {
        let now = parse_now("2026-11-11T12:00:00Z");
        let inrelease = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nSuite: resolute\nCodename: resolute\nDate: Wed, 11 Nov 2026 12:00:01 UTC\nValid-Until: Wed, 11 Nov 2026 11:59:59 UTC\nMD5Sum:\n abc 1 main/x\n-----BEGIN PGP SIGNATURE-----\n";
        let reply = lists(&[file("/l/a_InRelease", inrelease), file("/l/b_Release", "Suite: stable\nDate: Tue, 10 Nov 2026 12:00:00 UTC\nValid-Until: Wed, 11 Nov 2026 12:00:00 UTC\n")], now);
        assert!(reply.diagnostics.is_empty(), "{:?}", reply.diagnostics);
        let a = &reply.facts["/l/a_InRelease"];
        assert_eq!((a["codename"].as_str(), a["age-days"].as_i64(), a["expired"].as_bool(), a["signed-inline"].as_bool()), (Some("resolute"), Some(-1), Some(true), Some(true)));
        let b = &reply.facts["/l/b_Release"];
        assert_eq!((b["age-days"].as_i64(), b["expired"].as_bool(), b["signed-inline"].as_bool()), (Some(1), Some(false), Some(false)));
        assert!(b.get("origin").is_none());
    }

    #[test]
    fn no_clock_means_no_age_and_bad_input_is_named() {
        let reply = lists(&[file("/l/c_Release", "Date: someday\n"), file("/l/d_Release", "")], None);
        assert!(reply.facts["/l/c_Release"].get("expired").is_none());
        assert_eq!(reply.diagnostics.len(), 2);
        assert!(reply.diagnostics[0].message.contains("someday"));
    }
}
