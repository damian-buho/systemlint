// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Debian version ordering as dpkg compares `[epoch:]upstream[-revision]`.

use std::cmp::Ordering;

/// The epoch, upstream version and revision of a Debian version, or why it is not one.
pub fn parse_deb(text: &str) -> Result<(u64, &str, &str), String> {
    let (epoch, rest) = match text.split_once(':') {
        Some((epoch, rest)) => (epoch.parse::<u64>().map_err(|_| format!("“{text}” has an epoch that is not a number"))?, rest),
        None => (0, text),
    };
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, ""));
    if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(format!("“{text}” is not a Debian version: its upstream part does not start with a digit"));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || ".+~-:".contains(c);
    if let Some(bad) = rest.chars().find(|c| !allowed(*c)) {
        return Err(format!("“{text}” is not a Debian version: it holds “{bad}”"));
    }
    Ok((epoch, upstream, revision))
}

/// dpkg’s order of `a` against `b`; either failing to parse is an error.
pub fn compare_deb(a: &str, b: &str) -> Result<Ordering, String> {
    let ((ea, ua, ra), (eb, ub, rb)) = (parse_deb(a)?, parse_deb(b)?);
    Ok(ea.cmp(&eb).then_with(|| part(ua, ub)).then_with(|| part(ra, rb)))
}

fn weight(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        while a.first().is_some_and(|c| !c.is_ascii_digit()) || b.first().is_some_and(|c| !c.is_ascii_digit()) {
            let (wa, wb) = (weight(a.first().copied()), weight(b.first().copied()));
            if wa != wb {
                return wa.cmp(&wb);
            }
            (a, b) = (a.get(1..).unwrap_or_default(), b.get(1..).unwrap_or_default());
        }
        let digits = |s: &[u8]| s.iter().take_while(|c| c.is_ascii_digit()).count();
        let (na, nb) = (digits(a), digits(b));
        let trim = |s: &[u8]| -> Vec<u8> { s.iter().copied().skip_while(|c| *c == b'0').collect() };
        let (da, db) = (trim(&a[..na]), trim(&b[..nb]));
        let order = da.len().cmp(&db.len()).then_with(|| da.cmp(&db));
        if order != Ordering::Equal {
            return order;
        }
        (a, b) = (&a[na..], &b[nb..]);
    }
    Ordering::Equal
}
