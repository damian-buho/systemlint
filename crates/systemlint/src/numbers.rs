// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Quantities as the human report prints them: digits grouped and bytes in binary units, in the run’s locale.

use std::cell::Cell;

use num_format::{Locale, ToFormattedString};
use serde::{Deserialize, Serialize};

/// What a rule’s number counts, so the human report can print it as a quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unit {
    /// A number of bytes, printed in KiB, MiB and up.
    Bytes,
    /// A plain count, printed with its digits grouped.
    Count,
}

const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

thread_local! {
    static LOCALE: Cell<Option<Locale>> = const { Cell::new(None) };
}

/// The locale POSIX ranks first for numbers (`LC_ALL`, `LC_NUMERIC`, then `LANG`), `None` for C, POSIX or one CLDR lacks.
pub fn locale(var: impl Fn(&str) -> Option<String>) -> Option<Locale> {
    let name = ["LC_ALL", "LC_NUMERIC", "LANG"]
        .into_iter()
        .find_map(|v| var(v).filter(|s| !s.is_empty()))?;
    let bare = name
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .replace('_', "-");
    let language = bare.split('-').next().unwrap_or_default();
    let found = Locale::from_name(&bare)
        .or_else(|_| Locale::from_name(language))
        .ok()
        .filter(|_| !matches!(language, "C" | "POSIX" | ""));
    log::debug!(
        "numbers in locale {name:?} print as {:?}",
        found.map(|l| l.name())
    );
    found
}

/// Prints every later quantity on this thread in `locale`, or with no grouping for `None`.
pub fn set(locale: Option<Locale>) {
    LOCALE.set(locale);
}

/// `n` with its digits grouped as the locale groups them.
pub fn count(n: u64) -> String {
    LOCALE
        .get()
        .map_or_else(|| n.to_string(), |l| n.to_formatted_string(&l))
}

/// `n` bytes in the largest binary unit it fills, to one decimal, a whole number without one.
pub fn bytes(n: u64) -> String {
    let mut unit = 0;
    let tenths = loop {
        let tenths = (u128::from(n) * 10 + (1u128 << (10 * unit)) / 2) >> (10 * unit);
        if tenths < 10 * 1024 || unit == UNITS.len() - 1 {
            break tenths;
        }
        unit += 1;
    };
    let whole = count(u64::try_from(tenths / 10).unwrap_or(u64::MAX));
    match tenths % 10 {
        0 => format!("{whole} {}", UNITS[unit]),
        d => {
            let point = LOCALE.get().map_or(".", |l| l.decimal());
            format!("{whole}{point}{d} {}", UNITS[unit])
        }
    }
}

/// `text` printed as a quantity of `unit` when it is a whole number, else as it is.
pub fn quantity(unit: Unit, text: &str) -> String {
    match (text.parse::<u64>(), unit) {
        (Ok(n), Unit::Bytes) => bytes(n),
        (Ok(n), Unit::Count) => count(n),
        (Err(_), _) => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> Option<Locale> {
        locale(|v| (v == "LANG").then(|| name.to_owned()))
    }

    #[test]
    fn locale_follows_posix_precedence_and_c_groups_nothing() {
        let env = |all: &'static str, numeric: &'static str| {
            move |v: &str| match v {
                "LC_ALL" => Some(all.to_owned()),
                "LC_NUMERIC" => Some(numeric.to_owned()),
                _ => Some("en_US.UTF-8".to_owned()),
            }
        };
        assert_eq!(locale(env("uk_UA.UTF-8", "es_ES")), Some(Locale::uk));
        assert_eq!(locale(env("", "es_ES.UTF-8@euro")), Some(Locale::es));
        assert_eq!(locale(env("", "")), Some(Locale::en));
        assert_eq!(named("de_CH.UTF-8"), Some(Locale::de_CH));
        for none in ["C", "C.UTF-8", "POSIX", "xx_YY", ""] {
            assert_eq!(named(none), None, "{none}");
        }
        assert_eq!(locale(|_| None), None);
    }

    #[test]
    fn count_groups_in_the_set_locale_only() {
        set(None);
        assert_eq!(count(10_000), "10000");
        set(Some(Locale::en));
        assert_eq!((count(999), count(1000)), ("999".into(), "1,000".into()));
        set(Some(Locale::es));
        assert_eq!(count(10_000), "10.000");
        set(None);
    }

    #[test]
    fn bytes_takes_the_unit_it_fills_and_rounds_into_the_next() {
        set(None);
        let cases = [
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1 KiB"),
            (1536, "1.5 KiB"),
            (1024 * 1024 - 52, "1023.9 KiB"),
            (1024 * 1024 - 51, "1 MiB"),
            (2_147_483_648, "2 GiB"),
            (u64::MAX, "16 EiB"),
        ];
        for (n, want) in cases {
            assert_eq!(bytes(n), want, "{n}");
        }
        set(Some(Locale::uk));
        assert_eq!(bytes(1_610_612_736), "1,5 GiB");
        set(None);
    }

    #[test]
    fn quantity_leaves_what_is_not_a_whole_number() {
        set(Some(Locale::en));
        assert_eq!(quantity(Unit::Count, "12345"), "12,345");
        assert_eq!(quantity(Unit::Bytes, "1.5"), "1.5");
        assert_eq!(quantity(Unit::Count, "none"), "none");
        set(None);
    }
}
