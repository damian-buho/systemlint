// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The one YAML reader of the core: YAML 1.2 booleans only, so `no`, `off` and `y` stay strings.

use serde::de::DeserializeOwned;

/// `text` parsed as YAML into `T`, with only `true` and `false` read as booleans.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(text, serde_saphyr::options! { strict_booleans: true })
}
