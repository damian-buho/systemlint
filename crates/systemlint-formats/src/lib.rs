// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The generic parsers: bytes in, facts out.

use systemlint_protocol::{Describe, Reply, Request, Result};

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("formats", &[("ini", &[]), ("kv", &[]), ("lines", &[]), ("regex", &[]), ("toml", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    Err(format!("op {} is not implemented yet", request.op).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_lists_the_generic_parsers() {
        let describe = describe();
        assert_eq!(describe.name, "formats");
        assert_eq!(describe.ops.iter().map(|o| o.op.as_str()).collect::<Vec<_>>(), ["ini", "kv", "lines", "regex", "toml"]);
        assert!(describe.ops.iter().all(|o| o.needs.is_empty()));
    }
}
