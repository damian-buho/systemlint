// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! sshd: configuration files with `Include` expanded, and the effective `sshd -T` output.

use systemlint_protocol::{Describe, Reply, Request, Result};

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("sshd", &[("config", &[]), ("effective", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    Err(format!("op {} is not implemented yet", request.op).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_lists_files_and_effective() {
        let describe = describe();
        assert_eq!(describe.name, "sshd");
        assert_eq!(describe.ops.iter().map(|o| o.op.as_str()).collect::<Vec<_>>(), ["config", "effective"]);
    }
}
