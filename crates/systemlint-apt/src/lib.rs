// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! apt: sources, cached lists and installed packages, judged against the host release.

use systemlint_protocol::{Describe, Reply, Request, Result};

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("apt", &[("installed", &[]), ("lists", &[]), ("sources", &["os.release"])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    Err(format!("op {} is not implemented yet", request.op).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_needs_the_host_release() {
        let describe = describe();
        assert_eq!(describe.name, "apt");
        let sources = describe.ops.iter().find(|o| o.op == "sources").unwrap();
        assert_eq!(sources.needs, ["os.release"]);
    }
}
