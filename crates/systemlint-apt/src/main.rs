// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

fn main() -> std::process::ExitCode {
    systemlint_protocol::run(&systemlint_apt::describe(), systemlint_apt::op)
}
