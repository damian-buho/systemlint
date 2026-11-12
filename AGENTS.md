<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: MIT
-->

# damian-buho/systemlint

A linter for operating systems: a Rust core that collects host facts and judges them with declarative rules, plus one plugin binary per domain.

## Key facts

- Cargo workspace under `crates/`: `systemlint` (core), `systemlint-protocol` (the only crate a plugin must use), `systemlint-formats`, `systemlint-apt`, `systemlint-sshd`.
- A plugin is `fn op(Request) -> Result<Reply>` in its `lib.rs` behind a two-line `main.rs`; it never does I/O. Protocol and collector schema: `docs/how-to/protocol.md`, `docs/how-to/collectors.md`.
- Plugins are found only in `../lib/systemlint/plugins/` beside the core and in config-named directories, refused when they or any directory above are not owned by root or the user, or group/other-writable. A checkout under a 0775 directory is refused by design: install to a 0755 path to try it.
- Version: `SYSTEMLINT_VERSION` stamped at compile time (`systemlint_protocol::VERSION`), else the workspace `Cargo.toml` version.
- Release binaries: `.scripts/build-binaries.sh` builds every crate with a `src/main.rs` as static musl for `TARGET_OS`/`TARGET_ARCH` into `dist/<crate>-linux-<uname -m>`; the `build-binaries` tool runs it in `b19/rust:musl`. The host needs `rustup target add x86_64-unknown-linux-musl`; arm64 builds in CI only.
- Image: `b19/rust` builder → `b19/ubuntu`; core in `/usr/local/bin`, plugins in `/usr/local/lib/systemlint/plugins`.
- License AGPL-3.0-only for the code; scaffolded packaging files keep MIT.
- Integration tests that need files live in `crates/systemlint/tests/` (`CARGO_TARGET_TMPDIR`); fixture scripts are written once behind a `OnceLock` before any test forks, or a parallel exec hits `ETXTBSY`.

## Documentation

[Available make targets](docs/how-to/MAKEFILE.md)
