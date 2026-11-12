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
- Collectors: shipped ones in `collectors/*.yaml`, installed to `../share/systemlint/collectors/` beside the core, plus config `collect.directories`; same trust walk as plugins. Every path read goes through `source::Root` (`openat2` `RESOLVE_IN_ROOT`), live mode being root `/`, so never read a subject file with `std::fs`.
- Facts document: facts at the top level beside `meta` and `collectors`; a reply’s `facts` object lands AT `into`, `redact` entries are JSON Pointers into it. `collect()` takes the clock in `Options.now`.
- Try a change end-to-end by installing `target/debug/systemlint` to `<dir>/bin`, plugins to `<dir>/lib/systemlint/plugins` and `collectors/` to `<dir>/share/systemlint/collectors` under a 0755 `<dir>`, then `<dir>/bin/systemlint facts --root fixtures/ubuntu-26.04`.
- Rule engine: `rules.rs` (specs, rulesets, selectors), `judge.rs` (subjects, `when`, the four outcomes, scores, waivers, `x-version`), `comply.rs`, `report.rs`; format and exit codes in `docs/how-to/rules.md`. Rulesets ship to `../share/systemlint/rulesets/`, catalogs to `../share/systemlint/standards/`, plus `lint.directories` and `comply.directories`; same trust walk. Waiver expiry is the only judgement given the lint clock (`today`), so tests pass the day in.
- Every YAML read goes through `yaml::from_str` (`strict_booleans`): serde-saphyr’s default turns `no`, `off` and `y` into booleans in an untyped `Value`, so `Enabled: no` or `severity: off` would silently change meaning.
- Image: `b19/rust` builder → `b19/ubuntu`; core in `/usr/local/bin`, plugins in `/usr/local/lib/systemlint/plugins`, collectors in `/usr/local/share/systemlint/collectors`.
- License AGPL-3.0-only for the code; scaffolded packaging files keep MIT.
- Integration tests that need files live in `crates/systemlint/tests/` (`CARGO_TARGET_TMPDIR`); fixture scripts are written once behind a `OnceLock` before any test forks, to a temporary name then renamed, since nextest runs each test as its own process and an in-place rewrite of a script another process execs fails with `ETXTBSY`.

## Documentation

[Available make targets](docs/how-to/MAKEFILE.md)
