<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: MIT
-->

# damian-buho/systemlint

A linter for operating systems: a Rust core that collects host facts and judges them with declarative rules, plus one plugin binary per domain.

## Key facts

- Cargo workspace under `crates/`: `systemlint` (core), `systemlint-protocol` (the only crate a plugin must use), `systemlint-formats`, `systemlint-apt`, `systemlint-sshd`, `systemlint-env`.
- A plugin is `fn op(Request) -> Result<Reply>` in its `lib.rs` behind a two-line `main.rs`; it never does I/O. Protocol and collector schema: `docs/how-to/protocol.md`, `docs/how-to/collectors.md`.
- Plugins are found only in `../lib/systemlint/plugins/` beside the core and in config-named directories, refused when they or any directory above are not owned by root or the user, or group/other-writable. A checkout under a 0775 directory is refused by design: install to a 0755 path to try it.
- Version: `SYSTEMLINT_VERSION` stamped at compile time (`systemlint_protocol::VERSION`), else the workspace `Cargo.toml` version.
- Release binaries: `.scripts/build-binaries.sh` builds every crate with a `src/main.rs` as static musl for `TARGET_OS`/`TARGET_ARCH` into `dist/<crate>-linux-<uname -m>`, plus `dist/systemlint-linux-<uname -m>.tar.gz`, the relocatable install tree (`bin/`, `lib/systemlint/plugins/`, `share/systemlint/`, modes normalised, mtime from the commit) that a future nfpm package maps too; every asset matches the release actions’ `dist/systemlint-*` glob. The `build-binaries` tool runs it in `b19/rust:musl`. The host needs `rustup target add x86_64-unknown-linux-musl`; arm64 builds in CI only.
- Collectors: shipped ones in `collectors/*.yaml`, installed to `../share/systemlint/collectors/` beside the core, plus config `collect.directories`; same trust walk as plugins. Every path read goes through `source::Root` (`openat2` `RESOLVE_IN_ROOT`), live mode being root `/`, so never read a subject file with `std::fs`.
- Facts document: facts at the top level beside `meta` and `collectors`; a reply’s `facts` object lands AT `into`, `redact` entries are JSON Pointers into it. `collect()` takes the clock in `Options.now`.
- Try a change end-to-end by installing `target/debug/systemlint` to `<dir>/bin`, plugins to `<dir>/lib/systemlint/plugins`, `collectors/` and `rulesets/` to `<dir>/share/systemlint/` under a 0755 `<dir>` whose every parent is 0755 or stricter (a direct child of the home directory; `~/.local` is 0775), then `<dir>/bin/systemlint lint --root fixtures/ubuntu-26.04`.
- Rule engine (shipped rulesets in `rulesets/*.yaml`): `rules.rs` (specs, rulesets, selectors), `judge.rs` (subjects, `when`, the four outcomes, scores, waivers, `x-version`), `comply.rs`, `report.rs`; format and exit codes in `docs/how-to/rules.md`. Rulesets ship to `../share/systemlint/rulesets/`, catalogs to `../share/systemlint/standards/`, plus `lint.directories` and `comply.directories`; same trust walk. Waiver expiry is the only judgement given the lint clock (`today`), so tests pass the day in.
- Every YAML read goes through `yaml::from_str` (`strict_booleans`): serde-saphyr’s default turns `no`, `off` and `y` into booleans in an untyped `Value`, so `Enabled: no` or `severity: off` would silently change meaning.
- Image: `b19/rust` builder → `b19/ubuntu`; core in `/usr/local/bin`, plugins in `/usr/local/lib/systemlint/plugins`, collectors and rulesets in `/usr/local/share/systemlint/`.
- License AGPL-3.0-only for the code; scaffolded packaging files keep MIT.
- apt: `systemlint-apt` keys a source `path:line` (paragraph or line start); `sources` needs `apt.lists` and matches a source to its cached Release by apt’s list filename (`sources::list_name`). Facts and rules: `docs/how-to/apt.md`. `crates/systemlint/tests/apt.rs` reads fixtures through `collect::inputs` and calls the plugin libraries in-process (dev-dependencies), since the nextest tool builds only the core’s own binaries; `fixtures/apt-misconfigured` fails every `apt` rule once.
- files: one `files-<group>` collector per domain into `files.<group>` (`formats stat`), so one unreadable directory fails its group alone; `judge::walk` binds a failed collector’s `into` key under a `*` as an `unknown` subject. Git keeps no modes, so `tests/files.rs` builds its root under `CARGO_TARGET_TMPDIR` with explicit modes, parents included (the 0775 umask makes `usr` group-writable). Facts and rules: `docs/how-to/files.md`.
- sshd: one `sshd` collector reads the files and runs `sshd -T` (a collector with `files` keeps them under `--root` and drops its `exec`; an absent program reaches the plugin as exit 127); the plugin takes the global config from `-T` when it exits 0, else from the files over `src/defaults.txt` (`sshd -T -f /dev/null`, recaptured in a container on an OpenSSH bump), and `Match` blocks always from the files, merged. `tests/sshd.rs` pins that files and the captured `fixtures/sshd/sshd-T.txt` give identical outcomes. Facts and rules: `docs/how-to/sshd.md`.
- env: five `env-<source>` collectors into `env.files|defaults|units|processes|image`, one environment per file, unit, service or image (`{kind, vars, path}`); `systemlint-env` marks every value outside `env::CLEAR` in the reply’s `hash`, and the core replaces it with an HMAC under `Options.hash_key` (random per run, or `collect.hash-key`), so the key never reaches a plugin. `env-processes` is `live: true` and needs root; `env-image` reads `--image-config` (`read.image-config`), a host file outside the root. Rules over a whole `vars` object (`properties: {LD_PRELOAD: false}`), since an absent fact is `unknown`. `fixtures/services` fails every `env` rule once, its fake `/proc` read with `live` set in `tests/env.rs`. Facts and rules: `docs/how-to/env.md`; sysctl, Docker and unit facts: `docs/how-to/services.md`.
- A `files` match that is not a regular file is skipped (`source::Root::read` answers `InvalidInput`), so `/etc/default/*` with a directory or a unit masked to `/dev/null` never fails a collector.
- Integration tests that need files live in `crates/systemlint/tests/` (`CARGO_TARGET_TMPDIR`); fixture scripts are written once behind a `OnceLock` before any test forks, to a temporary name then renamed, since nextest runs each test as its own process and an in-place rewrite of a script another process execs fails with `ETXTBSY`.

## Documentation

[Available make targets](docs/how-to/MAKEFILE.md)
