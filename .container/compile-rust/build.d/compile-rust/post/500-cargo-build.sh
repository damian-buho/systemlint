#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

  export SYSTEMLINT_VERSION="${M6E_VERSION:-}"

  b19-run "SYSTEMLINT" "$(_p "Compile systemlint %s" "${SYSTEMLINT_VERSION:-from Cargo.toml}")" --      \
    cargo build --release --locked --workspace --manifest-path=Cargo.toml

  b19-run "SYSTEMLINT" "$(_p "Make %s directory" "/export/usr/local/lib/systemlint/plugins")" --      \
    mkdir --parents /export/usr/local/bin /export/usr/local/lib/systemlint/plugins

  b19-run "SYSTEMLINT" "$(_p "Copy %s to %s" "systemlint" "/export/usr/local/bin/")" --      \
    cp --verbose target/release/systemlint /export/usr/local/bin/

  for main in crates/systemlint-*/src/main.rs; do
    plugin="${main#crates/}"
    plugin="${plugin%%/*}"
    b19-run "SYSTEMLINT" "$(_p "Copy %s to %s" "${plugin}" "/export/usr/local/lib/systemlint/plugins/")" --      \
      cp --verbose "target/release/${plugin}" /export/usr/local/lib/systemlint/plugins/
  done

  b19-run "SYSTEMLINT" "$(_p "Copy %s to %s" "collectors" "/export/usr/local/share/systemlint/collectors/")" --      \
    install -D --mode 0644 --target-directory /export/usr/local/share/systemlint/collectors collectors/*.yaml

  b19-run "SYSTEMLINT" "$(_p "Copy %s to %s" "rulesets" "/export/usr/local/share/systemlint/rulesets/")" --      \
    install -D --mode 0644 --target-directory /export/usr/local/share/systemlint/rulesets rulesets/*.yaml
