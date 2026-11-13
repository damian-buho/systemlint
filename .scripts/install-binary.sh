#!/bin/sh

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

# install-binary.sh — build the host-native archive, unpack it into SYSTEMLINT_PREFIX and link the core into ~/.local/bin.

prefix="${SYSTEMLINT_PREFIX:-${HOME}/.systemlint}"
bindir="${HOME}/.local/bin"

log() { printf '[install-binary] %s\n' "$*" >&2; }

log "building the host-native archive"
assets="$(.scripts/build-binaries.sh)"
tarball="${assets##*"
"}" # the archive is the last asset printed

mkdir --parents "${prefix}"
chmod go-w "${prefix}"
tar --extract --gzip --same-permissions --no-same-owner --directory "${prefix}" --file "${tarball}"
log "unpacked ${tarball} -> ${prefix}"

mkdir --parents "${bindir}"
ln --symbolic --force --no-dereference "${prefix}/bin/systemlint" "${bindir}/systemlint"
log "linked ${bindir}/systemlint -> ${prefix}/bin/systemlint ($("${bindir}/systemlint" --version))"
log "sudo resets PATH, so run it as root with: sudo ${bindir}/systemlint check"
