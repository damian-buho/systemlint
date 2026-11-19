#!/bin/sh

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

# install-binary.sh — build the host-native archive, unpack it into SYSTEMLINT_PREFIX and link the core into ~/.local/bin.

home="${HOME%/}" # a HOME ending in a slash would double it in every path
prefix="${SYSTEMLINT_PREFIX:-${home}/.systemlint}"
bindir="${home}/.local/bin"

log() { printf '[install-binary] %s\n' "$*" >&2; }

log "building the host-native archive"
assets="$(.scripts/build-binaries.sh)"
tarball="${assets##*"
"}" # the archive is the last asset printed

stage="${prefix:?}.new"
old="${prefix}.old"
mkdir --parents "$(dirname "${prefix}")"
exec 9>"${prefix}.lock"
flock --nonblock 9 || { log "another install holds ${prefix}.lock"; exit 1; }
rm --recursive --force -- "${stage}" "${old}"
mkdir --mode=0755 "${stage}"
tar --extract --gzip --same-permissions --no-same-owner --directory "${stage}" --file "${tarball}"
log "unpacked ${tarball} -> ${stage}"
if [ -d "${prefix}" ]; then mv --no-target-directory "${prefix}" "${old}"; fi
mv --no-target-directory "${stage}" "${prefix}"
rm --recursive --force -- "${old}"
log "swapped ${stage} -> ${prefix}, dropping files the archive no longer ships"

mkdir --parents "${bindir}"
[ -x "${prefix}/bin/systemlint" ] || { log "the archive holds no executable ${prefix}/bin/systemlint"; exit 1; }
ln --symbolic --force --no-dereference "${prefix}/bin/systemlint" "${bindir}/systemlint"
log "linked ${bindir}/systemlint -> ${prefix}/bin/systemlint ($("${bindir}/systemlint" --version))"
log "sudo resets PATH, so run it as root with: sudo ${bindir}/systemlint check"
