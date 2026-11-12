#!/bin/sh

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

# build-binaries.sh — build every binary crate as a static musl binary for one TARGET_OS/TARGET_ARCH cell, stamping SYSTEMLINT_VERSION.

log() { printf '[build-binaries] %s\n' "$*" >&2; }

version="${1:-${GITHUB_REF_NAME:-}}"
case "${version}" in
	'' | *['{}']*) version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)" ;; # empty or an unexpanded template placeholder
esac

target_os="${TARGET_OS:-linux}"
target_arch="${TARGET_ARCH:-}"
case "${target_arch}" in
	'')
		case "$(uname -m)" in
			x86_64 | amd64) target_arch=amd64 ;;
			aarch64 | arm64) target_arch=arm64 ;;
			*) target_arch="$(uname -m)" ;;
		esac
		;;
esac

case "${target_os}/${target_arch}" in
	linux/amd64) triple=x86_64-unknown-linux-musl ;;
	linux/arm64) triple=aarch64-unknown-linux-musl ;;
	*)
		log "error: no musl target for ${target_os}/${target_arch}; supported: linux/amd64, linux/arm64"
		exit 2
		;;
esac

log "building systemlint ${version} for ${target_os}/${target_arch} (${triple})"
mkdir -p dist
export SYSTEMLINT_VERSION="${version}"

cargo build --release --locked --quiet --workspace --target "${triple}"

for main in crates/*/src/main.rs; do
	crate="${main#crates/}"
	crate="${crate%%/*}"
	asset="$(TARGET_OS="${target_os}" TARGET_ARCH="${target_arch}" .makefile/core/scripts/asset-name.sh "dist/${crate}")"
	log "copying target/${triple}/release/${crate} -> ${asset}"
	cp "target/${triple}/release/${crate}" "${asset}"
	printf '%s\n' "${asset}" # callers capture these to find the binaries
done
