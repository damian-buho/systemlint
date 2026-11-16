#!/bin/sh

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

# build-binaries.sh — build every binary crate as a static musl binary for one TARGET_OS/TARGET_ARCH cell, stamping SYSTEMLINT_VERSION.

log() { printf '[build-binaries] %s\n' "$*" >&2; }

version="${1:-${M6E_RELEASE_TAG:-${GITHUB_REF_NAME:-}}}"
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
cc_var="CC_$(printf '%s' "${triple}" | tr '-' '_')"
cc="musl-gcc"
[ "${triple%%-*}" = "$(uname -m)" ] || cc="${triple%%-*}-linux-gnu-gcc" # musl-gcc only targets the host architecture
if eval "[ -z \"\${${cc_var}:-}\" ]" && command -v "${cc}" >/dev/null 2>&1; then
	log "compiling C for ${triple} with ${cc} (${cc_var})"
	export "${cc_var}=${cc}"
fi

cargo build --release --locked --quiet --workspace --target "${triple}"

for main in crates/*/src/main.rs; do
	crate="${main#crates/}"
	crate="${crate%%/*}"
	asset="$(TARGET_OS="${target_os}" TARGET_ARCH="${target_arch}" .makefile/core/scripts/asset-name.sh "dist/${crate}")"
	log "copying target/${triple}/release/${crate} -> ${asset}"
	cp "target/${triple}/release/${crate}" "${asset}"
	printf '%s\n' "${asset}" # callers capture these to find the binaries
done

stage="target/${triple}/stage"
rm -rf "${stage}"
mkdir -p "${stage}/bin" "${stage}/lib/systemlint/plugins" "${stage}/share/systemlint"
cp "target/${triple}/release/systemlint" "${stage}/bin/"
for main in crates/systemlint-*/src/main.rs; do
	crate="${main#crates/}"
	cp "target/${triple}/release/${crate%%/*}" "${stage}/lib/systemlint/plugins/"
done
cp -R collectors rulesets "${stage}/share/systemlint/"
tarball="$(TARGET_OS="${target_os}" TARGET_ARCH="${target_arch}" .makefile/core/scripts/asset-name.sh dist/systemlint).tar.gz"
epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
log "packing ${stage} -> ${tarball} (mtime ${epoch})"
tar --create --directory "${stage}" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${epoch}" --mode='u=rwX,go=rX' bin lib share | gzip --no-name --best > "${tarball}"
printf '%s\n' "${tarball}"
