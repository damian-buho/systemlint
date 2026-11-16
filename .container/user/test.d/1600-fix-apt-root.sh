#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

work="$(mktemp --directory)"
trap 'rm --recursive --force -- "${work}"' EXIT

archive='deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu resolute main'
vendor='deb [trusted=yes] https://vendor.example/apt resolute main'
list="${work}/etc/apt/sources.list"
mkdir --parents "${work}/etc/apt"
printf 'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n' >"${work}/etc/os-release"
printf '%s\n%s\n%s\n' "${archive}" "${archive}" "${vendor}" >"${list}"
chmod 0640 -- "${list}"

b19-log info "fix apt sources under ${work}"
systemlint --quiet fix --root "${work}" --tags apt --force
b19-assert equals "FIX" "${archive}"$'\n'"#${archive}"$'\n'"#${vendor}" "$(cat -- "${list}")"
b19-assert equals "FIX" "640" "$(stat --format %a -- "${list}")"

before="$(sha256sum -- "${list}")"
systemlint --quiet fix --root "${work}" --tags apt --force
b19-assert equals "FIX AGAIN" "${before}" "$(sha256sum -- "${list}")"
