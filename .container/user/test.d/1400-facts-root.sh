#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

work="$(mktemp --directory)"
trap 'rm --recursive --force -- "${work}"' EXIT
mkdir --parents "${work}/root/etc" "${work}/root/usr/lib"
printf 'ID=fixture\nVERSION_CODENAME="inside root"\n' > "${work}/root/usr/lib/os-release"
ln --symbolic /usr/lib/os-release "${work}/root/etc/os-release"

facts="$(systemlint facts --root "${work}/root" --json)"
b19-assert matches "FACTS" '"VERSION_CODENAME": "inside root"' "${facts}"
b19-assert matches "FACTS" '"status": "ok"' "${facts}"

systemlint facts --root "${work}/root" --save "${work}/facts.yaml"
b19-assert equals "FACTS" "600" "$(stat --format %a "${work}/facts.yaml")"
systemlint --quiet lint --tags '!files' - < "${work}/facts.yaml"
