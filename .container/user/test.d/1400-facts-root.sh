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

facts="$(systemlint facts --root "${work}/root" --format json)"
b19-assert matches "FACTS" '"VERSION_CODENAME": "inside root"' "${facts}"
b19-assert matches "FACTS" '"status": "ok"' "${facts}"

systemlint facts --root "${work}/root" --output "${work}/facts.yaml"
b19-assert equals "FACTS" "600" "$(stat --format %a "${work}/facts.yaml")"
systemlint --quiet check --tags '!files' - < "${work}/facts.yaml"

stdout="$(cd "${work}" && systemlint facts --root "${work}/root" --output - --format json)"
b19-assert matches "DASH" '"VERSION_CODENAME": "inside root"' "${stdout}"
report="$(cd "${work}" && systemlint --quiet check --tags '!files' --format textfile --fail-on never --output - - < "${work}/facts.yaml")"
b19-assert matches "DASH" 'systemlint_collector_status\{collector="os-release",status="ok"\} 1' "${report}"
b19-assert equals "DASH" "absent" "$(test -e "${work}/-" && echo present || echo absent)"

b19-assert matches "COLLECTOR" 'needs fact sshd.accounts, which collector sshd skipped' "${facts}"
