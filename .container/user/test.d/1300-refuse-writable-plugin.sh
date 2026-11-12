#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

work="$(mktemp --directory)"
trap 'rm --recursive --force -- "${work}"' EXIT
mkdir --mode 0777 "${work}/plugins"
cp /usr/local/lib/systemlint/plugins/systemlint-formats "${work}/plugins/systemlint-planted"
printf 'plugins:\n  directories: [%s]\n' "${work}/plugins" > "${work}/config.yaml"

status=0
errors="$(systemlint --config "${work}/config.yaml" plugin list 2>&1 >/dev/null)" || status=$?
b19-assert equals "TRUST" "4" "${status}"
b19-assert matches "TRUST" "refused ${work}/plugins: group or others can write" "${errors}"
