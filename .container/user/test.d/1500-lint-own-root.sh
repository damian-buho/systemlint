#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

work="$(mktemp --directory)"
trap 'rm --recursive --force -- "${work}"' EXIT

systemlint --quiet facts --output "${work}/facts.json"
systemlint --quiet check "${work}/facts.json" --format sarif --fail-on never --output "${work}/systemlint.sarif"
sarif="$(cat -- "${work}/systemlint.sarif")"
b19-assert matches "SARIF" '"version": "2.1.0"' "${sarif}"
b19-assert matches "SARIF" '"name": "systemlint"' "${sarif}"

systemlint --quiet check "${work}/facts.json" --format textfile --fail-on never --output "${work}/systemlint.prom"
metrics="$(cat -- "${work}/systemlint.prom")"
b19-assert matches "TEXTFILE" 'systemlint_collector_status\{collector="os-release",status="ok"\} 1' "${metrics}"
b19-assert matches "TEXTFILE" 'systemlint_checks\{outcome="pass"\} [1-9]' "${metrics}"
b19-assert equals "TEXTFILE" "644" "$(stat --format %a "${work}/systemlint.prom")"
