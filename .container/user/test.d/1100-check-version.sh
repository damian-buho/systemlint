#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: MIT

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

b19-assert matches "VERSION" '^systemlint [0-9a-z.+-]+$' "$(systemlint --version)"
