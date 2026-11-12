#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eo pipefail

# shellcheck source=/dev/null
. b19-i18n

listed="$(systemlint plugin list)"
for plugin in apt formats sshd; do
  b19-assert matches "PLUGINS" "${plugin} [^ ]+ /usr/local/lib/systemlint/plugins/systemlint-${plugin}" "${listed}"
done
