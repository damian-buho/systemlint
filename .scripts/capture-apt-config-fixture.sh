#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Usage: capture-apt-config-fixture.sh IMAGE FIXTURE (ubuntu:26.04 apt-misconfigured): writes fixtures/FIXTURE/apt-config-dump.txt from the apt-config collector’s argv.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 2 ]] || { echo "usage: $0 IMAGE FIXTURE" >&2; exit 2; }
image="$1"
fixture="${here}/fixtures/$2"
[[ -d ${fixture} ]] || { echo "no fixture root ${fixture}" >&2; exit 2; }
mapfile -t argv < <(yq '.read.exec[]' "${here}/collectors/apt-config.yaml")
echo "capturing ${argv[0]} with $((${#argv[@]} - 1)) arguments in ${image} for $2" >&2
# shellcheck disable=SC2016 # the script expands inside the container
timeout --kill-after=30s 300s docker run --rm --cpus 1 --memory 512m --user 0 \
  --env "OWNER=$(id --user):$(id --group)" \
  --mount "type=bind,source=${fixture},target=/fixture" "${image}" bash -c '
  set -e
  if [ -d /fixture/etc/apt/apt.conf.d ]; then cp /fixture/etc/apt/apt.conf.d/* /etc/apt/apt.conf.d/; fi
  "$@" > /fixture/apt-config-dump.txt
  echo "$(wc --lines < /fixture/apt-config-dump.txt) keys" >&2
  chown "${OWNER}" /fixture/apt-config-dump.txt' capture "${argv[@]}"
