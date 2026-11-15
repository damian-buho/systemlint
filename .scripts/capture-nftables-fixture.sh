#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Usage: capture-nftables-fixture.sh: loads each fixtures/nftables/<name>.nft into a fresh user network namespace and writes the nftables collector’s output to <name>.json.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mapfile -t argv < <(yq '.read.exec[]' "${here}/collectors/nftables.yaml")
argv[0]="$(command -v nft)"
for source in "${here}"/fixtures/nftables/*.nft; do
  out="${source%.nft}.json"
  echo "capturing ${argv[*]} after loading ${source##*/}" >&2
  # shellcheck disable=SC2016 # the arguments expand inside the namespace
  timeout 60s unshare --map-root-user --net bash -c '"$1" --file "$2" && "${@:3}"' capture "${argv[0]}" "${source}" "${argv[@]}" >"${out}"
  printf '%s\n' 'SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>' '' 'SPDX-License-Identifier: AGPL-3.0-only' >"${out}.license"
done
