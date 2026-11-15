#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Usage: capture-sudo-fixture.sh IMAGE ACCOUNT… (ubuntu:26.04 alice bob carol dave daemon): writes fixtures/sudo/<sudo>/<account>.txt per sudo implementation from the sudo-grants collector’s argv, and version.txt from sudo --version, read through a pipe as the core reads it.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -gt 1 ]] || { echo "usage: $0 IMAGE ACCOUNT…" >&2; exit 2; }
image="$1"
shift
mapfile -t argv < <(yq '.read.exec-from.argv[]' "${here}/collectors/sudo-grants.yaml")
echo "capturing ${argv[*]} for $# accounts in ${image}" >&2
# shellcheck disable=SC2016 # the script expands inside the container
timeout --kill-after=30s 900s docker run --rm --cpus 2 --memory 1g --user 0 --env DEBIAN_FRONTEND=noninteractive \
  --env "OWNER=$(id --user):$(id --group)" --env "ARGV=${argv[*]}" \
  --mount "type=bind,source=${here}/fixtures/sudo,target=/fixture" "${image}" bash -c '
  set -e
  apt-get update --quiet=2 >/dev/null
  apt-get install --yes --quiet=2 --no-install-recommends sudo sudo-rs >/dev/null
  cp /fixture/etc/sudoers.d/* /etc/sudoers.d/
  chmod 0440 /etc/sudoers.d/*
  for account in "$@"; do id "${account}" >/dev/null 2>&1 || useradd "${account}"; done
  usermod --append --groups sudo carol
  for pair in sudo.ws:/usr/bin/sudo.ws sudo-rs:/usr/lib/cargo/bin/sudo; do
    sudo="${pair#*:}"
    out="/fixture/${pair%%:*}"
    mkdir --parents "${out}"
    LC_ALL=C "${sudo}" --version 2>/dev/null | cat > "${out}/version.txt"
    for account in "$@"; do
      read -r -a run <<<"${ARGV//\{key\}/${account}}"
      run[0]="${sudo}"
      LC_ALL=C "${run[@]}" 2>/dev/null | cat > "${out}/${account}.txt"
    done
    echo "${sudo}: $(cat "${out}"/*.txt | wc --lines) lines" >&2
  done
  chown --recursive "${OWNER}" /fixture' sudo "$@"
