#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Usage: capture-sshd-defaults.sh IMAGE… (debian:12 ubuntu:26.04): writes each image’s compiled sshd defaults.

set -euo pipefail

out="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../crates/systemlint-sshd/src/defaults" && pwd)"
[[ $# -gt 0 ]] || { echo "usage: $0 IMAGE…" >&2; exit 2; }

for image in "$@"; do
  echo "capturing sshd -T -f /dev/null in ${image}" >&2
  dump="$(timeout --kill-after=30s 900s docker run --rm --cpus 2 --memory 1g --env DEBIAN_FRONTEND=noninteractive "${image}" bash -c '
    set -e
    apt-get update --quiet=2 >/dev/null
    apt-get install --yes --quiet=2 --no-install-recommends openssh-server >/dev/null
    ssh-keygen -A >/dev/null
    mkdir --parents /run/sshd
    dpkg-query --show openssh-server | cut --fields=2
    /usr/sbin/sshd -T -f /dev/null')"
  package="$(head --lines=1 <<<"${dump}")"
  upstream="${package#*:}"
  upstream="${upstream%-*}"
  [[ ${upstream} =~ ^[0-9]+\.[0-9]+p[0-9]+$ ]] || { echo "${image}: unexpected openssh-server version ${package}" >&2; exit 1; }
  tail --lines=+2 <<<"${dump}" > "${out}/${upstream}.txt"
  echo "${image}: openssh-server ${package} → ${out}/${upstream}.txt ($(wc --lines < "${out}/${upstream}.txt") keywords)" >&2
done
