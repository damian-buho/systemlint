#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Usage: capture-sshd-fixture.sh IMAGE ACCOUNT… (ubuntu:26.04 root backup alice): writes fixtures/sshd `sshd -T` and one `sshd -T -C` per account.

set -euo pipefail

fixture="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../fixtures/sshd" && pwd)"
[[ $# -gt 1 ]] || { echo "usage: $0 IMAGE ACCOUNT…" >&2; exit 2; }
image="$1"
shift
mkdir --parents "${fixture}/accounts"

capture() {
  echo "capturing sshd $* in ${image}" >&2
  timeout --kill-after=30s 900s docker run --rm --cpus 2 --memory 1g --env DEBIAN_FRONTEND=noninteractive \
    --mount "type=bind,source=${fixture}/etc/ssh,target=/fixture,readonly" "${image}" bash -c '
    set -e
    apt-get update --quiet=2 >/dev/null
    apt-get install --yes --quiet=2 --no-install-recommends openssh-server >/dev/null
    cp --recursive /fixture/. /etc/ssh/
    ssh-keygen -A >/dev/null
    mkdir --parents /run/sshd
    /usr/sbin/sshd "$@"' sshd "$@"
}

capture -T > "${fixture}/sshd-T.txt"
for account in "$@"; do
  capture -T -C "user=${account},host=client.invalid,addr=192.0.2.1" > "${fixture}/accounts/${account}.txt"
  echo "${account}: $(wc --lines < "${fixture}/accounts/${account}.txt") keywords" >&2
done
