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
echo "capturing sshd -T and $# accounts in ${image}" >&2
# shellcheck disable=SC2016 # the script expands inside the container
timeout --kill-after=30s 900s docker run --rm --cpus 2 --memory 1g --user 0 --env DEBIAN_FRONTEND=noninteractive \
  --env "OWNER=$(id --user):$(id --group)" \
  --mount "type=bind,source=${fixture},target=/fixture" "${image}" bash -c '
  set -e
  apt-get update --quiet=2 >/dev/null
  apt-get install --yes --quiet=2 --no-install-recommends openssh-server >/dev/null
  cp --recursive /fixture/etc/ssh/. /etc/ssh/
  ssh-keygen -A >/dev/null
  mkdir --parents /run/sshd
  /usr/sbin/sshd -T > /fixture/sshd-T.txt
  for account in "$@"; do
    /usr/sbin/sshd -T -C "user=${account},host=client.invalid,addr=192.0.2.1" > "/fixture/accounts/${account}.txt"
    echo "${account}: $(wc --lines < "/fixture/accounts/${account}.txt") keywords" >&2
  done
  chown --recursive "${OWNER}" /fixture/sshd-T.txt /fixture/accounts' sshd "$@"
