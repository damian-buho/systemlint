# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

export https_proxy="http://user:pw@proxy.example:3128"
export no_proxy=localhost
export NODE_OPTIONS="--require /opt/hook.js"
if [ -d /snap/bin ]; then
  PATH="$PATH:/snap/bin"
fi
export PYTHONPATH="lib"
