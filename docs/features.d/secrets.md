<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Secrets and injected code in every environment

- The environments of system files, unit files, running services, containers and images are searched for credentials, `LD_PRELOAD` code injection, turned-off TLS checks and an empty or relative entry in `PATH`. See [environments](how-to/env.md).
- Every value is replaced by a keyed hash before it reaches a plugin, the facts document or the report, so a scan never copies a secret anywhere.
- Plain-text passwords in `~/.netrc`, `.rhosts` trust that an installed rsh honours, and readable PostgreSQL, Squid and CUPS configurations are each reported where other users can reach them.
