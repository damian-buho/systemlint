<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Safe to run as root on a host you do not trust

- Every path is read inside the root being checked, so a symbolic link in an untrusted image can never make the scan read the host’s own files.
- Each plugin is a separate static program that only turns bytes the core read into facts; it opens no file, runs no command and touches no network. See [protocol](how-to/protocol.md).
- Plugins, collectors and rulesets load only from directories owned by root or by you and writable by no one else, and a collector written inline in a configuration file may not run a command.
- Nothing leaves the host unless `--network` asks for it.
