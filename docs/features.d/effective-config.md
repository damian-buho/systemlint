<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Settings judged as the program applies them

- OpenSSH is asked for its own effective settings, once globally and once per account, so a `Match` block that turns password login back on for one user is found, with no configuration parser to fool. See [sshd](how-to/sshd.md).
- sudo grants and `Defaults` come from sudo itself, classic sudo and sudo-rs alike, with includes, aliases and groups settled, and a sudoers line sudo silently skips as broken is reported.
- PAM stacks, `login.defs`, password quality and resource limits are read in the order and precedence their libraries use, so the line that wins is the line judged. See [authentication](how-to/auth.md).
- Kernel settings and module blocklists come from `sysctl` and `modprobe` when they run, and from their drop-in directories in the same order otherwise, so a mounted image is judged like the booted host.
- A log file’s mode is judged against what recreates it: a log that logrotate will reopen with safe permissions is not a finding, its rotation rule is.
