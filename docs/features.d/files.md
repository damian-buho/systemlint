<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# File permissions that matter, not every bit

- Files that grant root, hold password hashes or host keys, or sit in the `PATH` are kept to root, and every directory above a set-user-ID program is checked too, since a writable parent is as good as a writable program. See [files](how-to/files.md).
- Each user’s home, `~/.ssh` and authorized keys are checked from the outside: a world-writable key file, a short RSA or a DSA key, a home others can enter.
- Mounts that honour set-user-ID bits, device files or programs where every user can write are named, both in `/etc/fstab` and as they are mounted now.
- Accounts are checked across `passwd`, `shadow` and `group` together: a second root, a repeated name or ID, an account with no password.
