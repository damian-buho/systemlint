<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Local accounts and groups

The `accounts-*` collectors read `/etc/passwd`, `/etc/group` and
`/etc/shadow`, and the `accounts` ruleset judges the identities they define.
Only the local files are read, never NSS or LDAP, so a root directory reads
the same as a live host.

```sh
systemlint check --tags accounts
systemlint check --root /mnt/image --tags accounts
```

## Collectors

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `accounts-passwd` | `/etc/passwd`, `/etc/shells` | `passwd` with `shells: /etc/shells` | `accounts.passwd.<name>` |
| `accounts-group` | `/etc/group` | `words` on `:`, the password field dropped | `accounts.group.<name>` |
| `accounts-shadow` | `/etc/shadow`, root only | `shadow` | `accounts.shadow.<name>` |

```yaml
accounts:
  passwd:
    root: {password: shadow, uid: 0, gid: 0, gecos: root, home: /root, shell: /bin/bash, login-shell: true, line: 1, shadowed: []}
  group:
    sudo: {gid: 27, members: [alice], path: /etc/group, line: 28, shadowed: []}
  shadow:
    root: {password: locked, line: 1, shadowed: []}
```

- Each entry is keyed by its name, from the first line holding it, as glibc
  reads the files top-down. A later line repeating the name is never read; its
  line number goes to the first entry’s `shadowed`.
- `password` is a word, never the hash: `shadow` for `x`, which defers to
  `/etc/shadow`, `empty`, `locked` for a leading `!` or `*`, else `hash`. A
  group carries no `password`: `accounts-group` drops the field, whose hash
  belongs in `/etc/gshadow`.
- `login-shell` is true when the shell is empty or listed in `/etc/shells`,
  as getusershell(3) reads it, and without that file only for `/bin/sh` and
  `/bin/csh`; the `sshd` collector runs for these accounts and root.
- Empty lines and lines starting with `#` are skipped. A line with the wrong
  number of fields, or a uid that is not a number, is left out with a
  diagnostic naming its line; a group’s `gid` is a number when it is written
  as one.
- `accounts-shadow` is skipped in an unprivileged run, so its rule answers
  `unknown` there.

## Rules

| Rule | Fails when |
| --- | --- |
| `accounts/uid-zero` | an account other than `root` has uid 0 |
| `accounts/uid-unique` | two accounts share a uid other than 0, which `uid-zero` reports |
| `accounts/gid-unique` | two groups share a gid |
| `accounts/user-repeated` | a name appears on a later line of `/etc/passwd` |
| `accounts/group-repeated` | a name appears on a later line of `/etc/group` |
| `accounts/passwd-empty-password` | the password field in `/etc/passwd` is empty |
| `accounts/shadow-empty-password` | `/etc/passwd` defers to `/etc/shadow`, whose password is empty |

The two `unique` rules fail every account or group holding the shared value
and name the others in the message, see
[unique values](rules.md#unique-values).
