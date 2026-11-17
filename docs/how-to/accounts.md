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
| `accounts-shadow` | `/etc/shadow`, `/etc/passwd`, root only | `shadow` with `passwd: /etc/passwd` | `accounts.shadow.<name>` |
| `accounts-shells` | `/etc/shells` | `lines` | `accounts.shells./etc/shells` |

```yaml
accounts:
  passwd:
    root: {password: shadow, uid: 0, gid: 0, gecos: root, home: /root, shell: /bin/bash, login-shell: true, line: 1, shadowed: []}
  group:
    sudo: {gid: 27, members: [alice], path: /etc/group, line: 28, shadowed: []}
  shadow:
    root: {password: locked, last-change: 20000, min-days: 0, max-days: 99999, warn-days: 7, inactive-days: null, expire-day: null, line: 1, shadowed: [], in-passwd: true}
    ghost: {password: missing, in-passwd: true}
```

- Each entry is keyed by its name, from the first line holding it, as glibc
  reads the files top-down. A later line repeating the name is never read; its
  line number goes to the first entry’s `shadowed`.
- `password` is a word, never the hash: `shadow` for `x`, which defers to
  `/etc/shadow`, `empty`, `locked` for a leading `!` or `*`, else `hash`. A
  group carries no `password`: `accounts-group` drops the field, whose hash
  belongs in `/etc/gshadow`.
- A shadow entry’s ageing fields are numbers of days, as shadow(5) writes
  them, and `null` where the field is empty, which turns that limit off:
  `last-change` and `expire-day` count days since 1970-01-01, `min-days`,
  `max-days`, `warn-days` and `inactive-days` are lengths.
- With `passwd`, an account that `/etc/passwd` defers to shadow with `x` but
  that has no `/etc/shadow` line gets `{password: missing}`, the entry pwck(8)
  reports as broken. No account is missing when no shadow file was read.
- With `passwd`, every shadow entry carries `in-passwd`, false for a line no
  account holds (an installer’s leftover), which no login can use, so the rules
  joining it to `/etc/passwd` skip it. It is absent when no passwd file was read.
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
| `accounts/passwd-hash` | `/etc/passwd`, which every user can read, holds the password hash |
| `accounts/shadow-empty-password` | `/etc/passwd` defers to `/etc/shadow`, whose password is empty |
| `accounts/shadow-missing` | `/etc/passwd` defers to `/etc/shadow`, which has no line for the account |
| `accounts/gid-zero` | an account other than `root`, `sync`, `shutdown`, `halt` and `operator` has gid 0 as its primary group |
| `accounts/shadow-group-members` | group `shadow` lists members, who can read every hash |
| `accounts/shadow-group-primary` | an account’s primary gid is 42, while group `shadow` holds gid 42 as Debian’s `base-passwd` fixes it; elsewhere it answers `skip` |
| `accounts/nologin-shell` | `/etc/shells` lists `nologin` on a line that is no comment, so it counts as a valid shell |

The rules only CIS Ubuntu 26.04 asks for carry `'!default'` and run with
`--tags 'cis-ubuntu-26.04:*'` or `--tags accounts`. Each ageing rule judges an
account with a usable password hash, and an empty field fails it. Each bound
is a ruleset var whose default is CIS’s number, so a site with its own
standard sets it, daily rotation included (`--var password-max-days=1`, or
`check.vars` in the config):

| Rule | CIS | Fails when (var, default) |
| --- | --- | --- |
| `accounts/password-max-days` | 5.4.1.1 | `max-days` is below 1 or above `password-max-days` (365) |
| `accounts/password-min-days` | 5.4.1.2 | `min-days` is below `password-min-days` (1) |
| `accounts/password-warn-days` | 5.4.1.3 | `warn-days` is below `password-warn-days` (7) |
| `accounts/password-inactive-days` | 5.4.1.5 | `inactive-days` is above `password-inactive-days` (45) |
| `accounts/useradd-inactive` | 5.4.1.5 | `INACTIVE` in `/etc/default/useradd`, read by `auth-useradd` through `kv`, is unset, negative or above `password-inactive-days` (45) |
| `accounts/stig-useradd-inactive` | STIG 200260 | `INACTIVE` is unset, negative or above `stig-password-inactive-days` (35) |
| `accounts/stig-root-unlocked` | STIG 400110 | root’s shadow password is not `locked` |
| `accounts/grpck` | Lynis AUTH-9216 | `grpck --read-only`, run as root by `accounts-grpck`, exits non-zero (in `default`) |
| `accounts/system-login-shell` | 5.4.2.7 | an account other than root, halt, sync, shutdown and nfsnobody, below `uid-min` (1000) or uid 65534, has a login shell |
| `accounts/no-shell-unlocked` | 5.4.2.8 | an account other than root has no login shell, and its shadow password is a hash or empty |

NIST SP 800-63B-4 §3.1.1.2 forbids forced periodic password changes, so
`accounts/password-rotation` (tag `nist-sp-800-63b-4:3.1.1.2`, in `default`)
fails an account with a usable hash whose `max-days` is set below 99999,
shadow’s “never”; an empty field passes. It and `accounts/password-max-days`
name each other in `conflicts`: a run selecting both answers `conflict` on
both and fails on neither, and `--tags '!accounts/password-max-days'` or
`'!accounts/password-rotation'` keeps the standard you follow, see
[conflicting standards](rule-book.md#conflicting-standards).

The two `unique` rules fail every account or group holding the shared value
and name the others in the message, see
[unique values](rules.md#unique-values).
