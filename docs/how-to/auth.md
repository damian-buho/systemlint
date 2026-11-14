<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Authentication configuration

The `auth-*` collectors read how logins are checked and limited: shadow’s
`/etc/login.defs`, the PAM service files, pam_limits, pam_pwquality and
`/etc/securetty`. The `login-defs` and `pam` rulesets and one `coredump` rule
judge them.

```sh
systemlint check --tags auth
systemlint check --root /mnt/image --tags auth
```

## Collectors

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `auth-login-defs` | `/etc/login.defs` | `login-defs` | `auth.login-defs.<NAME>` |
| `auth-pam` | `/etc/pam.d/*` | `pam` | `auth.pam.<path>` |
| `auth-limits` | `/etc/security/limits.conf`, `limits.d/*.conf` | `words` | `auth.limits.<path>` |
| `auth-pwquality` | `/etc/security/pwquality.conf`, `pwquality.conf.d/*.conf` | `ini` | `auth.pwquality.<path>` |
| `auth-securetty` | `/etc/securetty` | `lines` | `auth.securetty.<path>` |

```yaml
auth:
  login-defs: {UMASK: "022", PASS_MAX_DAYS: "99999", USERGROUPS_ENAB: "yes"}
  pam:
    /etc/pam.d/common-auth:
      - {line: 17, type: auth, control: "[success=1 default=ignore]", module: pam_unix.so, arguments: [nullok], silent: false}
      - {line: 21, include: common-account}
  limits:
    /etc/security/limits.conf:
      - {domain: "*", type: hard, item: core, value: 0, line: 52}
```

- `login-defs` reads `NAME value` lines as shadow does: the last line naming
  a key wins, and surrounding double quotes are dropped. Every value stays a
  string, written as in the file, since shadow reads numbers in C notation
  (`022` is octal).
- `pam` keeps each file’s entries in order and does not follow `@include`, so
  a finding names the file that holds the line. `module` is the module’s file
  name with any directory dropped; a leading `-` on the type sets `silent`; a
  `[…]` control is lowercased with its spaces collapsed, and a `[…]` argument
  loses its brackets. A line of an unknown type is left out with a diagnostic,
  as Linux-PAM skips it.
- `limits` lists each file’s entries in order, as written: pam_limits gives a
  user’s own line precedence over a group’s and a group’s over `*`, so a rule
  judges every file’s list rather than one winning line, and compares `type`
  and `item` without case, as pam_limits does. A line without exactly four
  fields is left out with a diagnostic, as pam_limits ignores it.

## Rules

| Rule | Fails when |
| --- | --- |
| `login-defs/umask` | `UMASK` is unset (022) or leaves group write or any other-user bit open: 027 or stricter passes |
| `pam/permit-sufficient` | an auth line makes `pam_permit` `sufficient` or `success=done`, so it settles the stack |
| `pam/nullok` | an auth line passes `nullok` or `nullok_secure` to `pam_unix` |
| `pam/no-lockout` | a file checks passwords with `pam_unix` in its auth stack but never calls `pam_faillock` there |
| `coredump/no-hard-limit` | pam_limits has no `* hard core 0` (or `-`), or any hard core line with another value |

`login-defs` is not applicable without `/etc/login.defs` and `pam` without
`/etc/pam.d`; `coredump/no-hard-limit` skips a host without PAM, which never
applies pam_limits. Password expiry (`PASS_MAX_DAYS`) has no rule here: NIST
SP 800-63B advises against forced rotation, so it belongs to a standard that
demands it, tagged with that standard’s control.
