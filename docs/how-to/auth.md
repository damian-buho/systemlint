<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Authentication configuration

The `auth-*` collectors read how logins are checked and limited: shadow’s
`/etc/login.defs`, the PAM service files, pam_limits, pam_pwquality and
`/etc/securetty`. The `login-defs`, `pam` and `pwquality` rulesets and one `coredump` rule
judge them.

```sh
systemlint check --tags auth
systemlint check --root /mnt/image --tags auth
```

## Collectors

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `auth-login-defs` | `/etc/login.defs` | `kv` | `auth.login-defs.<NAME>` |
| `auth-pam` | `/etc/pam.d/*` | `words` | `auth.pam.<path>` |
| `auth-limits` | `/etc/security/limits.conf`, `limits.d/*.conf` | `words` | `auth.limits.<path>` |
| `auth-pwquality` | `/etc/security/pwquality.conf.d/*.conf`, then `pwquality.conf` | `kv`, a bare option `true`, the last line winning | `auth.pwquality.<option>` |
| `auth-pwquality-module` | `pam_pwquality.so` under `/usr/lib` and `/lib` | `stat` | `auth.pwquality-module.<path>` |
| `auth-securetty` | `/etc/securetty` | `lines` | `auth.securetty.<path>` |
| `auth-faillock` | `/etc/security/faillock.conf` | `kv`, a bare option `true` | `auth.faillock.<option>` |
| `auth-pwhistory` | `/etc/security/pwhistory.conf` | `kv`, a bare option `true` | `auth.pwhistory.<option>` |

```yaml
auth:
  login-defs: {UMASK: "022", PASS_MAX_DAYS: "99999", USERGROUPS_ENAB: "yes"}
  pam:
    /etc/pam.d/common-auth:
      - {line: 17, type: auth, control: "success=1 default=ignore", module: pam_unix.so, arguments: [nullok]}
      - {line: 21, type: "@include", control: common-account, arguments: []}
  limits:
    /etc/security/limits.conf:
      - {domain: "*", type: hard, item: core, value: 0, line: 52}
```

- `auth-login-defs` reads `NAME value` lines as shadow does, through `kv`
  with `separator: whitespace` and `repeat: last`: the last line naming a key wins,
  and surrounding double quotes are dropped. A bare decimal number becomes a
  number (`PASS_MAX_DAYS 99999`); one with a leading zero stays text as
  written, since shadow reads numbers in C notation (`022` is octal).
- `pam` keeps each file’s entries in order as written, through `words`
  columns `type control module` and the rest as `arguments`, and does not
  follow `@include`, so a finding names the file that holds the line. A
  `[…]` control or argument is one word with its brackets dropped; `module`
  stays as written, a path or a filename; a leading `-` stays on the type;
  an `@include` line is `{type: "@include", control: <file>}`. The rules
  compare the type and control without case and the module by its
  filename, as Linux-PAM does, so `-Auth Sufficient /lib/security/pam_permit.so`
  fails like `auth sufficient pam_permit.so`. A `#` anywhere cuts the line,
  inside a word or brackets too, and a cut line never continues on the next,
  as Linux-PAM reads it (`inline-comments`).
- `limits` lists each file’s entries in order, as written: pam_limits gives a
  user’s own line precedence over a group’s and a group’s over `*`, so a rule
  judges every file’s list rather than one winning line, and compares `type`
  and `item` without case, as pam_limits does. A line without exactly four
  fields is left out with a diagnostic, as pam_limits ignores it.

## Rules

| Rule | Fails when |
| --- | --- |
| `login-defs/umask` | `UMASK` is unset (022) or leaves group write or any other-user bit open: 027 or stricter passes |
| `login-defs/umask-077` | `UMASK` is unset or leaves any group bit open, where the STIG asks 077 (*standard-only*) |
| `login-defs/encrypt-method` | `ENCRYPT_METHOD` is unset or not `SHA512` or `YESCRYPT`, compared with case as shadow does, which falls back to DES |
| `login-defs/encrypt-method-sha512` | `ENCRYPT_METHOD` is not `SHA512`, the STIG’s FIPS scheme (*standard-only*) |
| `login-defs/sha-rounds` | under `SHA256` or `SHA512`, `SHA_CRYPT_MIN_ROUNDS`, or a lone `SHA_CRYPT_MAX_ROUNDS`, is below the default 5000 |
| `login-defs/pass-max-days` | `PASS_MAX_DAYS` is unset or outside 1 to `password-max-days` (365, CIS; the STIG asks 60) (*standard-only*) |
| `login-defs/pass-rotation` | `PASS_MAX_DAYS` sets any expiry below 99999, as NIST SP 800-63B advises against |
| `login-defs/pass-min-days` | `PASS_MIN_DAYS` is unset or below `password-min-days` (1) (*standard-only*) |
| `login-defs/pass-warn-age` | `PASS_WARN_AGE` is unset or below `password-warn-days` (7) (*standard-only*) |
| `pam/permit-sufficient` | an auth line makes `pam_permit` `sufficient` or `success=done`, so it settles the stack |
| `pam/nullok` | an auth line passes `nullok` or `nullok_secure` to `pam_unix` |
| `pam/no-lockout` | a file checks passwords with `pam_unix` in its auth stack but never calls `pam_faillock` there |
| `pam/unix-remember` | a line in any file passes `remember=` to `pam_unix` |
| `pam/unix-hash` | the `common-password` password line of `pam_unix` names neither `sha512` nor `yescrypt`, leaving the scheme to `ENCRYPT_METHOD` (*standard-only*) |
| `pam/unix-enabled` | a `common-account`, `-auth`, `-password`, `-session` or `-session-noninteractive` file never calls `pam_unix` (*standard-only*) |
| `pam/pwquality-enabled` | `common-password` has no password line calling `pam_pwquality` (*standard-only*) |
| `pam/pwhistory-enabled` | `common-password` has no password line calling `pam_pwhistory` (*standard-only*) |
| `pam/su-unrestricted` | `/etc/pam.d/su` has no `required` or `requisite` auth line calling `pam_wheel` with `use_uid` and a `group=` (*standard-only*; whether that group is empty is not judged) |
| `pam/faillock-deny` | `faillock.conf` sets `deny` to 0 or above `faillock-deny` (5) (*standard-only*) |
| `pam/faillock-unlock-time` | `faillock.conf` leaves `unlock_time` unset (600) or between 1 and `faillock-unlock-time` (900) (*standard-only*) |
| `pam/faillock-root` | `faillock.conf` sets neither `even_deny_root` nor `root_unlock_time`, or a `root_unlock_time` below `faillock-root-unlock-time` (60) (*standard-only*) |
| `pam/pwhistory-remember` | `pwhistory.conf` leaves `remember` unset (10) or below `pwhistory-remember` (24) (*standard-only*) |
| `pam/pwhistory-root` | neither `pwhistory.conf` nor the `pam_pwhistory` line sets `enforce_for_root` (*standard-only*) |
| `pam/pwhistory-use-authtok` | the `pam_pwhistory` line of `common-password` lacks `use_authtok` (*standard-only*) |
| `pam/unix-use-authtok` | the `pam_unix` password line of `common-password` lacks `use_authtok` (*standard-only*) |
| `pam/pwquality-missing` | no `pam_pwquality.so` is on disk (*standard-only*) |
| `pwquality/minlen` | `minlen` is unset (8) or below `pwquality-minlen` (14, CIS) (*standard-only*) |
| `pwquality/minlen-single-factor` | `minlen` is unset or below `pwquality-single-factor-minlen` (15, NIST SP 800-63B-4 and the STIG) |
| `pwquality/credit` | a `dcredit`, `ucredit`, `lcredit` or `ocredit` above 0 counts characters of that class toward `minlen` |
| `pwquality/composition` | a credit below 0 or a `minclass` above 1 imposes a composition rule, as NIST SP 800-63B-4 advises against |
| `pwquality/stig-ucredit`, `stig-lcredit`, `stig-dcredit`, `stig-ocredit` | that credit is unset or above -1, where the STIG asks one character of the class (*standard-only*) |
| `pwquality/difok` | `difok` is unset (1) or below `pwquality-difok` (2, CIS) (*standard-only*) |
| `pwquality/stig-difok` | `difok` is unset or below `pwquality-stig-difok` (8) (*standard-only*) |
| `pwquality/maxrepeat` | `maxrepeat` is unset, 0 or above `pwquality-maxrepeat` (3) (*standard-only*) |
| `pwquality/maxsequence` | `maxsequence` is unset, 0 or above `pwquality-maxsequence` (3) (*standard-only*) |
| `pwquality/dictcheck` | the effective `dictcheck`, the module argument over the file, is 0 |
| `pwquality/enforcing` | the effective `enforcing`, the module argument over the file, is 0, so a weak password only draws a warning |
| `pwquality/root` | neither `pwquality.conf` nor the `pam_pwquality` line sets `enforce_for_root` (*standard-only*) |
| `coredump/no-hard-limit` | pam_limits has no `* hard core 0` (or `-`), or any hard core line with another value |

`login-defs` is not applicable without `/etc/login.defs` and `pam` without
`/etc/pam.d`. The `faillock` and `pwhistory` rules judge only a host whose
`common-auth` or `common-password` calls the module, and a file option only
while that line passes no argument of the same name, which overrides it; such
an argument is not judged. The `pwquality` rules judge only a host whose
`common-password` calls `pam_pwquality`, the same way, but for `dictcheck`
and `enforcing`, whose argument is judged in place of the file. `coredump/no-hard-limit` skips a host without PAM, which never
applies pam_limits. The `PASS_*` rules judge what new accounts get; the
`accounts` ruleset judges each existing one. `login-defs/pass-max-days` and
`login-defs/pass-rotation` contradict each other, so a run selecting both
reports one `Conflict`: keep the standard you follow with `--tags`.

## sudo

The `sudo` ruleset asks sudo itself, as root on a live host, what each account
may run, so includes, aliases, group grants and the implementation the host
runs (classic sudo or sudo-rs, which Ubuntu 26.04 installs as `sudo`) are
settled the way sudo settles them; under `--root` or unprivileged its rules
are `Not run`.

| Collector | Runs | Op | Facts at |
| --- | --- | --- | --- |
| `sudo-binary` | stats `sudo` in the usual `bin` directories | `stat` | `sudo.binary.<path>` |
| `sudo-grants` | `sudo --list --other-user=<account>` for every passwd account but uid 0, one reply each (`exec-from` `split`) | `match` | `sudo.grants.<account>.<line>` |
| `sudoers-check` | `visudo --check` | `exec` | `sudo.check` |

Each grant line sudo prints, such as `(ALL : ALL) NOPASSWD: ALL`, keys its
`runas` and `commands`; an account sudo allows nothing has none. The core
reads the output through a pipe, which sudo never wraps, so a long grant
stays one line.

| Rule | Fails when |
| --- | --- |
| `sudo/nopasswd` | a grant to the account carries the `NOPASSWD` tag, so a program running as it gets the rights unasked |
| `sudo/invalid-sudoers` | `visudo --check` exits non-zero: both implementations skip a line they cannot parse and run on without it |
| `sudo/not-installed` | no `sudo` program is on disk (CIS 5.2.1, *standard-only*) |

Every rule but `sudo/not-installed` skips a host without `sudo` on disk. The tag is matched
where sudo prints one, after the runas list or a comma and a blank; under
sudo-rs, which prints an escaped comma bare, a command argument written as
`x\, NOPASSWD: y` would read as a tag.

### sudo Defaults

The `sudo-defaults` ruleset judges the `Defaults` classic sudo applies to each
account, read from the same `sudo --list` output, so a `Defaults:alice` line
fails alice alone. sudo-rs prints no `Defaults`, so on it the ruleset is not
applicable.

| Collector | Runs | Op | Facts at |
| --- | --- | --- | --- |
| `sudo-version` | `sudo --version`; only classic sudo prints `Sudo version` | `match` | `sudo.version.<version>` |
| `sudo-defaults` | `sudo --list --other-user=<account>` for every passwd account but uid 0 | `kv` | `sudo.defaults.<account>.<setting>` |

`kv` reads the comma list under `Matching Defaults entries`: a flag is `true`,
`!flag` is `false`, a later entry of a key wins (`Defaults:dave !use_pty`
after a global `use_pty`), and a value is unescaped (`secure_path` reads
`/usr/sbin:/bin`). Runas and command bound `Defaults` (`Defaults>postgres`,
`Defaults!/usr/bin/id`) are not read. An account sudo allows nothing has no
`Defaults` and no check.

| Rule | Fails when | Tag |
| --- | --- | --- |
| `sudo-defaults/no-authenticate` | `!authenticate`: every grant runs without a password | CIS 5.2.5, STIG UBTU-24-300021 |
| `sudo-defaults/no-pty` | `!use_pty`: the command shares the caller’s terminal (on by default since sudo 1.9.14) | |
| `sudo-defaults/use-pty` | `use_pty` is not spelled out, *standard-only* | CIS 5.2.2 |
| `sudo-defaults/logfile` | no `logfile`, *standard-only* | CIS 5.2.3 |
| `sudo-defaults/timestamp-timeout` | `timestamp_timeout` is negative (never asks again) or above the `sudo-timestamp-timeout` var, 15, *standard-only* | CIS 5.2.6 |

An unset `timestamp_timeout` passes, the build default being 15 at most; a
fractional value (`2.5`) reads as text and passes unjudged.
