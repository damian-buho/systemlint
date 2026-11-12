<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# OpenSSH server

The `sshd` collector reads the OpenSSH server configuration, and the `ssh`
ruleset judges the settings that weaken authentication, forwarding or
cryptography. The rules give the same answer whether the configuration came
from `sshd -T` or from the files.

```sh
sudo systemlint lint --tags ssh
systemlint lint --root /mnt/image --tags ssh
```

## Collector

| Collector | Reads | Facts at |
| --- | --- | --- |
| `sshd` | `/etc/ssh/sshd_config`, every file in `/etc/ssh/sshd_config.d`, and `/usr/sbin/sshd -T` on a live host | `sshd` |

`systemlint-sshd` takes the global settings from `sshd -T`, the effective
configuration, when it exits 0, which needs root and the host keys. Otherwise,
in an unprivileged run, under `--root`, or when sshd refuses its config, it
reads the files the way sshd does:

- `Include` is expanded in place, each pattern’s files in name order, nested at
  most 16 deep; a relative pattern is under `/etc/ssh/`. An `Include` that
  matches nothing outside `/etc/ssh/sshd_config.d/` fails the collector, as the
  collector never read what it names.
- The FIRST value of a keyword wins, unlike most formats. `Port`,
  `ListenAddress`, `HostKey`, `HostCertificate`, `Subsystem`, `AcceptEnv` and
  the `Allow`/`Deny` `Users`/`Groups` lists accumulate instead.
- A keyword the files leave unset takes the compiled default, captured with
  `sshd -T -f /dev/null` from openssh-server 1:10.2p1-2ubuntu3.8 (Ubuntu
  26.04); `defaults` names that build. Another OpenSSH version may default
  differently.
- Values are shaped as `sshd -T` prints them: keywords and caseless values in
  lowercase, `without-password` as `prohibit-password`, times such as `1m30s`
  in seconds, a `+`, `-` or `^` algorithm list resolved against the default
  list, lists as arrays and whole numbers as numbers.

A keyword that `sshd -T` does not print, such as the obsolete `Protocol`, is
kept and reported as a diagnostic. `ListenAddress` is the one setting that can
differ between the two sources: sshd derives it from `Port`, and the files do
not.

## Facts

```yaml
sshd:
  source: files
  defaults: openssh-server 1:10.2p1-2ubuntu3.8
  global:
    /etc/ssh/sshd_config:
      logingracetime: 90
      port: [2222, 22]
      ciphers: [chacha20-poly1305@openssh.com, aes128-ctr]
  contexts:
    /etc/ssh/sshd_config:
      permitrootlogin: prohibit-password
    /etc/ssh/sshd_config:19:
      match: User backup Address 192.0.2.0/24
      passwordauthentication: "yes"
```

`source` is `effective` (from `sshd -T`), `files` or `none` when the host has
neither sshd nor its config, which gives no context and so no check. A failed
`sshd -T` is a diagnostic naming its exit code and first line of stderr.

`global` holds, under the main file’s path, the keywords a `Match` block
refuses (`Ciphers`, `LoginGraceTime`, `Port` …), which no connection can
change. `contexts` holds the keywords `Match` accepts: the global ones under
the main file’s path, and each `Match` block under the path and line that
opens it. `sshd -T` without a connection ignores `Match`, so a block always
comes from the files, merged over whichever global configuration won: every
such key a connection matching it would get, with its criteria under `match`.
A rule over `sshd.contexts.*` therefore judges the global settings and each
block; a global finding repeats on a block that leaves the setting alone,
since that connection gets it too, and the fix may go in either. A rule over
`sshd.global.*` judges the main file alone. A keyword `Match` refuses inside a
block is a diagnostic, since sshd will not start with it, and left out of the
block.

## Rules

The rules follow the controls of
[dev-sec ssh-baseline](https://github.com/dev-sec/ssh-baseline) (Apache-2.0),
whose IDs each rule carries as a `dev-sec-ssh-baseline:<id>` tag, so
`systemlint comply dev-sec-ssh-baseline` answers per control. The wording and
thresholds are systemlint’s own.

| Rule | Control | Severity | Fails when |
| --- | --- | --- | --- |
| `ssh/root-login` | sshd-06 | error | `PermitRootLogin` is not `no`, `prohibit-password` or `forced-commands-only` |
| `ssh/empty-passwords` | sshd-28 | error | `PermitEmptyPasswords` is not `no` |
| `ssh/ciphers` | sshd-01 | error | `Ciphers` offers a CBC, 3DES, RC4, Blowfish or CAST cipher |
| `ssh/kex` | sshd-02 | error | `KexAlgorithms` offers a SHA-1 or 1024-bit group exchange |
| `ssh/macs` | sshd-03 | warning | `MACs` offers MD5, SHA-1, a 96-bit or a 64-bit UMAC tag |
| `ssh/password-authentication` | sshd-27 | warning | `PasswordAuthentication` is not `no` |
| `ssh/keyboard-interactive` | sshd-29 | warning | `KbdInteractiveAuthentication` is not `no` |
| `ssh/hostbased` | sshd-25 | warning | `HostbasedAuthentication` is not `no` |
| `ssh/ignore-rhosts` | sshd-23 | warning | `IgnoreRhosts` is not `yes` |
| `ssh/strict-modes` | sshd-11 | warning | `StrictModes` is not `yes` |
| `ssh/user-environment` | sshd-17 | warning | `PermitUserEnvironment` is not `no` |
| `ssh/x11-forwarding` | sshd-42 | warning | `X11Forwarding` is not `no` |
| `ssh/gateway-ports` | sshd-41 | warning | `GatewayPorts` is not `no` |
| `ssh/tunnel` | sshd-38 | warning | `PermitTunnel` is not `no` |
| `ssh/max-auth-tries` | sshd-19 | info | `MaxAuthTries` is over 4 |
| `ssh/login-grace-time` | sshd-18 | info | `LoginGraceTime` is 0 (no limit) or over 60 seconds |
| `ssh/log-level` | sshd-13 | info | `LogLevel` is not `VERBOSE` |

Ubuntu’s shipped `sshd_config` sets `X11Forwarding yes` and keeps the
defaults `PasswordAuthentication yes`, `MaxAuthTries 6`, `LoginGraceTime 120`
and `LogLevel INFO`, so a stock server fails those rules until hardened. The
controls about ports, listen addresses, banners and forwarding of TCP or
agents depend on each site and have no rule; the permissions of the files
under `/etc/ssh` are the [files](files.md) ruleset’s.
