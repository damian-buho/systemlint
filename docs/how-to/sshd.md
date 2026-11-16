<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# OpenSSH server

The `sshd` collector asks the OpenSSH server for its effective
configuration, globally and for each account, and the `ssh` ruleset judges the
settings that weaken authentication, forwarding or cryptography.

```sh
sudo systemlint check --tags ssh
```

## Collector

| Collector | Runs | Facts at |
| --- | --- | --- |
| `sshd` | `/usr/sbin/sshd -T`, then `/usr/sbin/sshd -T -C user=<account>,host=client.invalid,addr=192.0.2.1` for root and every account whose `login-shell` is true (see [accounts](accounts.md)) | `sshd` |

`sshd -T` reads the host keys, so the collector needs root, and it runs only
on a live host: an unprivileged run or one under `--root` prints every `ssh`
rule as `Not run`. sshd itself expands `Include`, applies its compiled defaults
and settles every `Match` block for the connection `-C` describes, so the
facts are what sshd would use, never a reading of the files. A command that
fails, as sshd does when it refuses its config, fails the collector naming its
exit code and first line of stderr; a host without sshd gives empty facts and
so no check.

A `Match` on `Address` or `Host` describes the client, not the account, so
every run names the same client: `client.invalid`, a name that never resolves
([RFC 6761](https://www.rfc-editor.org/rfc/rfc6761)), and `192.0.2.1`, an
address reserved for documentation
([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)). A block for `Address *`
or `0.0.0.0/0` applies; a block for one network the reserved address is
outside of does not, and its settings are not judged.

Values are shaped as `sshd -T` prints them: caseless values in lowercase,
`without-password` as `prohibit-password`, lists as arrays and whole numbers
as numbers.

## Facts

```yaml
sshd:
  global:
    /etc/ssh/sshd_config:
      logingracetime: 90
      port: [2222, 22]
      ciphers: [chacha20-poly1305@openssh.com, aes128-ctr]
      permitrootlogin: prohibit-password
  accounts:
    root:
      permitrootlogin: prohibit-password
    backup:
      passwordauthentication: "yes"
  settings:
    passwordauthentication:
      /etc/ssh/sshd_config: "no"
      backup: "yes"
    x11forwarding:
      /etc/ssh/sshd_config: "yes"
  client: {host: client.invalid, addr: 192.0.2.1}
```

`global` holds every keyword of plain `sshd -T`, under the main file’s path.
`accounts` holds, per account, the keywords a `Match` block accepts as that
account’s own `sshd -T -C` run printed them; a keyword `Match` refuses
(`Ciphers`, `LoginGraceTime`, `Port` …) lives under `global` only.
`settings` holds each keyword a `Match` block accepts, its global value under
the main file’s path plus every account whose own run settled it otherwise;
a keyword no run printed is an empty map. A rule over `sshd.settings.<keyword>.*`
so fails a global setting once, under the main file, and an account only where
a `Match` changed it; a rule over `sshd.global.*` names the main file.
`client` is the connection every account’s run named.

## Rules

The rules follow the controls of
[dev-sec ssh-baseline](https://github.com/dev-sec/ssh-baseline) (Apache-2.0),
whose IDs each rule carries as a `dev-sec-ssh-baseline:<id>` tag, so
`systemlint check --tags 'dev-sec-ssh-baseline:*'` runs them. The wording and
thresholds are systemlint’s own.

| Rule | Control | Severity | Fails when |
| --- | --- | --- | --- |
| `ssh/root-login` | sshd-06 | error | `PermitRootLogin` is not `no`, `prohibit-password` or `forced-commands-only` |
| `ssh/empty-passwords` | sshd-28 | error | `PermitEmptyPasswords` is not `no` |
| `ssh/ciphers` | sshd-01 | error | `Ciphers` offers a CBC, 3DES, RC4, Blowfish or CAST cipher |
| `ssh/kex` | sshd-02 | error | `KexAlgorithms` offers a SHA-1 or 1024-bit group exchange |
| `ssh/kex-post-quantum` | CIS 5.1.14 | warning | `KexAlgorithms` offers neither `mlkem768x25519-sha256` nor `sntrup761x25519-sha512`, in any position, since the client’s order decides |
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
| `ssh/max-auth-tries` | sshd-19 | info | `MaxAuthTries` is over `ssh-max-auth-tries` (4) |
| `ssh/login-grace-time` | sshd-18 | info | `LoginGraceTime` is 0 (no limit) or over `ssh-login-grace-time` (60) seconds |
| `ssh/log-level` | sshd-13 | info | `LogLevel` is not `VERBOSE` |

The two bounds are ruleset vars defaulting to dev-sec’s numbers, so a site
with its own standard sets them (`--var ssh-max-auth-tries=3`).

Ubuntu’s shipped `sshd_config` sets `X11Forwarding yes` and keeps the
defaults `PasswordAuthentication yes`, `MaxAuthTries 6`, `LoginGraceTime 120`
and `LogLevel INFO`, so a stock server fails those rules until hardened. The
controls about ports, listen addresses, banners and forwarding of TCP or
agents depend on each site and have no rule; the permissions of the files
under `/etc/ssh` are the [files](files.md) ruleset’s.

## Authorized keys

| Collector | Reads | Facts at |
| --- | --- | --- |
| `ssh-authorized-key-files` | `sshd` and `accounts.passwd` | `ssh.authorized-key-files.<account>` |
| `ssh-authorized-keys` | every file the previous facts name, root only | `ssh.authorized-keys.<account>` |

```yaml
ssh:
  authorized-key-files:
    alice: [/home/alice/.ssh/authorized_keys, /etc/ssh/keys/alice]
  authorized-keys:
    alice:
      files:
        /home/alice/.ssh/authorized_keys: {kind: file, mode: "0600", uid: 1000, gid: 1000, …}
      keys:
        /home/alice/.ssh/authorized_keys:3:
          type: ssh-rsa
          bits: 1024
          fingerprint: SHA256:k35ODz81KXzw/r4J3gBeEn0haj1GObKbZGcoaxLMRLM
          comment: old
          options: {restrict: true, from: ["192.0.2.0/24"]}
```

`authorized-key-files` lists, per account in `accounts.passwd`, every path sshd
reads its keys from, in sshd’s order, taken from the `AuthorizedKeysFile` its
own run printed, else, for an account with no run, from `sshd.global`, so a
`Match` for an account without a login shell is not seen. With neither, the
account has no entry. `%%`, `%h`, `%u`
and `%U` are expanded and a relative path lands below the home directory; a
path with another token is left out with a diagnostic, as sshd refuses it.
`none` names no file.

`authorized-keys` keeps, per account, the `stat` of each file read and each
key keyed `path:line`: its type, size in bits, SHA256 fingerprint as
`ssh-keygen -l` prints it, comment, and options, a flag as `true` and a
valued option as the list of every value it was given. `line-sha256` hashes
the line as written, so `systemlint fix` comments out only the line the lint
judged. The key itself never
leaves the plugin. A blank or comment line holds no key; a line sshd would
skip is a diagnostic naming it. An account none of whose files exist has no
entry.

| Rule | Fails when |
| --- | --- |
| `authorized-keys/rsa-size` | an RSA key of 1024 to 2047 bits, while `RequiredRSASize` is at its 1024 floor and `PubkeyAcceptedAlgorithms` takes RSA |
| `authorized-keys/dsa` | a DSA key, while `PubkeyAcceptedAlgorithms` still takes `ssh-dss`; OpenSSH 10 dropped DSA, so there the rule is a skip |

Both guards read `sshd.global`, so a `Match` block that changes either
setting for some accounts is not judged.
