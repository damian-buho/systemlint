<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# apt sources

The `systemlint-apt` plugin and its three collectors read apt’s configuration
and cache, and the `apt` ruleset judges them. Nothing runs `apt`: every input
is a file, so a live host and `--root` give the same facts.

```sh
systemlint lint --tags apt
systemlint lint --root /mnt/image --tags apt
```

## Collectors

| Collector | Reads | Facts at |
| --- | --- | --- |
| `apt-lists` | `/var/lib/apt/lists/*_InRelease`, `*_Release` | `apt.lists.<path>` |
| `apt-sources` | `/etc/apt/sources.list`, `sources.list.d/*.sources` and `*.list` | `apt.sources.<path>:<line>` |
| `apt-installed` | `/var/lib/dpkg/status` | `apt.installed.<package>` |

`apt-sources` needs `os.release` and `apt.lists`, so it runs after both.

## Facts

A source is one deb822 paragraph or one `.list` line, keyed by its file and
the line it starts on, such as `/etc/apt/sources.list.d/docker.sources:5`.

| Fact | Meaning |
| --- | --- |
| `file`, `line`, `format` | where the source is written, `deb822` or `one-line` |
| `enabled` | `false` for `Enabled: no`; every shipped rule skips a disabled source |
| `types`, `uris`, `suites`, `components`, `architectures` | as written; a password in a URI reads `[redacted]` |
| `signed-by` | keyring paths or fingerprints, `(inline)` for an embedded key, empty when absent |
| `insecure-options` | which of `trusted`, `allow-insecure`, `allow-weak`, `allow-downgrade-to-insecure` are set |
| `options` | every other field or option, lowercase name to raw value |
| `codenames` | the Ubuntu or Debian releases its suites name, read inside the suite (`llvm-toolchain-questing-22`) or, for `stable`, from the cached Release |
| `stale-suites` | the suites whose release is not the host’s `VERSION_CODENAME`, `UBUNTU_CODENAME` or `DEBIAN_CODENAME`; absent when `os-release` names none |
| `suggested-suites` | each stale suite with its codename word replaced by the host’s, `llvm-toolchain-resolute-22` for `llvm-toolchain-questing-22` |
| `stale-uris` | the URIs naming the host’s distribution with another release, `xUbuntu_25.10/` or `ubuntu2204/` on 26.04; absent when `os-release` lacks `ID` or `VERSION_ID` |
| `suggested-uris` | each stale URI with the host’s `VERSION_ID` in its place, in the same form |
| `pinned-uris` | the URIs naming no release of the host’s distribution, for the version rule to review |
| `lists`, `fetched` | the cached Release files of its URI and suite pairs, and whether every pair has one |
| `expired-lists` | the cached Release files whose `Valid-Until` passed before the collection time |
| `release-age-days` | the age of the oldest `Date:` among them |
| `duplicates` | the other enabled sources listing one of its type, URI, suite and component |
| `key-conflicts` | the other enabled sources naming one of its URI and suite with different `Signed-By` |

A cached list carries `origin`, `label`, `suite`, `codename`, `version`,
`date`, `valid-until`, `age-days`, `expired` and `signed-inline`, the last
true for an `InRelease` file. A package carries `version`, `architecture` and
`status`, the last word of dpkg’s `Status:` (`installed`, `config-files`, …);
a package installed for several architectures is keyed `name:arch`.

`release-age-days` is no fetch time: apt records none, and a stable release’s
base suite keeps the `Date:` it shipped with. A Release is stale for apt only
once its `Valid-Until` passes.

## Rules

The ruleset applies where `os-release` names Debian or Ubuntu in `ID` or as a
word of `ID_LIKE`, so Linux Mint and Kali are judged too; on any other host each
rule answers `not-applicable`.

| Rule | Severity | Fails when an enabled source |
| --- | --- | --- |
| `apt/stale-suite` | error | names a suite of another Ubuntu or Debian release than the host’s; the fix names the host’s suite |
| `apt/stale-uri` | error | names another release of the host’s distribution in its URI; the fix names the replacement |
| `apt/versioned-uri` | warning | carries a version in its URI path, such as `/v1.34/` or `node_26.x`, that is no release of the host |
| `apt/signed-by` | warning | has no `Signed-By` |
| `apt/shared-keyring` | warning | names a keyring in `/etc/apt/trusted.gpg` or `trusted.gpg.d/` |
| `apt/https` | warning | fetches over `http://` or `ftp://` |
| `apt/insecure-options` | error | sets `trusted` or an `allow-*` option |
| `apt/duplicate` | warning | lists a repository another source lists |
| `apt/key-conflict` | error | shares a repository with a source of another `Signed-By` |
| `apt/stale-release` | error | has a cached Release past its `Valid-Until` |

A vendor that publishes one suite for every release, such as `xenial` for
all Ubuntu versions, fails `apt/stale-suite` by design; waive it:

```yaml
lint:
  waivers:
    - {rule: apt/stale-suite, subject: /etc/apt/sources.list.d/signal-desktop.sources:*, reason: Signal publishes xenial only, until: 2027-06-30}
```
