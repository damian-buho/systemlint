<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# apt sources

The `systemlint-apt` plugin and its three collectors read apt’s configuration
and cache, and the `apt` ruleset judges them; every input is a file, so a live
host and `--root` give the same facts. Two more ask apt itself, on a live host
only: for the pending upgrades, and for the effective value of the settings the
rules judge.

```sh
systemlint check --tags apt
systemlint check --root /mnt/image --tags apt
```

## Collectors

| Collector | Reads | Facts at |
| --- | --- | --- |
| `apt-lists` | `/var/lib/apt/lists/*_InRelease`, `*_Release` | `apt.lists.<path>` |
| `apt-sources` | `/etc/apt/sources.list`, `sources.list.d/*.sources` and `*.list` | `apt.sources.<path>:<line>` |
| `apt-installed` | `/var/lib/dpkg/status` | `apt.installed.<package>` |
| `apt-upgrades` | `apt-get --simulate dist-upgrade`, live only, `formats match` | `apt.upgrades.<package>` |
| `apt-config` | `apt-config dump` of the keys the rules judge, live only, `formats kv` | `apt.config.<key>` |
| `unattended-upgrades-binary` | `unattended-upgrade` in the usual `bin` directories, `formats stat` | `unattended-upgrades.binary.<path>` |

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
| `line-sha256` | a one-line source’s SHA-256, which `disable-line` checks before commenting it out; absent on a deb822 paragraph and on a line whose URI holds a user or token |
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
| `covered-by` | the kept sources listing every type, URI, suite and component it lists, when it is not kept: walking from the last source up, one is dropped when the sources still kept list all of it, so the first of two equal sources stays and a subset goes before its superset |
| `overlaps` | the other kept sources sharing one of its targets, when it is kept |
| `key-conflicts` | the other enabled sources naming one of its URI and suite with different `Signed-By` |

A cached list carries `origin`, `label`, `suite`, `codename`, `version`,
`date`, `valid-until`, `age-days`, `expired` and `signed-inline`, the last
true for an `InRelease` file. A package carries `version`, `architecture` and
`status`, the last word of dpkg’s `Status:` (`installed`, `config-files`, …);
a package installed for several architectures is keyed `name:arch`.

The upgrades are apt’s `Inst <package> [<installed>] (<candidate> <Label>:<Version>/<Archive>, … [<arch>])`
lines, as it prints them after pins, holds and phased updates, matched by the
collector’s `with.pattern`: each package carries `installed` (absent for a
package the upgrade newly pulls in), `candidate`, `origins` and `arch`, so a
rule matches a pending security fix with `pattern` on `origins` ending
`-security`. An `apt-get` that exits non-zero fails the collector, so its
rules are `unknown`, never a clean pass. apt resolves against the cached
lists, so the answer is as fresh as the last `apt update`.

`apt.config` holds each judged key apt has a value for, spelled as apt
first read it (apt compares keys without case, so the rules do too), each value
as text: apt settles `apt.conf`, `apt.conf.d` in name order and its compiled
defaults itself, and an unset key is absent. The collector names its keys, so
nothing else of apt’s configuration, such as a proxy URL with a password in
it, enters the facts. A rule reads a boolean as apt’s `StringToBool` does
(`1`, `yes`, `true`, `with`, `on`, `enable` without case, a number through
`strtol`), and any other value as apt’s default for the key.

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
| `apt/duplicate` | warning | lists nothing the kept sources do not list (`covered-by`); a one-line source carries the `disable-line: apt-list` remedy, which never leaves its target unlisted |
| `apt/overlap` | warning | shares a suite and component with another kept source while listing one of its own (`overlaps`) |
| `apt/key-conflict` | error | shares a repository with a source of another `Signed-By` |
| `apt/stale-release` | error | has a cached Release past its `Valid-Until` |

`apt/security-suite` (warning) judges the sources together: it fails when no
enabled `deb` source names a suite ending in `-security`, so the release’s
security fixes never arrive. It judges Debian and Ubuntu releases that carry a
`VERSION_ID`, and derivatives whose `os-release` names their base in
`UBUNTU_CODENAME` or `DEBIAN_CODENAME`, such as Linux Mint, Pop!_OS and LMDE;
testing, unstable, rolling derivatives such as Kali, and derivatives that
publish no security suite, such as Raspbian, answer `skip`.

The rules over `apt.config` judge what apt does with its settings, so an
unset key passes where apt’s default is safe:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `apt/allow-unauthenticated` | error | `APT::Get::AllowUnauthenticated` is on |
| `apt/allow-insecure-repositories` | error | `Acquire::AllowInsecureRepositories` is on |
| `apt/allow-weak-repositories` | error | `Acquire::AllowWeakRepositories` is on |
| `apt/allow-downgrade-to-insecure` | error | `Acquire::AllowDowngradeToInsecureRepositories` is on |
| `apt/check-date-off` | warning | `Acquire::Check-Date` is off |
| `apt/weak-dependencies` | info | `APT::Install-Recommends` is not off, or `APT::Install-Suggests` is on; CIS only, out of `default` |

The `unattended-upgrades` ruleset applies where `unattended-upgrade` is on
disk. `unattended-upgrades/off` (warning) fails when
`APT::Periodic::Unattended-Upgrade` is `0` or unset, as `apt.systemd.daily`
reads it; `unattended-upgrades/stale-lists` (warning) fails when it runs while
`APT::Periodic::Update-Package-Lists` is `0` or unset, so it upgrades against
old lists; `unattended-upgrades/keeps-replaced` (info, STIG only, out of
`default`) fails unless both `Unattended-Upgrade::Remove-Unused-Dependencies`
and `Remove-Unused-Kernel-Packages` are on. Whether `apt-daily.timer` and
`apt-daily-upgrade.timer` fire is not judged yet.

A vendor that publishes one suite for every release, such as `xenial` for
all Ubuntu versions, fails `apt/stale-suite` by design; waive it:

```yaml
check:
  waivers:
    - {rule: apt/stale-suite, subject: /etc/apt/sources.list.d/signal-desktop.sources:*, reason: Signal publishes xenial only, until: 2027-06-30}
```
