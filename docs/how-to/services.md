<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Kernel parameters, Docker and systemd units

Three collectors on `systemlint-formats` record service configuration as
facts. No shipped rule reads them yet: a ruleset in `lint.directories`
can.

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `sysctl` | `/usr/sbin/sysctl -a` on a live host, else `/etc/sysctl.conf` and the `sysctl.d` directories | `sysctl` | `sysctl` |
| `docker-daemon` | `/etc/docker/daemon.json` | `json` | `docker.daemon` |
| `systemd-units` | every `.service` file and drop-in in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` `systemd/system` | `ini` | `systemd.units.<path>` |

## sysctl

`sysctl.source` is `effective` when `sysctl -a` ran and exited 0, `files`
when the configuration was read instead (under `--root`, or with no
`sysctl` binary), or `none`. `sysctl.settings` nests each key by its dots, so
`net.ipv4.ip_forward` is the fact `sysctl.settings.net.ipv4.ip_forward`, and a
rule can bind every interface with `sysctl.settings.net.ipv4.conf.*.rp_filter`.
An interface name holding a dot shows it as `/` (`eth0/100`), as `sysctl`
prints it. A whole number becomes a number, anything else stays a string.

`sysctl -a` reads the running kernel rather than `/proc/sys` file by file:
an unprivileged run cannot read some keys (`kernel.cad_pid`, the
`stable_secret` of each interface), and a rule on one of them answers
`unknown`.

The files are applied as systemd-sysctl applies them: one file per name, from
the highest of `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`,
`/usr/lib/sysctl.d` and `/lib/sysctl.d`, in name order, then
`/etc/sysctl.conf`; a later setting wins. A key written with `/` separators
(`net/ipv4/ip_forward`) is read as dotted, a leading `-` is dropped, and a
glob key (`net.ipv4.conf.*.rp_filter`) stays as written, with `*` as its
segment.

## Docker daemon

`docker.daemon` is `/etc/docker/daemon.json` as it stands, so
`docker.daemon.icc` or `docker.daemon.userns-remap` are facts. With no file,
`docker.daemon` is empty, and a rule on one key answers `unknown`.

## systemd units

`systemd.units` keys each unit file and drop-in by its path, and each holds its
sections, every key a list of values in file order:

```yaml
systemd:
  units:
    /usr/lib/systemd/system/app.service:
      Service:
        EnvironmentFile: ["-/etc/default/app"]
        ExecStart: [/opt/app/bin/app]
```

A key that repeats keeps every value, an empty one included, since systemd
reads an empty value as a reset; a line ending in `\` continues on the next. A
masked unit, a symlink to `/dev/null`, is not a file and is skipped. The
merged environment of each unit is in [environment variables](env.md).
