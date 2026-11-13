<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Kernel parameters, Docker, systemd units and ufw

Six collectors on `systemlint-formats` record service configuration as
facts. The `kernel`, `coredump`, `fs-protected`, `ip-routing` and `ip-flood`
rulesets judge `sysctl`, and `ufw` judges the two `ufw` collectors and the
state of `ufw.service`; no shipped rule reads the Docker or unit-file facts
yet.

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `sysctl` | `/usr/sbin/sysctl -a` on a live host, else `/etc/sysctl.conf` and the `sysctl.d` directories | `sysctl` | `sysctl` |
| `docker-daemon` | `/etc/docker/daemon.json` | `json` | `docker.daemon` |
| `systemd-units` | every `.service` file and drop-in in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` `systemd/system` | `ini` | `systemd.units.<path>` |
| `systemd-state` | every entry and `.wants`/`.requires` link in the unit directories, and `systemctl list-units --all` on a live host | `systemd` | `systemd.state.<unit>` |
| `ufw` | `/etc/ufw/ufw.conf` | `kv` | `ufw.conf` |
| `ufw-binary` | the `ufw` program in `/usr/local/*bin`, `/usr/*bin` and `/*bin` | `stat` | `ufw.binary.<path>` |

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

## systemd unit state

`systemd.state` keys each unit by its name, timers, sockets and the other unit
types included:

```yaml
systemd:
  state:
    ufw.service: {enabled: true, masked: false, active: active, sub: exited}
```

- `enabled`: a `.wants` or `.requires` directory in a unit directory links the
  unit, as `systemctl enable` makes it; an alias or a unit another one names in
  its own `Wants=` is not counted.
- `masked`: the unit’s file in the highest unit directory links to `/dev/null`
  or is empty, so an `/etc` file overrides a mask in `/run`. The directories,
  highest first: `/run/systemd/generator.early`, `/etc/systemd/system`,
  `/run/systemd/system`, `/run/systemd/generator`,
  `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`,
  `/lib/systemd/system`, `/run/systemd/generator.late`.
- `active` and `sub`: the `ACTIVE` and `SUB` columns of `systemctl
  list-units`, live only. A unit on disk that the manager has not loaded is
  `inactive` and `dead`, since systemd unloads only inactive units. A unit only
  the manager knows, such as a device, carries these two alone. Under `--root`,
  or where `systemctl` fails (a container with no manager, named in the
  collector’s diagnostics), no unit has them, and a rule on them answers
  `unknown`.

Both `enabled` and `masked` come from the files, so they read the same live and
under `--root`.

## ufw

`ufw.conf.ENABLED` is what `ufw enable` and `ufw disable` write, and what
ufw reads at boot to load its rules or not. `ufw.binary` is empty when no `ufw`
program exists, which makes the `ufw` ruleset `not-applicable`, whatever
installed it. Once `ENABLED=yes`, `ufw/service-masked` fails a masked
`ufw.service` and `ufw/service-disabled` one that nothing links, since systemd
then never starts ufw at boot; a host with no `ufw.service` unit has no check.
`ufw/service-failed` fails a `ufw.service` whose `active` state is `failed`,
which loaded no rules either; under `--root`, where no unit carries `active`,
it answers `skip` rather than `unknown`.
