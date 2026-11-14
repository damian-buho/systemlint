<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Kernel parameters, modules and audit rules, Docker, systemd units and ufw

Ten collectors record service configuration as facts, `systemd-units` on
`systemlint-systemd` and the rest on `systemlint-formats`. The `kernel`,
`coredump`, `fs-protected`, `ip-routing` and `ip-flood` rulesets judge
`sysctl`, `ufw` judges the two `ufw` collectors and the state of
`ufw.service`, and `services` judges the sandbox of each unit; no shipped rule
reads the Docker or kernel module facts yet.

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `sysctl` | `/usr/sbin/sysctl -a` on a live host, else `/etc/sysctl.conf` and the `sysctl.d` directories | `sysctl` | `sysctl` |
| `kernel-modules` | the `modprobe.d` directories, and `modules.order` and `modules.builtin` of every kernel in `/lib/modules` | `modprobe` | `kernel.modules.<module>` |
| `kernel-modules-loaded` | `/proc/modules` on a live host | `proc-modules` | `kernel.loaded.<module>` |
| `audit-rules` | `/etc/audit/rules.d/*.rules` | `audit-rules` | `audit.rules` |
| `audit-rules-loaded` | `/usr/sbin/auditctl -l` on a live host, as root | `audit-rules` | `audit.loaded` |
| `docker-daemon` | `/etc/docker/daemon.json` | `json` | `docker.daemon` |
| `systemd-units` | every `.service` file and drop-in in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` `systemd/system`, with its `stat` | `units` | `systemd.units.<unit>` |
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

## Kernel modules

`kernel.modules` keys each module by its name, `-` read as `_` as kmod does,
with what `modprobe` would do with it:

```yaml
kernel:
  modules:
    cramfs: {loadable: true, builtin: false, blacklist: false, install: /bin/false}
```

- `loadable`: some kernel in `/lib/modules` lists it in `modules.order`; a
  module only `depmod` added (DKMS, `updates/`) is not counted.
- `builtin`: some kernel lists it in `modules.builtin`, so no `modprobe.d`
  line can keep it out of that kernel.
- `blacklist`: a `blacklist` line names it, which stops loading by alias only;
  an explicit `modprobe` still loads it.
- `install`: the command of the first `install` line matching it, as an
  fnmatch(3) pattern, or `null`; `/bin/false` makes `modprobe` refuse it.

The files are read as kmod reads them: one file per name, from the highest of
`/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`,
`/usr/lib/modprobe.d` and `/lib/modprobe.d`, in name order; a trailing `\`
joins the next line. A module named only by a `modprobe.d` line is listed with
`loadable` and `builtin` false.

`kernel.loaded` keys each module in `/proc/modules` by name with `size` in
bytes, `instances`, `used-by` and `state` (`live`, `loading`, `unloading`).
It is a live fact, absent under `--root`.

## Kernel audit rules

`audit.rules` holds the rules augenrules loads from `/etc/audit/rules.d`, the
files in `ls -v` order; `audit.loaded` holds the set the kernel runs, as
`auditctl -l` lists it, which needs root. Both take one shape:

```yaml
audit:
  rules:
    watches:
      /etc/sudoers:
        - {action: always, perms: wa, filters: [], keys: [scope], source: /etc/audit/rules.d/50-scope.rules:1}
      /usr/bin/sudo:
        - {action: always, perms: x, filters: [auid>=1000, auid!=unset], keys: [privileged], source: /etc/audit/rules.d/50-scope.rules:4}
    syscalls:
      execve:
        - {action: always, arch: b64, filters: [euid!=uid, auid!=unset], keys: [user_emulation], source: /etc/audit/rules.d/50-scope.rules:2}
    lists:
      exclude:
        - {action: never, syscalls: [], filters: [msgtype=CWD], keys: [], source: /etc/audit/rules.d/50-scope.rules:3}
    control: {backlog: 8192, failure: 1, enabled: 2}
```

- `watches` keys each watched path, a trailing `/` dropped, with every rule on
  it in load order: a `-w` line, or an `exit` rule naming `path=` or `dir=`
  over every syscall. `perms` is the accesses it audits in `rwxa` order, all
  four when the rule names none.
- `syscalls` keys each syscall an `exit` rule names, `all` for a rule naming
  none, with every rule on it in load order, a `-A` rule first. `arch` is
  `b64` or `b32` for any name of those tables (`x86_64`, `i386`), `null`
  when the rule gives none, which auditctl reads as the table it was built for.
- `lists` keys every other list, `exclude`, `user`, `task`, `filesystem` or
  `io_uring`, with its rules in load order.
- `filters` are the `-F` and `-C` conditions as written, an ID field’s `-1`
  or `4294967295` read as `unset`; `key` and `arch` are taken out.
- `control` holds the last value of `-e` (`enabled`), `-b` (`backlog`),
  `-f` (`failure`), `-r` (`rate`) and `--backlog_wait_time`, and `true` for
  `-c`, `-i` and `--loginuid-immutable`.

A `-D` line clears every rule before it, as it does at load. A line the op
does not apply (`-d`, `-W`, `-R`, a malformed rule) is a diagnostic naming its
file and line, and is left out. `audit.loaded` is absent when `auditctl` is
not installed or exited non-zero, as without `CAP_AUDIT_CONTROL`.

## Docker daemon

`docker.daemon` is `/etc/docker/daemon.json` as it stands, so
`docker.daemon.icc` or `docker.daemon.userns-remap` are facts. With no file,
`docker.daemon` is empty, and a rule on one key answers `unknown`.

## systemd units

`systemd.units` keys each unit by its name, merged as systemd loads it: the
unit file from the highest directory, then its drop-ins by name, one per name
from the highest directory. A drop-in with no unit file loads nothing and is
left out.

```yaml
systemd:
  units:
    app.service:
      path: /etc/systemd/system/app.service
      file: /opt/app/app.service
      alias-of: null
      drop-ins: [/etc/systemd/system/app.service.d/override.conf]
      type: notify
      sections:
        Service:
          ExecStart: ["", /opt/app/bin/app --serve]
          Type: [notify]
      sandbox:
        user: root
        dynamic-user: false
        no-new-privileges: false
        protect-system: "no"
        capability-bounding-set: all
```

- `path`: the unit file found; `file`: where it leads when it is a link, a
  relative target read from its directory, else `path`.
- `alias-of`: the unit a link names when its filename differs, as
  `display-manager.service` names `sddm.service`, else `null`; the alias’s
  facts are its unit’s.
- `sections`: every key a list of values in reading order. An empty value
  drops every value before it and stays, so `["", /bin/b]` reads as systemd’s
  reset then `/bin/b`; a line ending in `\` continues on the next.
- `type`: a service’s last valid `Type=`, else the default
  [`systemd.service(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Type=)
  names: `dbus` with `BusName=`, `oneshot` with no `ExecStart=`, `exec` with a
  credential setting, else `simple`.
- `sandbox`: what a service runs with, from
  [`systemd.exec(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html):
    - `user`: the last `User=`, else `root`; with `DynamicUser=` and no `User=`,
      the unit name without `.service`, left out when that is no valid user
      name, since systemd then hashes it.
    - `dynamic-user`, `no-new-privileges`: booleans, both `false` by default;
      `DynamicUser=` turns on `NoNewPrivileges=`.
    - `protect-system`: `no`, `yes`, `full` or `strict`, `no` by default;
      `DynamicUser=` makes `no` read as `strict`.
    - `capability-bounding-set`: `all`, or the capabilities kept, sorted. The
      first line sets the set, a later one adds, a `~` line removes, an empty
      one empties it and a bare `~` restores every capability.

A value systemd would refuse (`NoNewPrivileges=maybe`) is ignored, as systemd
ignores it, and named in the collector’s diagnostics. A masked unit, a link to
`/dev/null`, is no file: the unit below it shows, so a rule guards on
`systemd.state.*.masked`. The merged environment of each unit is in
[environment variables](env.md).

### Service sandbox

`services/unconfined-root` fails a service that runs as root with every
capability, without `NoNewPrivileges=` and without `ProtectSystem=`: any bug in
it is the whole host. One confinement among the four passes it. It judges only
units written on the host, as a stock install’s units are the distribution’s:

- the unit is enabled and not masked
- its `file` is outside `/usr/lib`, `/lib` and `/run`, so a unit linked in
  from `/opt` counts, and it is no alias
- it is no `oneshot`, which runs once and exits
- it carries no `X-Snappy=` in `[Unit]`: snapd writes those units, and
  `snap run` confines them

The rule covers part of
[`systemd-analyze security`](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html),
whose exposure score it does not reproduce.

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
