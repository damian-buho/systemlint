<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Kernel parameters, modules and audit rules, Docker, systemd units, plain-text servers, running services, listening sockets, ufw and nftables

Eighteen collectors record service configuration as facts, `systemd-units` on
`systemlint-systemd`, `nftables` on `systemlint-firewall`, `processes-services`
and `ports-listening` on `systemlint-proc` and the rest on `systemlint-formats`. The `kernel`,
`coredump`, `fs-protected`, `ip-routing` and `ip-flood` rulesets judge
`sysctl`, `ufw` judges the two `ufw` collectors and the state of
`ufw.service`, `nftables` judges the loaded nftables ruleset and the state of
`nftables.service`, `restart` judges the code each running service holds, `services` judges the sandbox of each unit, and
`kernel-modules` judges the module facts, and `audit` the audit rules; no shipped rule reads the Docker
facts yet.

| Collector | Reads | Op | Facts at |
| --- | --- | --- | --- |
| `sysctl` | `/usr/sbin/sysctl -a` on a live host, else the `sysctl.d` directories and `/etc/sysctl.conf` | `kv` | `sysctl.settings` |
| `sysctl-apparmor` | `/usr/sbin/sysctl --all --pattern '^kernel\.apparmor_restrict_unprivileged_'` on a live host, as root | `kv` | `sysctl.apparmor` |
| `kernel-modules-shipped` | `modules.order` of every kernel in `/lib/modules` | `match` | `kernel.shipped.<module>` |
| `kernel-modules-builtin` | `modules.builtin` of every kernel in `/lib/modules` | `match` | `kernel.builtin.<module>` |
| `kernel-modules-blacklist` | `/usr/sbin/modprobe --showconfig` on a live host, else the `modprobe.d` files | `words` | `kernel.blacklist.<module>` |
| `kernel-modules-install` | `/usr/sbin/modprobe --showconfig` on a live host, else the `modprobe.d` files | `words` | `kernel.install.<module>` |
| `kernel-modules-loaded` | `/proc/modules` on a live host | `words` | `kernel.loaded.<module>` |
| `audit-rules` | `/etc/audit/rules.d/*.rules` | `options` | `audit.rules.<file>` |
| `audit-rules-loaded` | `/usr/sbin/auditctl -l` on a live host, as root | `options` | `audit.loaded./usr/sbin/auditctl` |
| `auditd-binary` | `auditd` in `/usr/local/sbin`, `/usr/sbin`, `/sbin` and their `bin` siblings | `stat` | `auditd.binary` |
| `docker-daemon` | `/etc/docker/daemon.json` | `json` | `docker.daemon` |
| `systemd-units` | every `.service` file and drop-in in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` `systemd/system`, with its `stat` | `units` | `systemd.units.<unit>` |
| `systemd-state` | every entry and `.wants`/`.requires` link in the unit directories, and `systemctl list-units --all --output=json` on a live host | `systemd` | `systemd.state.<unit>` |
| `ufw` | `/etc/ufw/ufw.conf` | `kv` | `ufw.conf` |
| `ufw-binary` | the `ufw` program in `/usr/local/*bin`, `/usr/*bin` and `/*bin` | `stat` | `ufw.binary.<path>` |
| `nftables` | `/usr/sbin/nft --json list ruleset` on a live host, as root | `nftables` | `nftables.hooks.<family>.<hook>` |
| `processes-services` | `/proc/*/cgroup` and `/proc/*/maps` on a live host, as root | `services` | `processes.services.<unit>` |

## sysctl

`sysctl.settings` holds what `sysctl -a` printed when it ran and exited 0
(`read.prefer: exec`), else the configuration (under `--root`, or with no
`sysctl` binary or a failing one). It nests each key by its dots, so
`net.ipv4.ip_forward` is the fact `sysctl.settings.net.ipv4.ip_forward`, and a
rule can bind every interface with `sysctl.settings.net.ipv4.conf.*.rp_filter`.
An interface name holding a dot shows it as `/` (`eth0/100`), as `sysctl`
prints it. A whole number becomes a number, anything else stays a string.

`sysctl -a` reads the running kernel rather than `/proc/sys` file by file:
an unprivileged run cannot read some keys (`kernel.cad_pid`, the
`stable_secret` of each interface), and a rule on one of them answers
`unknown`.

The AppArmor keys are root-only, so `sysctl-apparmor` reads them alone as a
`privileged` collector: unprivileged, `kernel/apparmor-unconfined` is `Not
run`, and a kernel without AppArmor’s user namespace restriction skips it.

The files are applied as systemd-sysctl applies them (`read.order: drop-in`): one file per name, from
the highest of `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`,
`/usr/lib/sysctl.d` and `/lib/sysctl.d`, in name order, then
`/etc/sysctl.conf`; a later setting wins. A key written with `/` separators
(`net/ipv4/ip_forward`) is read as dotted, a leading `-` is dropped, and a
glob key (`net.ipv4.conf.*.rp_filter`) stays as written, with `*` as its
segment.

## Kernel modules

Five collectors compose kmod’s own answers with `formats words`, or `formats
match` for a module path’s base name, one collection each, every module keyed
by its name:

```yaml
kernel:
  shipped: {cramfs: {}, usb-storage: {}}
  builtin: {unix: {}}
  blacklist: {floppy: {path: /usr/sbin/modprobe, line: 12, shadowed: []}}
  install: {cramfs: {command: [/bin/false], path: /usr/sbin/modprobe, line: 40, shadowed: []}}
  loaded: {ext4: {size: 1105920, instances: 1, state: Live, path: /proc/modules, line: 3, shadowed: []}}
```

- `shipped`: some kernel in `/lib/modules` lists it in `modules.order`; a
  module only `depmod` added (DKMS, `updates/`) is not counted. The name keeps
  the file’s spelling, so `usb-storage` keeps its `-`.
- `builtin`: some kernel lists it in `modules.builtin`, so no `modprobe.d`
  line can keep it out of that kernel; spelled as in the file too.
- `blacklist`: a `blacklist` line names it, which stops loading by alias only;
  an explicit `modprobe` still loads it.
- `install`: the `command` words of its first `install` line, which kmod runs
  instead of loading it; `/bin/false` makes `modprobe` refuse it.
- `loaded`: each module in `/proc/modules` with `size` in bytes, `instances`
  as numbers and `state` (`Live`, `Loading`, `Unloading`).

`blacklist` and `install` come from `modprobe --showconfig`, kmod’s merged view
of every `modprobe.d` file in the order it reads them. Under `--root`, or when
`modprobe` fails or is absent, they come from the `.conf` files in
`/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` `modprobe.d` instead,
in kmod’s order: a name in `/etc` hides the same name below it, then name
order. Either way a name is spelled as kmod spells it, `-` read as `_`
(`key-underscores`, `usb_storage`); a rule on `usb-storage` guards on
`shipped` under one spelling and judges `install` under the other. `loaded` is a live fact, absent under `--root`.

The `kernel-modules` ruleset gives each module CIS Ubuntu 26.04 lists three
rules, all tagged with its control:

- `kernel-modules/<module>` fails a shipped module whose `install` line is
  missing or runs anything but `/bin/false` or `/bin/true`, with or without
  `/usr`; it skips a module no kernel ships.
- `kernel-modules/<module>-loaded` fails a module in `/proc/modules`; it skips
  under `--root`.
- `kernel-modules/<module>-blacklist` fails a shipped module with no
  `blacklist` line. A blacklist stops loading by alias only, so this rule never
  runs by default.

By default the first two run for cramfs, freevxfs, hfs, hfsplus, jffs2, udf,
dccp, rds, sctp and tipc. For firewire-core, atm and can only `-loaded` runs,
since a host may need them. overlay, squashfs (Docker, snaps) and usb-storage
run only when their tag is named, as in `--tags 'cis-ubuntu-26.04:*'`.
`kernel-modules/builtin` fails a module from the default list that some kernel
builds in, since no `modprobe.d` line can keep it out of that kernel; CIS
counts that as passing, so it carries no CIS tag.

## CPU vulnerabilities

The `cpu-vulnerabilities` collector (`live`) reads each file under
`/sys/devices/system/cpu/vulnerabilities/` into `cpu.vulnerabilities.<path>`,
its lines as the running kernel reports them. The `cpu` ruleset judges them:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `cpu/vulnerable` | warning | a line starts with `Vulnerable`, so the flaw is unmitigated on this CPU, microcode and kernel |

`Not affected`, `Unknown` and any `Mitigation`, even one noting `SMT
vulnerable`, pass. Under `--root` the rule is `Not run`, since `/sys` there
is not the running kernel’s.

## Pending reboot

The `reboot-required` collector (`live`) stats `/run/reboot-required` into
`reboot.required.<path>`, the flag Debian and Ubuntu package hooks write once
an installed kernel or core library update needs a reboot to run. The `reboot`
ruleset judges it:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `reboot/required` | warning | `/run/reboot-required` exists |

A host without the file, or whose packages never write it, has no check.
Under `--root` the rule is `Not run`, since `/run` there is not the running
host’s. A service still running replaced code is `restart/replaced-code`.

## Kernel audit rules

`audit.rules` holds the rules of each file augenrules loads from
`/etc/audit/rules.d`; `audit.loaded` holds the rules `auditctl -l` prints for
the set the kernel runs, which needs root. Both are `formats options`: each
source keys its lines in order, each line a record of its flags, `-a` and
`-S` split on `,`:

```yaml
audit:
  rules:
    /etc/audit/rules.d/50-scope.rules:
      - {"-w": [/etc/sudoers], "-p": [wa], "-k": [scope], args: [], line: 1}
      - {"-e": [2], args: [], line: 2}
  loaded:
    /usr/sbin/auditctl:
      - {"-a": [always, exit], "-F": [arch=b64, auid!=-1, key=user_emulation], "-S": [execve], "-C": [uid!=euid], args: [], line: 2}
```

A rule says that some source holds a line with the flags it needs, in any
order:

```yaml
expect:
  not:
    additionalProperties:
      not:
        contains:
          required: ["-w", "-p"]
          properties:
            "-w": {contains: {const: /etc/sudoers}}
            "-p": {contains: {allOf: [{pattern: w}, {pattern: a}]}}
          anyOf:
            - required: ["-k"]
            - properties: {"-F": {contains: {pattern: '^key='}}}
              required: ["-F"]
```

`auditctl -l` prints each rule in one normal form (`-p` in `rwxa` order,
`auid!=-1` for `unset`, `-F key=`), while the files keep what was written, so
a rule over `audit.rules` accepts every spelling auditctl does. The lines
are not applied: a `-D` does not clear the lines before it and a `never` rule
does not shadow a later `always`. `audit.loaded` is absent when `auditctl` is
not installed, and the collector fails when it exits non-zero.

The `audit` ruleset applies once `auditd` is on disk and carries no `default`
tag, since only a standard asks for it: `--tags audit` or
`--tags 'cis-ubuntu-26.04:*'` runs it. It gives each CIS Ubuntu 26.04 control
from 6.2.3.1 to 6.2.3.35 one rule, but 6.2.3.3 (the sudo log file is set in
sudoers, which no collector reads yet) and 6.2.3.10 (every setuid program,
a join with the `setuid` inventory). A rule binds `audit.*`, so the files
and the loaded set each pass or fail on their own, and asks for what gets
recorded rather than the spelling CIS prints:

- a file or directory passes on a `-w` watch or an `-a always,exit` rule
  with `-F path=` or `-F dir=`, whose access holds `w` and `a` (`x` for a
  program run)
- a syscall passes when some `-a always,exit` line on each architecture CIS
  names (`arch=b64`, `arch=b32`) lists it, alone, grouped or split over lines
- filters that only narrow a rule (`auid>=1000`, `-C uid!=euid`, `a0=0x0`)
  and the `-k` key are not asked for, so a broader rule passes, and a
  narrower one passes too; for 6.2.3.11 an `exit=` filter must be the one
  error asked for, or absent
- `audit/continue-on-error` asks for `-c` and `audit/immutable` for `-e 2`
  with no `-e 0` or `-e 1` anywhere; both judge `audit.rules` alone, since
  `auditctl -l` prints neither

## Audit daemon

`auditd-conf` (root) reads `/etc/audit/auditd.conf` through `kv` into
`auditd.conf`, the last line of a key winning, as auditd reads it, and
`auditd-logs` (root) stats `/var/log/audit` and every entry in it into
`auditd.logs.<path>`. The `auditd` ruleset applies once auditd is on disk;
only its two mode rules carry `default`, the others the CIS control alone:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `auditd/disabled` | info | `auditd.service` is not enabled |
| `auditd/inactive` | info | `auditd.service` is not active |
| `auditd/no-rules` | info | auditd is active and `auditctl -l` lists no `-a` or `-w` rule |
| `auditd/deletes-logs` | info | `max_log_file_action` is not `keep_logs` |
| `auditd/full-disk` | info | `disk_full_action` is not `halt` or `single`, or `disk_error_action` not `syslog`, `single` or `halt` |
| `auditd/low-space` | info | `space_left_action` is not `email`, `exec`, `single` or `halt`, or `admin_space_left_action` not `single` or `halt` |
| `auditd/log-mode` | warning | an audit log is wider than 0640 |
| `auditd/log-owner` | warning | an audit log is not owned by uid 0 |
| `auditd/log-directory-mode` | warning | `/var/log/audit` is group-writable or reaches other users |

auditd compares keywords and values without case (`auditd-config.c`), so the
rules match `(?i)`; an unset key takes auditd’s default (`rotate`, `suspend`,
`ignore`), which fails. Under `--root` no unit has an active state, so
`auditd/inactive` and `auditd/no-rules` are skipped. Ubuntu’s stock
`auditd.conf` fails `deletes-logs`, `full-disk` and `low-space`: CIS trades
availability for a complete record, a choice only the host’s owner can make.

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

### Rescue shells

`rescue/no-sulogin` fails `rescue.service` or `emergency.service` when an
`ExecStart=` it would run names no `sulogin`, so a console that boots into
`rescue.target` gets a root shell unasked. Stock units run
`systemd-sulogin-shell` and pass. A reset with no command after it passes
too: systemd refuses a service with no `ExecStart=`, so no shell opens.

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
- `active` and `sub`: the `active` and `sub` fields of `systemctl
  list-units --all --output=json`, live only. A unit on disk that the manager has not loaded is
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

## Plain-text servers

The `plaintext-servers` ruleset judges servers that carry logins or files in
plain text with little or no authentication, by whether they run, never by
the package: Ubuntu’s telnetd installs its `inetd.conf` line commented out.

| Rule | Severity | Fails when |
| --- | --- | --- |
| `plaintext-servers/nis-unit` | error | `ypserv`, `yppasswdd` or `ypxfrd` is enabled or active |
| `plaintext-servers/tftp-unit` | warning | `tftpd-hpa`, `atftpd` or a `tftp` unit is enabled or active |
| `plaintext-servers/login-unit` | error | a `telnet`, `rsh`, `rlogin` or `rexec` socket unit is enabled or active |
| `plaintext-servers/inetd` | error | an active `inetd.conf` or `inetd.d` line serves telnet, login, shell, exec, tftp, talk, ntalk or a debugging service (echo, discard, chargen, daytime, time) while `inetd.service`, `openbsd-inetd.service` or `inetutils-inetd.service` is enabled or active |
| `plaintext-servers/xinetd` | error | an `xinetd.d` file for one of those services lacks `disable = yes` while `xinetd.service` is enabled or active |

A masked unit passes. The `inetd-services` collector reads `inetd.conf` and
`inetd.d` through `words` columns keyed by service, so `127.0.0.1:telnet`
counts as telnet; `xinetd-services` keeps each `xinetd.d` file’s `service`
and `disable` words, its first block only, and `xinetd-conf` the `enabled` and
`disabled` lists of `xinetd.conf`, which skip the xinetd rule when set, since
they decide instead of `disable`. `xinetd.service` runs without
`-inetd_compat`, so `inetd.conf` lines count only for an inetd unit.

## Services not in use

The `unused-services` ruleset carries no `default` tag: it runs with
`--tags unused-services` or `--tags 'cis-ubuntu-26.04:2.1.*'`, since a host
may serve any of these on purpose. Each rule fails one of CIS 2.1.1 to 2.1.20’s
units while enabled or active and not masked, by unit, never by package:
`autofs`, `avahi-daemon`, Kea DHCP, `named`, `dnsmasq`, `vsftpd`, `slapd`,
`dovecot`, `nfs-server`, `cups`, `rpcbind`, `rsync`, `smbd`, `snmpd`,
`inetutils-inetd`, `squid`, `apache2` and `nginx`, `xinetd`. NIS and TFTP
(2.1.10, 2.1.17) are `plaintext-servers` rules, in `default`.

## Running services

`processes.services` holds, per system service with a running process, its
process IDs and the files they still execute that are gone from disk:

```yaml
processes:
  services:
    nginx.service: {pids: [812, 813], replaced: [/usr/lib/x86_64-linux-gnu/libssl.so.3]}
```

- A process belongs to the service whose `system.slice` cgroup holds it; a
  container’s processes and user sessions are left out.
- `replaced` lists each executable mapping in `/proc/<pid>/maps` that the
  kernel marks `(deleted)` under `/usr`, `/bin`, `/sbin`, `/lib*` or `/opt`: an
  upgrade renames a new file over the old one, and the running process keeps
  the old one. Data files, `memfd` and `/dev/shm` mappings are not code an
  upgrade replaced, so they are left out.

Reading another user’s maps needs root; unprivileged, or under `--root`, the
rule is `Not run`. `restart/replaced-code` fails an `active` service still
running a replaced file; an `activating` one, as a oneshot `apt` upgrading its
own library, is about to exit and is skipped.

## Listening sockets

`ports` holds, per protocol and port, the addresses a socket listens on, from
`/proc/net/{tcp,tcp6,udp,udp6}`:

```yaml
ports:
  "tcp:22": {addresses: [0.0.0.0, "::"]}
  "udp:5353": {addresses: [0.0.0.0, 224.0.0.251, "::"]}
```

- A TCP socket counts in the `LISTEN` state, a UDP one while unconnected, so it
  takes datagrams from anyone; IPv4 and IPv6 share one key, an IPv4-mapped IPv6
  address shown as IPv4.
- The tables need no privilege, but they are the network namespace systemlint
  runs in: inside a container they list the container’s sockets. Under `--root`
  the rules are `Not run`.

The `ports` rules fail a listener on any address outside `127.0.0.0/8` and
`::1`, for services that answer whoever reaches them: `ports/docker-api-plain`
(TCP 2375, Docker’s API without TLS), `ports/cups-browsed` (UDP 631, legacy
CUPS browsing, CVE-2024-47176), `ports/memcached-udp` (UDP 11211, a
reflection amplifier) and `ports/mta-public` (TCP 25, 465 or 587, a mail
server meant for local mail, CIS 2.1.22; waive it on a host that receives mail
for others).

## Journal and display manager

`journald/remote-listening` (CIS 6.1.1.1.2) fails
`systemd-journal-remote.socket` or `.service` while enabled or active and not
masked, since it writes whatever the network sends into the journal.
`gdm/xdmcp` (CIS 1.7.6) fails a GDM file (`custom.conf` or `daemon.conf` under
`/etc/gdm3` or `/etc/gdm`, read by the `gdm-config` collector through `ini`)
whose `[xdmcp]` section sets `Enable` to `true` or `1` in any case; the `gdm`
ruleset is not applicable without one.

## nftables

`nftables.hooks` holds the filter each address family gets on each netfilter
hook, from every base chain of the loaded ruleset, iptables-nft’s included:

```yaml
nftables:
  hooks:
    ipv4:
      input: {policy: drop, drops: false, chains: [inet filter input]}
      forward: {policy: accept, drops: false, chains: []}
    ipv6:
      input: {policy: drop, drops: false, chains: [inet filter input]}
```

- The families are `ipv4` and `ipv6`: an `ip` table counts for IPv4, an `ip6`
  table for IPv6, an `inet` table for both; `arp`, `bridge` and `netdev` tables
  count for neither. Each family has all five hooks, `prerouting`, `input`,
  `forward`, `output` and `postrouting`, with no chain on it when none is.
- `policy`: `drop` when any base chain on the hook has that policy, since
  a packet must pass every base chain on its hook.
- `drops`: some rule in a base chain on the hook, or in a chain it reaches
  through `jump` or `goto`, holds a `drop` or `reject` verdict, a verdict map’s
  included. A chain no hook reaches counts nowhere.

The collector needs `CAP_NET_ADMIN`; unprivileged, or under `--root`, its rules
are `Not run`. The `nftables` ruleset applies once `nftables.service` is
enabled: `nftables/ipv4-input-open` and `nftables/ipv6-input-open` fail an
input hook with neither a drop policy nor a reachable drop or reject, the IPv6
one only while `net.ipv6.conf.all.disable_ipv6` is not 1, and
`nftables/service-failed` fails a `nftables.service` that failed to load its
ruleset. Docker’s own drops sit on the forward hook, so they never pass an
open input hook.
