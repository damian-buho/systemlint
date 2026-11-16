<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# File permissions

The `files-*` collectors read the mode and owner of the files that grant root,
hold password hashes or host keys, or sit in the default `PATH`, and the
`files` ruleset judges them. Only metadata is read, never content, so
`/etc/shadow` is judged without being opened.

```sh
systemlint check --tags files
systemlint check --root /mnt/image --tags files
```

## Collectors

Each collector passes its `read.stat` globs to the `stat` op of
`systemlint-formats`, which keys every stat by its path and adds
`exists: true`.

| Collector | Stats | Facts at |
| --- | --- | --- |
| `files-shadow` | `/etc/shadow`, `/etc/gshadow` and their `-` backups, `/etc/security/opasswd` and `opasswd.old` | `files.shadow.<path>` |
| `files-sudoers` | `/etc/sudoers`, `/etc/sudoers.d` and every file in it | `files.sudoers.<path>` |
| `files-cron` | `/etc/crontab`, every `/etc/cron.*` and every file in one | `files.cron.<path>` |
| `files-sshd` | `/etc/ssh/sshd_config`, `sshd_config.d` and its files, the public host keys | `files.sshd.<path>` |
| `files-ssh-host-keys` | the private host keys, `/etc/ssh/ssh_host_*_key` | `files.ssh-host-keys.<path>` |
| `files-apt-keyrings` | `/etc/apt/trusted.gpg`, `trusted.gpg.d`, `/etc/apt/keyrings`, `/usr/share/keyrings` and their files | `files.apt-keyrings.<path>` |
| `files-path` | `/usr`, `/usr/local`, the directories of Debian’s default `PATH`, `/snap/bin` included, and every absolute `PATH` entry of a system file, a `/etc/default` or `EnvironmentFile=` file, or a unit | `files.path.<path>` |
| `files-search-path` | every absolute `LD_LIBRARY_PATH` and `PYTHONPATH` entry of a system file, a `/etc/default` or `EnvironmentFile=` file, or a unit | `files.search-path.<path>` |
| `files-accounts` | `/etc/passwd`, `/etc/group`, their `-` backups and `/etc/shells` | `files.accounts.<path>` |
| `files-apt-sources` | `/etc/apt/sources.list`, `sources.list.d` and its files, and the `auth.conf.d` directory | `files.apt-sources.<path>` |
| `files-apt-auth` | `/etc/apt/auth.conf` and every file in `auth.conf.d` | `files.apt-auth.<path>` |
| `files-boot` | `/boot/grub/grub.cfg` and `user.cfg` | `files.boot.<path>` |
| `files-audit-config` | `/etc/audit`, its `.conf` files, `rules.d` and `plugins.d` and their files | `files.audit-config.<path>` |
| `files-audit-tools` | `auditctl`, `aureport`, `ausearch`, `autrace`, `auditd` and `augenrules` in `/usr/sbin` or `/usr/bin` | `files.audit-tools.<path>` |
| `files-libraries` | `/usr/lib`, `/usr/lib64`, every `/usr/lib/*-linux-gnu*` directory and the `*.so*` files at their top | `files.libraries.<path>` |
| `files-commands` | every regular file in `/usr/bin`, `/usr/sbin`, `/usr/local/bin` and `/usr/local/sbin` | `files.commands.<path>` |

A stat holds `kind` (`file`, `directory`, `symlink`, `other`), `mode` as four
octal digits, `uid`, `gid`, `size`, and the `world-writable`,
`group-writable`, `setuid` and `setgid` booleans. A symlink is described
itself, not followed, with its target as written in `linked-to`, and its
booleans are all false; its target is judged where a collector lists it. A
collector with `read.hash` adds `sha256` or `sha512` to each regular file.

The `setuid` collector walks `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64` and
`/opt` (`read.stat` `**`) and keeps the regular files with a set-user-ID or
set-group-ID bit (`read.stat-keep`) into `setuid.<path>`, in the same stat
shape. It needs root, since `/opt` often holds directories only root may list,
and sits outside `files` so the `files` rules never judge a package’s setuid
file owned by its service user. It also stats every directory above each kept
file (`read.stat-parents`), `/` left out, into the same map, since whoever may
write one of them can swap the file for a program of their own. The `setuid`
ruleset judges every entry, file or directory:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `setuid/world-writable` | error | a set-user-ID or set-group-ID file, or a directory above it, is writable by others |
| `setuid/group-writable` | warning | one of them is writable by its group |

A directory with the sticky bit passes both, since then no other user may
rename or delete the root-owned file in it.

The groups are separate collectors so that one unreadable directory, such as a
0750 `/etc/sudoers.d` in an unprivileged run, fails its own group alone. Rules
over every group (`files.*.*`) then answer `unknown` for that group, naming its
collector, and still judge the others. The `PATH` a session really uses
depends on its environment, which these collectors do not read.

## Rules

| Rule | Severity | Fails when |
| --- | --- | --- |
| `files/world-writable` | error | any listed file or directory is writable by others |
| `files/group-writable` | warning | any of them is writable by its group |
| `files/owner` | error | any of them is not owned by uid 0 |
| `files/shadow-mode` | error | a shadow file is more open than 0640 |
| `files/ssh-host-key-mode` | error | a private host key is more open than 0640 |
| `files/apt-auth-readable` | error | an APT credentials file is readable by others |
| `files/accounts-mode` | info | an account database is more open than 0644 (CIS only) |
| `files/accounts-group` | info | an account database or `/etc/shells` is in a group other than root (CIS and dev-sec only) |
| `files/shadow-group` | warning | a shadow or gshadow file is in a group other than root or `shadow`, while `shadow` holds Debian’s gid 42 (CIS and dev-sec only) |
| `files/bootloader-readable` | info | a GRUB configuration file grants its group or others any access (CIS only) |
| `files/audit-config-mode` | info | an audit configuration file is more open than 0640 (CIS and STIG only) |
| `files/audit-config-group` | info | an audit configuration file or directory is in a group other than root (CIS and STIG only) |
| `files/audit-tools-mode` | info | an audit tool is more open than 0755, or carries a special bit (CIS and STIG only) |
| `files/audit-tools-group` | info | an audit tool is in a group other than root (CIS and STIG only) |
| `files/library-group` | info | a shared library is in a group above `system-gid-max` (999) (STIG only) |
| `files/library-directory-group` | info | a library directory is in a group other than root (STIG only) |
| `files/command-group` | info | a system command is in a group above `system-gid-max` (999) (STIG only) |

The `grub` ruleset applies where `/boot/grub/grub.cfg` exists. The
`grub-users` collector matches its `superusers` and `password_pbkdf2` lines
through `match`, keeping the keyword alone, never the user or the hash, and
`grub/no-password` (CIS 1.4.1, Lynis BOOT-5122, STIG 102000, *standard-only*)
fails unless both are there. `session-lock/no-vlock` (STIG 101000,
*standard-only*) fails without a `vlock` program (`vlock-binary`).

A subject of the first three rules is the group and the path, such as
`sudoers, /etc/sudoers.d/deploy`. “0640 or stricter” means no execute bit, no
special bit, a group that may only read and no access for others, so 0600 and
Red Hat’s 0000 pass and 0644, 0660 and 4640 fail. The STIG’s library and
command controls ask what the first three rules judge, no group or other
write and owner root, over `files-libraries` and `files-commands`; setgid
commands in a system group (`crontab`, `chage`, `ssh-agent`) pass the group
rule. Debian’s `/usr/local` was
once 2775 `root:staff`; waive `files/group-writable` there when the `staff`
group is meant to install software:

```yaml
check:
  waivers:
    - {rule: files/group-writable, subject: "path, /usr/local*", reason: staff installs into /usr/local, until: 2027-06-30}
```

## Login banners

The `banner-files` collector stats `/etc/motd`, `/etc/motd.d` and its files,
`/run/motd.dynamic`, `/etc/issue` and `/etc/issue.net` into
`banner.files.<path>`, and `banner-sshd` stats each absolute path sshd’s
`Banner` names (`sshd.settings.banner`) into `banner.sshd.<path>`, so it runs
only where the `sshd` collector did. They sit outside `files`, since nobody
becomes root through a banner. `banner-text` reads the lines of the motd and
issue files, `issue.d` and `/run/motd.dynamic` (the `motd=` file of Ubuntu’s
stock `pam_motd` lines) included, into `banner-text.files.<path>`, and
`banner-sshd-text` the file sshd’s `Banner` names into
`banner-text.sshd.<path>`, outside `banner` so no stat rule binds them. The
`banner` ruleset judges them, and the update-notifier units in
`systemd.state`:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `banner/writable` | warning | its group or others may write it, so they can show every user a forged notice at login |
| `banner/owner` | warning | it is not owned by uid 0 |
| `banner/discloses-system` | info | it holds an agetty `\s`, `\r`, `\v` or `\m` escape, either case, not after an escaping backslash (CIS 1.6.1 to 1.6.5, *standard-only*; CIS also asks for no `ID` of `os-release`, left out) |
| `banner/update-notifier-service` | info | `update-notifier-motd.service` is enabled or running and not masked, so the update counts reach the motd (CIS 1.6.11, *standard-only*) |
| `banner/update-notifier-timer` | info | `update-notifier-motd.timer` is enabled or running and not masked (CIS 1.6.12, *standard-only*) |

## Cron

The `cron` ruleset judges the `files-cron` stats of `/etc/crontab` and the
`/etc/cron.d`, `cron.hourly`, `cron.daily`, `cron.weekly`, `cron.monthly` and
`cron.yearly` directories:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `cron/world-readable` | warning | one grants others any access, so every user reads the jobs root runs and any password or token written into one |

Stock Debian and Ubuntu ship 0644 and 0755, so a stock host fails;
`systemlint fix` clears the other bits. Group bits pass, as does a symlink.
The files inside a directory are not judged, since a 0700 directory already
hides them, nor are `cron.allow`, `cron.deny`, `at.allow` and `at.deny`, whose
usernames `/etc/passwd` already shows to everyone.

CIS asks more, *standard-only*, so these rules are out of `default`
(`--tags 'cis-ubuntu-26.04:2.4.*'`). The `cron-access` and `at-access`
collectors stat `cron.allow`, `cron.deny` and `/usr/bin/crontab` into
`cron.access.<path>`, and `at.allow`, `at.deny` and `/usr/bin/at` into
`at.access.<path>`, a missing path as `exists: false`. The `at` ruleset is
also out of `default` (`--tags at`).

| Rule | Severity | Fails when |
| --- | --- | --- |
| `cron/off` | info | `cron.service` is on disk and not masked, but not both enabled and active (CIS 2.4.1.1) |
| `cron/no-allow` | info | `crontab` is installed and `cron.allow` is missing, so every user `cron.deny` leaves out may schedule jobs (CIS 2.4.1.9) |
| `cron/access-mode`, `at/access-mode` | info | an existing allow or deny file is more open than 0640 (CIS 2.4.1.9, 2.4.2.1) |
| `cron/access-owner`, `at/access-owner` | info | an existing allow or deny file is not owned by uid 0 |
| `cron/access-group`, `at/access-group` | info | an existing allow or deny file is in a group other than root and `crontab`, or root and `daemon`, the gid read from `accounts.group` |
| `at/no-allow` | info | `at` is installed and `at.allow` is missing; the stock `at.deny` alone fails (CIS 2.4.2.1) |

## Temporary directories

The `tmp-dirs` collector stats `/tmp`, `/var/tmp` and `/dev/shm` into
`tmp.dirs.<path>`, apart from the `files` groups, since these directories are
world-writable by design. The `tmp` ruleset judges them:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `tmp/sticky` | error | a world-writable one lacks the sticky bit, so any user can delete or replace another user’s files in it |

A directory no other user can write, or an absent one, passes.

## Home directories

The `home-directories` collector stats each `/etc/passwd` home into
`home.directories.<path>`, with no privilege, since `/home` is searchable by
everyone; a home that does not exist lands as `exists: false`
(`read.stat-absent`). The `home` ruleset judges them:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `home/open-to-others` | warning | a home owned by a uid from `uid-min` (1000) to `uid-max` (60000) grants others any access, so they list it and read what its owner leaves readable |
| `home/not-owned` | warning | an account with a uid from `uid-min` to `uid-max` has a home directory another uid owns, who can then change its files and shell startup scripts |

The uid is the directory’s owner, not the account’s, so a service account
whose home is root’s `/usr/sbin` or `/var/www` is skipped, as are `nobody`
(65534) and the uids systemd gives dynamic users. The two bounds are ruleset
vars, set with `check.vars` where `/etc/login.defs` moves `UID_MIN` or
`UID_MAX`. A symlink is skipped; its target is not followed.
`home/not-owned` is judged per account instead, so a home two accounts share
fails for the one that does not own it, and an account whose home was never
made is skipped.

## Users’ SSH directories

Two collectors stat each `/etc/passwd` home’s `.ssh` (`read.stat-from`
`{accounts.passwd.*.home}/.ssh`) into `ssh-user.directories.<path>`, and every
entry in it, dotted names left out, into `ssh-user.files.<path>`. Both need
root, since another user’s home is often 0750, and sit outside `files`, since
these belong to their users, not to root. A home that is absent, a file or a
relative path names nothing. The `ssh-user` ruleset judges them:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `ssh-user/world-writable` | error | a `.ssh` or an entry in it is writable by others, who can then add a key and log in as its owner |
| `ssh-user/directory-mode` | warning | a `.ssh` grants others any access, so they reach its public keys, `known_hosts` and `config` |

Group bits pass both: Debian and Ubuntu give each user a group of their own,
and their OpenSSH accepts a group-writable `.ssh` when that group holds its
owner alone. A symlink passes, its booleans being false; its target is not
followed.

## Users’ .netrc

The `netrc-files` collector (root) stats each `/etc/passwd` home’s `.netrc`
into `netrc.files.<path>`. The `netrc` ruleset judges them:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `netrc/readable` | error | every user can read it, and with it the plain-text passwords it holds |

Group bits pass, for the reason above; a symlink is skipped.

## Host trust files

`rhosts-system` stats `/etc/hosts.equiv` into `rhosts.system`, `rhosts-users`
(root) each `/etc/passwd` home’s `.rhosts` into `rhosts.users`, and
`rhosts-readers` the rsh and rlogin servers (`in.rshd`, `in.rlogind`) into
`rhosts.readers`. The `rhosts` ruleset applies only where one of those servers
is installed, since nothing else on a current host reads these files; sshd’s
use of `.rhosts` is `ssh/ignore-rhosts`.

| Rule | Severity | Fails when |
| --- | --- | --- |
| `rhosts/hosts-equiv` | error | `/etc/hosts.equiv` is not empty, so the hosts it names log in as any matching local user without a password |
| `rhosts/user-file` | error | a `.rhosts` is not empty, so the users it names log in as its owner without a password |

An empty file trusts nobody and passes; a symlink is skipped, since `ruserok`
refuses any that does not lead to a regular file, and linking it to
`/dev/null` is the usual way to switch one off.

## Mounts

Two collectors read the mount table, each keyed by mount point with its
`source`, `filesystem`, `options` and `line`:

| Collector | Into | Reads |
| --- | --- | --- |
| `mounts-active` | `mounts.active` | `/proc/self/mounts` on a live host (`formats words`), the top of a stacked mount point winning; `options` holds the mount’s and its filesystem’s |
| `mounts-fstab` | `mounts.fstab` | `/etc/fstab` (`formats words`), `options` with the later option winning and what `user`, `users`, `owner` and `group` imply added after them, so `suid,user` reads `nosuid` and `user,suid` keeps `suid` |

A third, `mounts-usage`, statfs each active mount point on a live host into
`mounts.usage.<point>`: `blocks` and `inodes` used, in whole percent rounded up
as `df` does, each left out when the filesystem counts none (`proc`, `sysfs`),
and `read-only`. A mount point the run may not reach, such as another user’s
FUSE mount, answers `unknown` as its own subject; a `statfs` that gives no answer within the collector
timeout, as a dead network mount does, fails the collector.

The `mounts` ruleset judges `/tmp`, `/var/tmp` and `/dev/shm` when each is a
mount of its own; one that is part of `/` has no check. A live run judges the
active table, a `--root` run the declared one:

| Rule | Severity | Fails when |
| --- | --- | --- |
| `mounts/nosuid`, `mounts/fstab-nosuid` | warning | the mount lacks `nosuid`, so a set-user-ID file left there runs with its owner’s rights |
| `mounts/nodev`, `mounts/fstab-nodev` | warning | the mount lacks `nodev`, so a device file unpacked there opens the device it names |
| `mounts/noexec`, `mounts/fstab-noexec` | warning | the mount lacks `noexec`, so a program dropped there runs straight from it |

Stock Debian and Ubuntu mount `/tmp` and `/dev/shm` without `noexec`, and fail
`mounts/noexec` all the same. An interpreter still runs a script from a
`noexec` mount, so the rule stops dropped binaries, not scripts. Package
installs keep working: debconf unpacks config scripts into
`/var/cache/debconf/tmp.ci`, not `/tmp`.

CIS alone asks more, in `'!default'` rules on a live run: `mounts/separate-tmp`,
`-dev-shm`, `-home`, `-var`, `-var-tmp`, `-var-log` and `-var-log-audit` fail
when that path is no mount of its own (1.1.2.x.1), and
`mounts/partition-nodev`, `-nosuid` (`/home`, `/var`, `/var/log`,
`/var/log/audit`) and `-noexec` (`/var/log`, `/var/log/audit`) judge the options
of those that are.

The `disk` ruleset judges `mounts.usage` on a live run, scored on a curve from
warning at 90 % to error from 98 %. It leaves out read-only filesystems, which
always read full (squashfs snaps, ISO images), `overlay` mounts, which
repeat the disk under them once per container, and `nsfs` namespace handles,
which hold no data and which an unprivileged run may not reach:

| Rule | Fails when |
| --- | --- |
| `disk/full` | 90 % or more of the blocks a user may fill are used, so writes fail soon |
| `disk/inodes` | 90 % or more of the inodes are used, so creating a file fails while space is still free |

Both guard on `collectors.mounts-usage.status`, so a `--root` run skips them and
a failed collector answers `unknown`.
