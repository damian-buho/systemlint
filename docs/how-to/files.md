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
systemlint lint --tags files
systemlint lint --root /mnt/image --tags files
```

## Collectors

Each collector passes its `read.stat` globs to the `stat` op of
`systemlint-formats`, which keys every stat by its path and adds
`exists: true`.

| Collector | Stats | Facts at |
| --- | --- | --- |
| `files-shadow` | `/etc/shadow`, `/etc/gshadow` and their `-` backups | `files.shadow.<path>` |
| `files-sudoers` | `/etc/sudoers`, `/etc/sudoers.d` and every file in it | `files.sudoers.<path>` |
| `files-cron` | `/etc/crontab`, every `/etc/cron.*` and every file in one | `files.cron.<path>` |
| `files-sshd` | `/etc/ssh/sshd_config`, `sshd_config.d` and its files, the public host keys | `files.sshd.<path>` |
| `files-ssh-host-keys` | the private host keys, `/etc/ssh/ssh_host_*_key` | `files.ssh-host-keys.<path>` |
| `files-apt-keyrings` | `/etc/apt/trusted.gpg`, `trusted.gpg.d`, `/etc/apt/keyrings`, `/usr/share/keyrings` and their files | `files.apt-keyrings.<path>` |
| `files-path` | `/usr`, `/usr/local`, the directories of Debian’s default `PATH`, `/snap/bin` included, and every absolute `PATH` entry of a system file or a unit | `files.path.<path>` |

A stat holds `kind` (`file`, `directory`, `symlink`, `other`), `mode` as four
octal digits, `uid`, `gid`, `size`, and the `world-writable`,
`group-writable`, `setuid` and `setgid` booleans. A symlink is described
itself, not followed, with its target as written in `linked-to`, and its
booleans are all false; its target is judged where a collector lists it. A
collector with `read.hash` adds `sha256` or `sha512` to each regular file.

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

A subject of the first three rules is the group and the path, such as
`sudoers, /etc/sudoers.d/deploy`. “0640 or stricter” means no execute bit, no
special bit, a group that may only read and no access for others, so 0600 and
Red Hat’s 0000 pass and 0644, 0660 and 4640 fail. Debian’s `/usr/local` was
once 2775 `root:staff`; waive `files/group-writable` there when the `staff`
group is meant to install software:

```yaml
lint:
  waivers:
    - {rule: files/group-writable, subject: "path, /usr/local*", reason: staff installs into /usr/local, until: 2027-06-30}
```
