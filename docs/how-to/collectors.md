<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Collectors

A collector is a YAML file that tells the systemlint core what to read, which
plugin op turns it into facts, and where those facts land in the facts
document. Collecting never depends on the rules: every configured collector
runs, so one facts document serves any number of lint runs.

```yaml
id: apt-sources
read:
  files: [/etc/apt/sources.list, /etc/apt/sources.list.d/*.sources, /etc/apt/sources.list.d/*.list]
parse: {plugin: apt, op: sources}
into: apt.sources
```

| Field | Meaning |
| --- | --- |
| `id` | a unique slug; its outcome is recorded as `collectors.<id>` |
| `read.files` | absolute globs whose files are read and passed with their content |
| `read.stat` | absolute globs whose files are passed with their `stat` and no content |
| `read.statfs` | absolute globs whose paths are passed with the `statfs` of the filesystem holding them; a path the run may not reach is left out (`partial` makes it unknown), and one that gives no answer within the timeout fails the collector |
| `read.exec` | an argv list run without a shell, live mode only; the program is an absolute path |
| `read.image-config` | `true` to pass the file given with `--image-config`; skipped without one |
| `read.files-from` | dotted fact paths, `*` a whole segment, whose strings name files to read, as `env.units.*.environment-files` |
| `read.stat-from` | the same, naming files to pass with their `stat` |
| `read.stat-keep` | a JSON Schema over each `stat`: only the stats it admits reach the plugin, as `{properties: {setuid: {const: true}}}` keeps a walk of `/usr/**` to its set-user-ID files; needs `stat` or `stat-from` |
| `read.statfs-from` | the same, naming paths to pass with their `statfs`, as `mounts.active` |
| `read.hash` | `sha256`, `sha512` or both: adds the file’s lowercase hex digest to the `stat` of each regular file; needs `stat` or `stat-from` |
| `live` | `true` when the collector reads what only a running host has, such as `/proc`; skipped under `--root` |
| `secret` | `true` to replace every string the op returns with its keyed hash, as for values a plugin marks, so a command’s output compares without being stored |
| `partial` | `true` to keep what the run may read: a path it may not read becomes the key `into.<path>`, which every rule under a `*` there answers `unknown` for; only for an op that keys its facts by input path |
| `privileged` | `true` when only root can read its sources, such as `/proc/1/environ` or a 0600 file under `/etc/default`; skipped when systemlint runs unprivileged |
| `parse.plugin` | the plugin name, `apt` for `systemlint-apt` |
| `parse.op` | an op the plugin lists in `--describe` |
| `into` | the dotted fact path the reply’s facts are placed at; never under `meta` or `collectors`, never overlapping another collector’s |

`files`, `stat` and `exec` sit side by side under `read`; a collector uses
the ones it needs. A path in both `files` and `stat` reaches the plugin as one
input carrying both.

In a glob, `*` matches any run of characters and `?` one character, both within
one path component and never a leading dot; `.*` matches dotfiles. A path with
no wildcard is passed when it exists, and an absent one is not an error. A
`**` as the whole last component (`/usr/**`) matches the directory and every
path below it, dotted names included, but never enters a symlinked directory or
another filesystem; a glob naming more than a million paths fails its
collector, so a walk that was cut short never passes. A
`files` match that is not a regular file, such as a directory in
`/etc/default/*` or a masked unit linked to `/dev/null`, is skipped.

## Sources

- `files`: each match is read whole and passed as text, or as base64 when it is
  not UTF-8.
- `stat`: each match is passed with its type, octal mode, owner, group, size and
  the `world-writable`, `group-writable`, `setuid` and `setgid` booleans. A
  final symlink is described itself, not followed, with its target as
  `linked-to`; its booleans are all false, since a symlink’s own mode means
  nothing on Linux.
- `exec`: the argv runs directly, never through a shell, with an empty
  environment except `LC_ALL=C`, a timeout and an output cap. Its `stdout`,
  `stderr` and exit code are passed to the plugin, which judges the exit; an
  absent program is passed as exit 127, as a shell reports it.
- `image-config`: the OCI image config or `docker inspect` JSON the operator
  names with `--image-config`, read from the host as given, since an image’s
  `ENV` is not in its root filesystem. The path as given is the input’s
  `path`, and `meta.subject.image-config` records it.

Every source is read-only and capped at 16 MiB per file or stream; `exec`
and the plugin call each time out after 30 seconds, or `collect.timeout`
seconds from the configuration. Collectors run `--jobs N` at once (1 to 64,
default `collect.jobs`, else the available CPUs), a collector waiting for
the ones that produce what it `needs`; the facts document is the same for
any `N`. Under `--root <dir>` every
path, symlinks and `..` included, resolves inside that directory through
`openat2` `RESOLVE_IN_ROOT` (Linux 5.6 or later), so an image’s symlink to
`/etc/shadow` reads the image’s file, never the host’s. `exec` never runs
there: a collector that only runs a command is recorded as `skipped` with the
reason, never as an error, and one that also reads `files` or `stat` runs
without the command input.

A file that exists but cannot be read, such as `/etc/shadow` in an
unprivileged run, fails the whole collector with that path in its reason,
because partial facts would read as compliant. A `partial` collector records
such a path and why under `collectors.<id>.unreadable` instead, finishes
`ok`, and the judge binds the path as a subject under `into` that answers
`unknown`, naming the file, so `env-defaults` judges every readable
`/etc/default` file while a 0600 one stays visible.

## Outcomes

Each collector records `collectors.<id>.status` and its `into` in the facts
document, with a `reason` when it is not `ok`:

| Status | Meaning |
| --- | --- |
| `ok` | the plugin replied and its facts are under `into` |
| `error` | reading failed, the plugin exited non-zero or replied with invalid JSON; the reason is kept |
| `skipped` | the mode cannot run it, such as `exec` or `live` under `--root`, `image-config` without `--image-config`, or `privileged` in an unprivileged run; the reason is kept |

An `ok` collector also records its `plugin` and `op`, the plugin’s
`diagnostics`, under `redacted` the JSON Pointers of the values the plugin
marked secret, which are replaced by `[redacted]` in every output, and under
`hashed` how many values were replaced by their keyed hash, and under
`unreadable` each path a `partial` collector could not read.

A rule that reads a fact from a collector that did not finish `ok` answers
`unknown`, naming that collector, rather than passing. The `human` report lists
an `unknown` from a `skipped` collector on no line of its own: it prints one
`not run` line per skip reason, naming the collectors and the rules, and counts
those checks as `not run`; `json`, `sarif`, `textfile` and the `--standard`
verdicts keep them `unknown`, so a run that skipped a collector is never
`compliant`.

## The facts document

```console
$ systemlint facts --root fixtures/ubuntu-26.04
collectors:
  os-release:
    op: kv
    plugin: formats
    status: ok
meta:
  collected-at: "2026-11-11T12:00:00Z"
  plugins:
    formats: "0.1.0"
  privileged: false
  schema: 1
  subject:
    kind: root
    path: /srv/systemlint/fixtures/ubuntu-26.04
  systemlint: "0.1.0"
os:
  release:
    ID: ubuntu
    VERSION_CODENAME: resolute
```

Facts sit at the top level beside `meta` and `collectors`. `meta.subject` is
`{kind: host, name}` on a live host and `{kind: root, path}` under `--root`;
`privileged` says whether the run was root, so an unprivileged collection is
never mistaken for a full one. `collected-at` is the one clock: every plugin
gets it as `now`, and a later `check` judges ages by it.

`systemlint facts -o PATH` (`--output`) writes the document atomically with
mode 0600, as JSON when the name ends in `.json`, else YAML, unless `--format
yaml|json` says; `-o -` prints it as without `-o`. A save then prints one
stderr line naming the file, the
collectors run and failed, and the `check` command that reads it; `-q` drops
it. On a terminal, `facts` and `check` show which collector runs now, and a
run of a second or more ends with its time and the commands it ran
(`Collected in 2.3 s; ran sshd -T.`); `-q` drops both, `-v` the first. `systemlint check PATH`, or
`check -` for stdin, judges a saved document with no access to the subject.

## Where collectors come from

A collector runs code on the host, so the core loads collectors only from
`../share/systemlint/collectors/` beside the `systemlint` binary and from the
directories the configuration names, never from the subject being scanned and
never over the network:

```yaml
collect:
  directories:
    - /etc/systemlint/collectors
```

Each `*.yaml` file there is one collector, read in name order. The same trust
rules as for plugins apply: a directory or file that a stranger owns or that
group or others can write is refused, and so is a file whose `id` is taken or
whose `into` overlaps an earlier collector’s.

A configuration may also list collectors inline under `collect.collectors`, in
the same shape, to stat or read a file no shipped collector names:

```yaml
collect:
  collectors:
    - id: nginx
      read: {stat: [/etc/nginx/nginx.conf], hash: [sha256]}
      parse: {plugin: formats, op: stat}
      into: files.nginx
```

An inline collector never runs `exec`, since `.systemlint.yaml` comes with
whatever directory systemlint runs in; one that needs a command goes in a file
under `collect.directories`. It runs after the collectors from directories,
and one whose `id` or `into` clashes with theirs is refused. A `stat` path it
names that is absent becomes `{exists: false}` from the `stat` op, so a rule
can require absence; under `files.*` that path leaves the shipped `files`
rules `unknown`, so give such a collector its own `into`. To judge a file’s
contents, read it under `files` with `op: lines`, which keys each file’s list of
lines by its path, so a rule asserts `contains: {pattern: …}`; contents enter
the facts document only through a collector the operator writes. `op: yaml`
(YAML 1.2 booleans, so `no` stays a string), `op: toml` (a date as its TOML
text) and `op: csv` (a list of rows keyed by the header row) key each parsed
file by its path, a file that does not parse becoming a diagnostic.

To judge any command, a collector file under `collect.directories` runs it
with `read.exec` and `op: exec`, which returns its `exit-status`, `stdout`,
`stderr` and `stdout-lines`:

```yaml
id: nginx-test
read: {exec: [/usr/sbin/nginx, -t]}
parse: {plugin: formats, op: exec}
into: commands.nginx-test
```

## Derived facts

A collector never computes a fact from other facts. A plugin op that needs
facts collected first lists them in `--describe` as `needs`, receives them in
the request, and returns the derived facts in its reply. See
[the plugin protocol](protocol.md).

A collector may still read the files a fact names: `read.files-from`,
`read.stat-from` and `read.statfs-from` take every string, or string in a list,
at their pattern, or every key of a map there (`mounts.active` names each mount
point), keep the absolute ones, and read each path as written, never as a glob,
through the same root. The collector runs after every collector writing under
the pattern’s literal part, the segments before its first `*`; when that part
is absent from the facts, it fails naming the fact and the collector that left
it out, so its rules read as unknown instead of passing on fewer files. A
pattern may not start with `*` or read what its own collector writes.
