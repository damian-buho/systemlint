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
| `read.exec` | an argv list run without a shell, live mode only; the program is an absolute path |
| `read.image-config` | `true` to pass the file given with `--image-config`; skipped without one |
| `live` | `true` when the collector reads what only a running host has, such as `/proc`; skipped under `--root` |
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
`files` match that is not a regular file, such as a directory in
`/etc/default/*` or a masked unit linked to `/dev/null`, is skipped.

## Sources

- `files`: each match is read whole and passed as text, or as base64 when it is
  not UTF-8.
- `stat`: each match is passed with its type, octal mode, owner, group, size and
  the `world-writable`, `group-writable`, `setuid` and `setgid` booleans. A
  final symlink is described itself, not followed; its booleans are all false,
  since a symlink’s own mode means nothing on Linux.
- `exec`: the argv runs directly, never through a shell, with an empty
  environment except `LC_ALL=C`, a timeout and an output cap. Its `stdout`,
  `stderr` and exit code are passed to the plugin, which judges the exit; an
  absent program is passed as exit 127, as a shell reports it.
- `image-config`: the OCI image config or `docker inspect` JSON the operator
  names with `--image-config`, read from the host as given, since an image’s
  `ENV` is not in its root filesystem. The path as given is the input’s
  `path`, and `meta.subject.image-config` records it.

Every source is read-only and capped at 16 MiB per file or stream; `exec`
and the plugin call each time out after 30 seconds. Under `--root <dir>` every
path, symlinks and `..` included, resolves inside that directory through
`openat2` `RESOLVE_IN_ROOT` (Linux 5.6 or later), so an image’s symlink to
`/etc/shadow` reads the image’s file, never the host’s. `exec` never runs
there: a collector that only runs a command is recorded as `skipped` with the
reason, never as an error, and one that also reads `files` or `stat` runs
without the command input.

A file that exists but cannot be read, such as `/etc/shadow` in an
unprivileged run, fails the whole collector with that path in its reason,
because partial facts would read as compliant.

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
`hashed` how many values were replaced by their keyed hash.

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
gets it as `now`, and a later `lint` judges ages by it.

`systemlint facts -o PATH` (`--output`) writes the document atomically with
mode 0600, as JSON when the name ends in `.json`, else YAML, unless `--format
yaml|json` says; `-o -` prints it as without `-o`. A save then prints one
stderr line naming the file, the
collectors run and failed, and the `lint` command that reads it; `-q` drops
it. `systemlint lint PATH`, or
`lint -` for stdin, judges a saved document with no access to the subject.

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

## Derived facts

A collector never computes a fact from other facts. A plugin op that needs
facts collected first lists them in `--describe` as `needs`, receives them in
the request, and returns the derived facts in its reply. See
[the plugin protocol](protocol.md).
