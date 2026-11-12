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
| `read.exec` | an argv list run without a shell, live mode only |
| `parse.plugin` | the plugin name, `apt` for `systemlint-apt` |
| `parse.op` | an op the plugin lists in `--describe` |
| `into` | the dotted fact path the reply’s facts are placed under |

`files`, `stat` and `exec` sit side by side under `read`; a collector uses
the ones it needs.

## Sources

- `files`: each match is read whole and passed as text, or as base64 when it is
  not UTF-8.
- `stat`: each match is passed with its type, octal mode, owner, group, size and
  the `world-writable`, `group-writable`, `setuid` and `setgid` booleans.
- `exec`: the argv runs directly, never through a shell, with an empty
  environment except `LC_ALL=C`, a timeout and an output cap. Its `stdout`,
  `stderr` and exit code are passed to the plugin.

Every source is read-only. Under `--root <dir>` every path, symlinks included,
resolves inside that directory, and `exec` collectors do not run: they are
recorded as `skipped` with the reason, never as an error.

## Outcomes

Each collector records `collectors.<id>.status` in the facts document:

| Status | Meaning |
| --- | --- |
| `ok` | the plugin replied and its facts are under `into` |
| `error` | reading failed, the plugin exited non-zero or replied with invalid JSON; the reason is kept |
| `skipped` | the mode cannot run it, such as `exec` under `--root`; the reason is kept |

A rule that reads a fact from a collector that did not finish `ok` answers
`unknown`, naming that collector, rather than passing.

## Where collectors come from

A collector runs code on the host, so the core loads collectors only from the
directories its configuration names and from those shipped beside it, never
from the subject being scanned and never over the network.

## Derived facts

A collector never computes a fact from other facts. A plugin op that needs
facts collected first lists them in `--describe` as `needs`, receives them in
the request, and returns the derived facts in its reply. See
[the plugin protocol](protocol.md).
