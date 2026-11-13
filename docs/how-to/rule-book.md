<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Rule book: how to write a shipped rule

[Rules, rulesets and compliance](rules.md) defines the format. This page sets
the conventions every rule under `rulesets/` follows.

## A finding is always real

A rule fails only when the host really is exposed. Leave a check out rather
than guess: a setting that a stock install ships, that a router or container
host needs, or that a newer kernel ignores is no finding.

Judge the value that takes effect. When the consumer combines several keys,
model how it combines them, so the subject reported is the one exposed:

- the kernel accepts IPv4 redirects on an interface when its own key or `all`
  is on, and ignores them on a forwarding interface, so
  `ip-routing/ipv4-redirects` judges each interface under its own `forwarding`,
  and leaves out `lo`, which no redirect can reach
- it accepts IPv4 source routing only when both the interface key and `all`
  are on, so `ip-routing/ipv4-source-route` fails an interface only when both are

## Small rulesets

One ruleset per subject a person thinks of (`ufw.yaml`, `kernel.yaml`,
`fs-protected.yaml`), never one per upstream benchmark. A rule ID is the
ruleset name, a slash and the problem in a few words: `ufw/disabled`.

## Agnostic by default

Detect a tool by what is on disk: its binary or its configuration file, never
the package manager that installed it. A guard that only one distribution can
answer leaves every other host `unknown`.

Put the guard in the ruleset’s `when`, so a host without the tool answers
`not-applicable` and is never rated:

```yaml
when: {ufw.binary: {minProperties: 1}}
```

A collector that stats a binary globs the usual directories with `*`
(`/usr/*bin/ufw`), since an unmatched glob passes nothing and leaves the
object empty.

## Words

- `title` names the problem, not the fix: “ufw installed but switched off”.
- `message` opens with `{subject}` when the fact has a `*`, else with the
  setting; then what it is, `so`, and what an attacker or an accident gets.
- `fix` says what to set or run, with the value.
- `docs` links the upstream manual of the setting.

## Upstream checks

A rule covering a check of another tool cites the check’s ID, never its code
or wording. A rule may cover a check more broadly or more strictly than its
source does.

| Source | Tag | Reference |
| --- | --- | --- |
| Lynis | `lynis` | `{title: Lynis <ID>, url: "https://cisofy.com/lynis/controls/<ID>/"}` |
| `systemd-analyze security` | `systemd-analyze` | `{title: systemd-analyze security, url}` to its manual |
| a catalog under `standards/` | `<standard>:<control>` | the standard’s own link |

`systemlint check --tags lynis` then runs every rule that covers a Lynis check.

## Tests

Every rule is pinned at its edge: the value that passes and the nearest one
that fails (`minimum: 1` passes at `1` and fails at `0`), plus `unknown` when
the fact is absent and `not-applicable` when the ruleset’s guard is false.
