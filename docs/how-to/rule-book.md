<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Rule book: how to write a shipped rule

[Rules, rulesets and compliance](rules.md) defines the format. This page sets
the conventions every rule under `rulesets/` follows.

## A finding is always real

A rule fails only when the host really is exposed. Leave a check out rather
than guess: a setting that a router or container host needs, or that a newer
kernel ignores, is no finding. A stock install shipping it is no excuse: a
stock default that exposes the host fails all the same.

Judge the value that takes effect. When the consumer combines several keys,
model how it combines them, so the subject reported is the one exposed:

- the kernel accepts IPv4 redirects on an interface when its own key or `all`
  is on, and ignores them on a forwarding interface, so
  `ip-routing/ipv4-redirects` judges each interface under its own `forwarding`,
  and leaves out `lo`, which no redirect can reach
- it accepts IPv4 source routing only when both the interface key and `all`
  are on, so `ip-routing/ipv4-source-route` fails an interface only when both are

## Conflicting standards

A rule judges what is good for the system, not what a distribution ships: a
stock default that exposes the host still fails. Where two standards disagree
(NIST SP 800-63B against forced password rotation, a benchmark demanding it),
ship each side as its own rule tagged with its standard’s control, so the user
picks the standard they follow with `--tags` or `--prefer`. Each side names the other in
`conflicts`, so a run selecting both reports one `Conflict` block and fails
the host on neither, unless `--prefer` matches one side’s tags. A threshold a standard picks is a ruleset var defaulting
to that standard’s number, so a user’s own standard is a `--var`, never a
misuse.

## The default tag

A ruleset that hardens the host carries `tags: [default]`, so a bare
`systemlint check` runs it, every rule in it included: a ruleset’s `when`
already leaves out software the host does not have. A practice ruleset
(performance, stability, an opinionated profile) leaves it out and runs when
its tag is named; a category is a tag, never a field. A rule carries
`'!default'` and its control tag only when it is the standard-only side of a
`conflicts` pair, a stricter copy of a default rule (`login-defs/umask-077`,
the `stig-` variants), a preference with no exposure behind it (a tool that
is not installed, a separate mount), or one whose fix breaks a common
workload: forwarding and `overlay` break Docker, `squashfs` breaks snaps,
`usb-storage` breaks a desktop, refused router advertisements break SLAAC.
It stays in its subject’s ruleset and runs when that standard is named.

## Scores

A score says how bad the exposure is on a typical host, never how often a
benchmark cites it. Pick the band from who can do what, then move within it
by how likely and how easy that is:

| Score | Who gains what |
| --- | --- |
| 8.0–9.9 | anyone on the network takes the host, its root or its secrets now, with no login, or any local user becomes root at once: an open Docker socket, an empty password with SSH open, unsigned packages, a setuid file anyone may write |
| 6.6–7.9 | anyone on the network reads or changes its traffic, or a local user becomes root with a known step: plain-HTTP sources, root login over SSH, an exploit ASLR would stop |
| 4.5–6.5 | a neighbour on the link or any local user gains a real foothold: redirects accepted, a kernel module any user can load, secrets readable by every user |
| 3.3–4.4 | an attacker who already has a foothold gets a step further, or the host stops working under load: core dumps of setuid programs, a service port in the ephemeral range |
| 2.0–3.2 | a hardening layer that makes a known attack harder is off: ICMP rate limits, a kernel pointer leak, ASLR weaker than full |
| 1.0–1.9 | a record or a preference is missing and nothing is exposed by it alone: an audit watch, a separate mount, a banner |

Loss of data or service scores on its own scale, the higher of the two
winning:

| Score | What is lost |
| --- | --- |
| 8.0–9.9 | data is being lost now or at the next fault: a failing disk, a degraded array, a critical temperature |
| 6.6–7.9 | the host or its trust breaks soon on its own: a worn-out disk, an expired certificate |
| 4.5–6.5 | data or a service degrades: bad sectors, media errors, a high temperature |
| 3.3–4.4 | the host stops working under load: a full `/boot`, files near their limit |

A rule a standard alone asks for scores what its exposure is worth, not less
for being standard-only. A score never sits at a band’s floor by default: give
it the number its row and its likelihood earn, and two rules about the same
exposure the same number.

## Small rulesets

One ruleset per subject a person thinks of (`ufw.yaml`, `kernel.yaml`,
`fs-protected.yaml`), never one per upstream benchmark. A rule ID is the
ruleset name, a slash and the problem in a few words: `ufw/disabled`.
Each names one of the book’s existing topics (`topic: Network`), so the rule
reference stays a handful of pages; a new topic is for a subject none of them
covers.

## Agnostic by default

Detect a tool by what is on disk: its binary or its configuration file, never
the package manager that installed it. A guard that only one distribution can
answer leaves every other host `unknown`.

Put the guard in the ruleset’s `when`, so a host without the tool answers
`not-applicable` and is never rated:

```yaml
when: {ufw.binary: {minProperties: 1}}
```

A standard asking for the tool itself (`auditd/not-installed`) is a rule over
the binary fact with `expect: {minProperties: 1}`, in the tool’s own ruleset;
that ruleset then carries no guard, and each of its other rules puts the same
guard in its own `when`, so a host without the tool skips them.

A collector that stats a binary globs the usual directories with `*`
(`/usr/*bin/ufw`), since an unmatched glob passes nothing and leaves the
object empty.

## Words

Every text is written for a person reading a terminal, never for a parser.

- The rule ID is the thing, a slash and its state: `ufw/disabled`,
  `kernel-modules/cramfs`.
- `title` is the description: what is wrong, as “thing A is B” or “thing A
  does C”, never the fix: “ufw is installed but switched off”. It names the
  thing first and quotes a name: “Kernel module “can” loads automatically”.
- `message` is what was found: it opens with `{subject}` when the fact has a
  `*`, else with the setting, then says what it is and where.
- `rationale` is the reasoning: why it is bad, in one sentence for a reader
  who is not a specialist, naming what an attacker or an accident gets.
- `fix` is the fix: how to repair it, in a whole sentence with proper
  punctuation. Every literal a person types (a config line, a key, a value,
  a path, a command) sits in typographic quotes, so it never reads as part
  of the sentence: `add “install cramfs /bin/false” to a file ending in
  “.conf” under “/etc/modprobe.d/”`, `run “chmod o-w” on the file`. The
  report adds the full stop. `{got}` and `{suggested}` arrive quoted, so
  they never take quotes of their own; `{field}` does not.
- A fix of more than one move is a list of steps, never one sentence
  joining them with “and” or “then”. Each step is a sentence a reader who
  is not a specialist can follow; what they type goes in a `run:` step and
  what they write in a file in a `lines:` step, each printed alone below the
  step before it, which ends in a colon and names the exact place: “Add these
  lines to “/etc/pam.d/common-auth”, the first before the “pam_unix” line:”,
  never “add X before Y and Z after it”. Quote a step ending in a colon, as
  YAML reads an unquoted one as a key.
- `docs` links the upstream manual of the setting.

## Upstream checks

A rule covering a check of another tool cites the check’s ID, never its code
or wording. A rule may cover a check more broadly or more strictly than its
source does.

| Source | Tag | Reference |
| --- | --- | --- |
| Lynis | `lynis` | `{title: Lynis <ID>, url: "https://cisofy.com/lynis/controls/<ID>/"}` |
| `systemd-analyze security` | `systemd-analyze` | `{title: systemd-analyze security, url}` to its manual |
| a published standard | `<standard>:<control>` | the standard’s own link |

`systemlint check --tags lynis` then runs every rule that covers a Lynis check.

## Tests

Tests pin the mechanics a rule relies on, never the rule itself: a new rule
gets no test of its own. When it needs an op option, a schema keyword or a
judgement no test covers yet, that mechanic gets a test at its edge, with
neutral facts, in the crate that owns it (`x-version` inside `anyOf` in
`tests/judge.rs`, a spaced `words` separator in `words.rs`). Run the rule
against a real capture before shipping it.
