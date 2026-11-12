<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Rules, rulesets and compliance

`systemlint lint` judges a facts document with declarative rules;
`systemlint comply <standard>` groups the same judgement by the controls of one
standard. Both read a saved document (`lint facts.yaml`, `lint -` for stdin) or
collect one first (`lint`, `lint --root DIR`).

## A rule

A rule holds one fact to a JSON Schema (draft 2020-12):

```yaml
apt/https:
  fact: apt.sources.*.uri
  when: {apt.sources.*.enabled: true}
  expect: {pattern: "^https://"}
  severity: warning
  message: "{subject} fetches over {got}"
  fix: switch {subject} to https://
  docs: https://wiki.debian.org/SourcesList
  tags: [apt, cis-ubuntu-26.04:1.2.1.2]
```

| Key | Meaning |
| --- | --- |
| `fact` | the fact path; a `*` segment binds one subject per key or array index |
| `expect` | the JSON Schema the fact must satisfy, `x-version` included |
| `when` | a guard: a map is AND, a list of maps is OR; each entry is a constant to equal or a schema to satisfy |
| `severity` | `error`, `warning`, `info`, `hint` or `off`; `warning` when absent |
| `score` | a number from 0.0 to 9.9, or a curve of `[value, score]` points read against the fact’s number |
| `message` | the finding’s sentence, with `{got}`, `{field}`, `{fact}` and `{subject}` filled in |
| `fix` | how to fix it, with the same placeholders |
| `docs` | a link |
| `tags` | slugs; a tag with `:` names a control of a standard |

A fact path is dotted (`os.release.VERSION_ID`), or a JSON Pointer when it
starts with `/`, for keys holding dots (`/files/~1etc~1ssh~1sshd_config.d~1a.conf/mode`).

### Subjects

The `*`s of a path bind subjects: the first `*` of every `when` path takes the
key the first `*` of `fact` bound, and so on, so every condition holds on the
same source or unit, never on any. A `when` path may not hold more `*`s than
`fact`. The checks of a rule are one per subject; a subject is its bound keys,
joined by a comma and a space.

### Outcomes

Each rule answers one outcome per subject:

| Outcome | When |
| --- | --- |
| `pass` | the fact satisfies `expect` |
| `fail` | it does not; the check carries a severity, a score and the message |
| `skip` | the `when` guard is false |
| `unknown` | a fact in `when` or `fact` is absent; the reason names the collector that should have produced it and how it finished |

`when` follows three-valued logic: one false entry makes a map false even when
another is absent, and one true map makes a list true. A collection absent
before the first `*` is one `unknown`; a present but empty one gives no check,
since nothing in it can fail. A `*` also binds every key a collector’s `into`
places at that point, so a collector that failed under `files.*` is one
`unknown` subject beside the present ones, never a gap. An unprivileged run, an
older collector or a failed probe therefore never reads as a pass.

### Versions

`x-version` orders versions a plain schema cannot:

```yaml
expect: {x-version: {scheme: deb, min: "1:9.6p1-3ubuntu13.3", below: "1:10"}}
```

The fact must be a string at or above `min` and below `below`, either optional,
compared as dpkg does. `deb` is the one scheme so far.

### Scores

Scores and levels share spiderlint’s bands: hint 0.0–0.9 (base 0.5), info
1.0–3.2 (2), warning 3.3–6.5 (5), error 6.6–9.9 (8). A number sets the score and
its band sets the level; a curve computes the score from the fact’s number and
may cross bands; a level alone gives its base score. A level written over a
score in a ruleset entry pins the score inside that band.

## Rulesets

A ruleset is a YAML file named after itself, shipped in
`../share/systemlint/rulesets/` beside the binary or found in a
`lint.directories` entry, under the same ownership and permission checks as
plugins. A config may also hold rulesets inline under `lint.rulesets`; a name
used twice is refused.

```yaml
description: Stricter than the shipped rules
extends: [recommended]
rules:
  apt/https: error
  os/supported: {expect: {enum: ["26.04"]}}
  ssh/legacy: off
  sysctl/kptr-restrict: 7.5
```

An entry with `fact` defines a rule; a rule is defined in one ruleset only. Any
other entry overrides the rule by ID, defined in a parent or anywhere else: a
level, a score, or a partial rule whose keys win and whose `expect` merges
keyword by keyword, dropping the inherited `message`, which may state the old
bounds. `extends` takes rulesets, rule IDs and tag globs, flattened depth first.

## Selecting rules

`--tags`, or `lint.tags` in the config, is one comma list of selectors. Each
names a ruleset, or is a glob (`*` any run of characters, `/` and `:`
included; `?` one) over rule IDs and tags. The list is a union: a ruleset
brings its overrides, an ID or tag pick brings the plain rule unless a ruleset
already brought it. `!x` removes what `x` names; `off` rules drop out. With no
selector every rule runs. A selector matching nothing is an error.

```sh
systemlint lint facts.yaml --tags 'strict,!experimental'
systemlint lint facts.yaml --tags 'cis-ubuntu-26.04:5.2.*'
```

## Waivers

```yaml
lint:
  waivers:
    - {rule: apt/*, subject: /etc/apt/sources.list.d/*, reason: the mirror moves in December, until: 2026-12-31}
```

A waiver covers the failures of the rules its `rule` glob matches, on every
subject or those its `subject` glob matches, through the `until` day. Both
`reason` and `until` are required. A waived failure is listed but counts toward
no exit code; after `until` it is a finding again, marked as expired. Waiver
expiry is the only judgement that reads the clock at lint time.

## Lint output and exit codes

`--format human` prints one line per failure and per unknown, one `not run` line
per reason a collector was skipped (no root, no `--image-config`, live-only under
`--root`) naming its collectors and rules, then the counts;
`--format json` prints the document’s `meta`, every check, passes included, and
the counts; `--format sarif` and `--format textfile` are described in
[Outputs](outputs.md). `--output PATH` writes the report atomically instead of
printing it. `--fail-on` (`lint.fail-on`) takes `error`, the default, `warning`,
`info`, a score from 0.1 to 9.9, or `never`; a hint never fails a run.

| Code | `lint` | `comply` | `facts` |
| --- | --- | --- | --- |
| 0 | no failure at `--fail-on` | compliant | every collector ended `ok` or `skipped` |
| 1 | a failure at `--fail-on` | non-compliant | a collector ended `error`, so the document is partial |
| 2 | bad arguments, config, facts document, or a ruleset or catalog file invalid or refused | the same | bad arguments or config, or the document could not be written |
| 3 | — | indeterminate | — |
| 4 | a plugin or collector file was refused | the same, when otherwise compliant | the same, when no collector ended `error` |

## Compliance

`systemlint comply <standard>` takes the rules tagged `<standard>:<control>`,
filtered by `lint.tags` when set, and answers per control:

| Verdict | When |
| --- | --- |
| `non-compliant` | a rule of the control fails, unwaived |
| `indeterminate` | none fails, but one is `unknown`, or no rule covers the control |
| `compliant` | every check passes or is skipped |
| `manual` | the catalog marks the control manual and no rule covers it |

The standard is non-compliant when any control is, else indeterminate when any
control is or none exists, else compliant.

A catalog, `<standard>.yaml` in `../share/systemlint/standards/` beside the
binary or in a `comply.directories` entry, lists every control, adds the
display name, and gives coverage:

```yaml
name: CIS Ubuntu Linux 26.04 LTS Benchmark
controls:
  - {id: "5.2.10", title: Ensure SSH root login is disabled}
  - {id: "1.1.1", title: Ensure the bootloader password is set, manual: true}
```

With a catalog, an uncovered control is indeterminate. Without one, the verdict
carries a note: compliant only means no tagged rule failed.

## Differences from spiderlint

The format starts from spiderlint’s declarative rules and differs where OS
facts need it:

- a `*` in `fact` binds subjects of any collection, and `when` paths share them,
  where spiderlint knows only `site.origins.*` and `site.hosts.*`;
- `when` takes a list of maps as OR, and an absent fact answers `unknown`
  rather than skipping the rule;
- a fact path may be a JSON Pointer, as file paths hold dots;
- `x-version` adds Debian version ordering to the schema;
- rules carry `tags`, and selectors mix rulesets, IDs and tags, with `!` to
  remove, replacing `--exclude-rules` and the per-level override flags;
- a waiver exempts a rule on a subject until a day;
- `{got}` quotes any string, without spiderlint’s character count, which
  measures web titles;
- `fix` placeholders are the finding’s `{subject}`, `{got}`, `{field}` and
  `{fact}`, not the host or origin of a URL;
- exit code 3 means an indeterminate compliance answer, not a failed fetch, and
  4 a refused plugin or file;
- there are no `unique`, `scope`, `hints` or built-in rules.
