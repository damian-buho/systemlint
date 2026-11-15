<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Rules and rulesets

`systemlint check` judges a facts document with declarative rules. It reads
a saved document (`check facts.yaml`, `check -` for stdin) or collects one first
(`check`, `check --root DIR`).

## A rule

A rule holds one fact to a JSON Schema (draft 2020-12):

```yaml
apt/https:
  title: Source fetches over plain HTTP
  fact: apt.sources.*.uri
  when: {apt.sources.*.enabled: true}
  expect: {pattern: "^https://"}
  severity: warning
  score: 6.0
  message: "{subject} fetches over {got}"
  fix: switch the source to https://
  docs: https://wiki.debian.org/SourcesList
  rationale: anyone on the path can swap a package or hold back an update
  references:
    - {title: "SourcesList", url: "https://wiki.debian.org/SourcesList"}
  tags: [apt, cis-ubuntu-26.04:1.2.1.2]
```

| Key | Meaning |
| --- | --- |
| `title` | a short name for the problem, the heading of the rule’s block in the human report |
| `fact` | the fact path; a `*` segment binds one subject per key or array index |
| `expect` | the JSON Schema the fact must satisfy, `x-version` included |
| `facts` | instead of `fact` and `expect`: `all`, `any` or `none` over a list of `{fact, expect}`, see [Several facts](#several-facts) |
| `keys` | a JSON Schema the key of the fact’s last `*` must satisfy, or it is no subject, see [Subjects](#subjects) |
| `when` | a guard: a map is AND, a list of maps is OR; each entry is a constant to equal or a schema to satisfy |
| `severity` | `error`, `warning`, `info`, `advice` (a tuning hint, below `info`) or `off`; `warning` when absent |
| `score` | a number from 0.0 to 9.9, or a curve of `[value, score]` points read against the fact’s number |
| `message` | the finding’s sentence, with `{got}`, `{field}`, `{fact}` and `{subject}` filled in |
| `fix` | how to fix it, with the same placeholders; the human report lists the subjects above it, so a fix that leaves `{subject}` out reads once for all of them |
| `remedy` | a change `systemlint fix` makes to the subject path, see [Remedies](#remedies) |
| `suggest` | `{fact, otherwise}`: the fact, bound like `when`, whose value fills `{suggested}` in `message` and `fix`, and the words used when it is absent or empty |
| `docs` | a link |
| `rationale` | why the rule matters, a `Why:` line under the title of its human block, and in JSON and SARIF `help` |
| `references` | a list of `{title, url}` sources; an override adds to the list instead of replacing it |
| `tags` | slugs; a tag with `:` names a control of a standard |
| `manual` | `true` for a procedure a person follows: no `fact` or `expect`, the steps in `rationale` |
| `unique` | `true` to fail every subject whose fact value another subject holds too, see [Unique values](#unique-values); `expect` may then be left out |

A fact path is dotted (`os.release.VERSION_ID`), or a JSON Pointer when it
starts with `/`, for keys holding dots (`/files/~1etc~1ssh~1sshd_config.d~1a.conf/mode`).

### Subjects

The `*`s of a path bind subjects: the first `*` of every `when` path takes the
key the first `*` of `fact` bound, and so on, so every condition holds on the
same source or unit, never on any. A `when` path may not hold more `*`s than
`fact`. The checks of a rule are one per subject; a subject is its bound keys,
joined by a comma and a space (`path, /usr` for `files.*.*.uid`). The reports
and `{subject}` show only its last key (`/usr`), the one that names the thing;
`--format json` and `sarif` keep every key, and a waiver’s `subject` matches
either form.

`keys` filters subjects by the key of the fact’s last `*`, the one `{subject}`
shows, judged as a JSON Schema over that string:

```yaml
fact: files.ssh-user.*.mode
keys: {not: {pattern: "\\.pub$|^known_hosts$"}}
expect: {pattern: "^0[0-7]00$"}
```

A key it refuses binds no subject at all, so no check, not `skip`, and no
`when` reads it; when it admits no key, the rule has no checks. A subject cut
short by an absent fact keeps its `unknown` check, since its last key belongs
to an earlier `*`.

### Several facts

`facts` judges one subject over several facts, under different roots:

```yaml
ssh/root-login:
  title: Root may log in over SSH
  facts:
    any:
      - {fact: sshd.accounts.*.permitrootlogin, expect: {const: "no"}}
      - {fact: apt.installed, expect: {not: {required: [openssh-server]}}}
```

The first fact binds the subjects, and every other one takes its keys as a
`when` path does, so it may not hold more `*`s; when the first fact’s collection
is absent, it is one `unknown` fact and the facts without `*` are judged beside
it, so the rule above passes on a host without `openssh-server`. `all` passes when every fact
satisfies its schema, `any` when one does, `none` when none does, in the same
three-valued logic as `when`: an absent fact makes `all` unknown unless another
fails, and `any` unknown unless another passes. A failure reports the first
fact that decides it, in `{fact}`, `{got}` and `{field}`; under `none` that is
the first fact that holds. Facts under one parent need no `facts`: a schema over
the parent (`anyOf`) reads them, but an absent key there only fails the schema
and never answers `unknown`.

### Unique values

`unique: true` compares the fact across the rule’s subjects, after `keys`,
`when` and `expect` have judged each one:

```yaml
accounts/uid-unique:
  fact: accounts.passwd.*.uid
  unique: true
  message: "{subject} shares uid {got} with {others}"
```

Every subject that passed and holds a value another passing subject holds
fails, and `{others}` names the rest, joined by a comma. A subject that is
skipped, unknown, failed by `expect` or left out by `keys` takes no part, so
it never makes another fail. The fact needs a `*`, and `facts` takes no
`unique`.

### Outcomes

Each rule answers one outcome per subject:

| Outcome | When |
| --- | --- |
| `pass` | the fact satisfies `expect` |
| `fail` | it does not; the check carries a severity, a score and the message |
| `skip` | the `when` guard is false |
| `unknown` | a fact in `when` or `fact` is absent; the reason names the collector that should have produced it and how it finished |
| `not-applicable` | the `when` of a ruleset that defines or brings the rule is false; one check per rule, without a subject |
| `manual` | the rule is `manual`; one check, which a person reviews |

A ruleset’s `when` is checked first, so a rule outside its target host answers
`not-applicable` and is never judged or rated; `skip` stays for a subject its own
`when` leaves out. A `manual` rule ignores its own `when`.

`when` follows three-valued logic: one false entry makes a map false even when
another is absent, and one true map makes a list true. A collection absent
before the first `*` is one `unknown`, or one `skip` when the rule’s `when`
over its parent is false (`when: {mounts: {required: [active]}}` for a
collection only a live run fills); a present but empty one gives no check,
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
compared in the order `scheme` names:

| Scheme | Order of | Edges |
| --- | --- | --- |
| `deb` | dpkg | epoch, `~` before the end |
| `semver` | SemVer 2.0.0 precedence | prerelease before release, `+build` ignored, no `v` prefix |
| `rpm` | rpm’s `rpmverCmp` | epoch, `~` before the end, `^` after it, a missing release first |
| `apk` | apk-tools | `_alpha`…`_rc` before the release, `_cvs`…`_p` and `-rN` after it |
| `pacman` | `alpm_pkg_vercmp` | epoch, a trailing letter run (`1.0rc`) before the release, a release compared only when both carry one |

A `min` or `below` the scheme cannot read fails the ruleset load; a fact it
cannot read fails the rule.

### Scores

Scores and levels share spiderlint’s bands: advice 0.0–0.9 (base 0.5), info
1.0–3.2 (2), warning 3.3–6.5 (5), error 6.6–9.9 (8). A number sets the score and
its band sets the level; a curve computes the score from the fact’s number and
may cross bands; a level alone gives its base score. A level written over a
score in a ruleset entry pins the score inside that band.

### Rating

A run is graded as spiderlint grades a crawl, on the same constants
(`src/report/rating.ts` there, `report::rate` here): S with no failure;
otherwise the share of judged checks kept, each failure costing
`(score / 5.0)²`, against the floors A 0.9, B 0.7, C 0.6, D 0.4, E 0.2, else F;
any error caps the grade at B. Judged checks are passes and failures; waived
failures, unknowns, skips, `not-applicable` and `manual` checks stay out, and a run with none gets no grade. The
grade closes the human report and is `rating` in JSON, the run’s
`properties.rating` in SARIF and `systemlint_rating` in the textfile.

## Rulesets

A ruleset is a YAML file named after itself, shipped in
`../share/systemlint/rulesets/` beside the binary or found in a
`check.directories` entry, under the same ownership and permission checks as
plugins. A config may also hold rulesets inline under `check.rulesets`; a name
used twice is refused.

```yaml
description: Stricter than the shipped rules
tags: [default]
extends: [recommended]
when: {os.release.ID: {const: ubuntu}}
rules:
  apt/https: error
  os/supported: {expect: {enum: ["26.04"]}}
  ssh/legacy: off
  kernel/kptr-restrict: 7.5
```

An entry with `fact` defines a rule; a rule is defined in one ruleset only. Any
other entry overrides the rule by ID, defined in a parent or anywhere else: a
level, a score, or a partial rule whose keys win and whose `expect` merges
keyword by keyword, dropping the inherited `message`, which may state the old
bounds. `extends` takes rulesets, rule IDs and tag globs, flattened depth first;
a ruleset name also brings the rules tagged with it, as a selector does.
`tags` go to every rule the ruleset defines, before the rule’s own, so the
shipped rulesets carry `tags: [default]` once rather than on each rule. A
rule’s own `!tag` drops an inherited one, so `tags: ['!default']` keeps a
rule a standard asks for out of the default run, and an override’s `!tag`
does the same to the rule it overrides.

`when` takes the form a rule’s does, without `*`, since a ruleset has no
subject. It guards every rule the ruleset defines, however it is selected, and
every rule it brings through `extends` or overrides; a rule answers
`not-applicable` when any such `when` is false, `unknown` when one is absent.
A fact no collector produces is false there, so a ruleset over facts only an
optional collector writes (`when: {probes: {minProperties: 1}}`) does not
apply until one is configured.
A false schema over an object names in its reason only the properties the
schema reads (`when os.release.ID is “fedora” and os.release.ID_LIKE is none`).

### Variables

A ruleset declares `vars`, and `${name}` fills the strings of its own entries’
`expect`, `when` and `message`, and of its ruleset `when`, as it loads:

```yaml
vars:
  ntp: {default: pool.ntp.org, from-env: NTP_SERVER}
  max-days: {default: 90}
rules:
  time/server: {fact: ntp.server, expect: {const: "${ntp}"}, message: "use ${ntp}"}
  login/max-days: {fact: login.max-days, expect: {maximum: "${max-days}"}}
```

A value comes from the first that sets it: `--var NAME=VALUE`, `--vars FILE` (a
YAML map), the environment variable `from-env` names, `check.vars`, then
`default`. A string that is only `${name}` takes the value with its type, so
`maximum` above gets the number 90; a text value from a flag or the environment
takes the type of a number or boolean default, and fails when it is not one.
`$${` writes a literal `${`. Substitution is static: no expressions, and no
environment read unless `from-env` names it. The load fails, naming the var and
the ruleset, when a var has no value and no default, when an entry names a var
its ruleset does not declare, or when a value names a var no ruleset declares.

## Selecting rules

`--tags`, or `check.tags` in the config, is one comma list of selectors. Each
is a glob (`*` any run of characters, `/` and `:` included; `?` one) over rule
IDs and tags; a selector naming a ruleset also picks that ruleset’s rules, so
`ssh` brings the `ssh` ruleset and every rule tagged `ssh`. The list is a union: a ruleset
brings its overrides, an ID or tag pick brings the plain rule unless a ruleset
already brought it. `!x` removes what `x` names; `off` rules drop out. With no
selector, or only `!` ones, the rules tagged `default` run: every shipped
ruleset carries it, an opinionated one (performance, a latency profile) does
not. A selector matching nothing is an error.

`--tags performance` replaces the default, `--tags default,performance` extends
it, `--tags '*'` runs every rule, and `check.tags` sets a site’s own default.
A run on the default prints one stderr line naming what it left out, per
defining ruleset, so a rule of your own without `default` never vanishes
silently (`-q` drops it):

```text
12 rules not selected: containers (3), performance (9). Name them in --tags to run them.
```

```sh
systemlint check facts.yaml --tags 'default,performance'
systemlint check facts.yaml --tags 'strict,!experimental'
systemlint check facts.yaml --tags 'cis-ubuntu-26.04:5.2.*'
```

## Remedies

A rule may name one remedy beside its prose `fix`, which `systemlint fix`
applies to each failing subject that is an absolute path:

```yaml
files/world-writable:
  fix: chmod o-w the file
  remedy: {chmod: o-w}
```

| Remedy | Change |
| --- | --- |
| `chmod` | clears the permission bits a symbolic `who-perms` list names, such as `g-wx,o-rwx`; `+` and `=` are refused |
| `chown` | `0` only: gives the file to root, leaving its group |
| `chgrp` | `0` only: gives the file to the root group, leaving its owner |
| `disable-line` | `authorized-keys` or `apt-list` (one-line sources, never a deb822 paragraph): comments out the subject line, named `path:line`, of a syntax where every line grants access |

A remedy only takes access away, so a ruleset from an untrusted
`.systemlint.yaml` can never hand a file to a user. A line is changed only
when it still hashes to the `line-sha256` its facts carry, so a file edited
since the lint fails that change, naming the line, instead of losing another. A line remedy never
disables the last line its owner has, such as an account’s only authorized key:
`fix` keeps it, prints `Kept <path:line>`, and exits 1 until another is added. An override that sets its
own `fact` or `facts` drops the inherited remedy.

`systemlint fix` lints the live host, or with `--root DIR` a root filesystem
such as an image being built, prints each change as its command on stdout,
naming the path under that root, and asks before making them when stdin is a terminal. `--dry-run`
stops after the list, `--force` skips the question, and `--no-input` fails
naming `--force` instead of asking. Each file is opened again right before its
change, refusing a symbolic link or a special file, and a line such as
`/etc/shadow: 0644 → 0640` follows each change made; a change already made
is skipped, so a re-run after a crash finishes the rest. `fix.enabled: false`
in the configuration turns the command off. Exit codes: 0 every change made or
none needed, 1 a change failed or was declined, 2 a change needs `--force`.

## Waivers

```yaml
check:
  waivers:
    - {rule: apt/*, subject: /etc/apt/sources.list.d/*, reason: the mirror moves in December, until: 2026-12-31}
```

A waiver covers the failures of the rules its `rule` glob matches, on every
subject or those its `subject` glob matches, through the `until` day. Both
`reason` and `until` are required. A waived failure is listed but counts toward
no exit code; after `until` it is a finding again, marked as expired. Waiver
expiry is the only judgement that reads the clock at lint time.

## Check output and exit codes

`--format human` prints one block per rule, an empty line after each: a
`Not run` block per reason a collector was skipped (no root, a refused read,
live-only under `--root`) with its rules wrapped under it, none for an opt-in the
run did not ask for (`--image-config`, `--network`, `--containers`), which only the counts show, a
`Not read` block per path a collector could not read (still `unknown` in the
counts and every machine format), then a `Not applicable` block per ruleset reason with its rules wrapped under it,
`Unknown`, `Manual` (with the `Why:` procedure) and `Waived` blocks, then the failures, lowest score first, so the
worst sits just above the rating and counts
(`Rating B · 5 errors, 9 warnings, 0 info · 577 pass, 24 not run, 21 skip`).
A failure block opens with the level, the highest score of the rule, its ID and
`title`, then a `Why:` line with the `rationale`, lists each subject on its own dash line with the value it failed on, and
ends with one `Fix:` line, or a fix under each subject when they differ. A rule
with a remedy puts its command under each subject as a `Run:` line with no full
stop, so it pastes into a shell, and closes with the `systemlint fix --tags`
call that makes every change; `-v` adds a `See:` line per reference.
Failures that name each other, the two sides of `apt/duplicate`, list as one
problem. `--plain` prints one tab-separated line per finding instead: outcome
or level, score, rule, subject, message, fix, the message without the subject
it opens with, a rule not run on one `not-run` line per reason whatever its
subjects, and the counts after `rating` and the grade. Subject, `Why:` and `Fix:` lines, and the last two fields of every
line, end with a full stop unless they already end a sentence, and
the last field opens with a capital, so a screen reader reading the whole report
pauses between them. Colour marks only the level word
and rule IDs, so the words still carry the meaning; `--color auto`, the
default, turns it off under `NO_COLOR`, `SYSTEMLINT_NO_COLOR`, `TERM=dumb` or
when stdout is not a terminal, and `FORCE_COLOR` turns it on.
`--format json` prints the document’s `meta`, every check, passes included, and
the counts; `--format sarif` and `--format textfile` are described in
[Outputs](outputs.md). `-o PATH` (`--output`) writes the report atomically instead of
printing it, then one stderr line with its number of findings, which `-q` drops. `--fail-on` (`check.fail-on`) takes `error`, the default, `warning`,
`info`, `advice`, a score from 0.1 to 9.9, or `never`; advice fails a run
only under `--fail-on advice`.

| Code | `check` | `facts` |
| --- | --- | --- |
| 0 | no failure at `--fail-on` | every collector ended `ok` or `skipped` |
| 1 | a failure at `--fail-on` | a collector ended `error`, so the document is partial |
| 2 | bad arguments | the same |
| 4 | a plugin or collector file was refused | the same, when no collector ended `error` |
| 5 | the config or a ruleset is unreadable, invalid or refused | the config is unreadable or invalid |
| 6 | the facts document or `--root` can’t be read | `--root` can’t be opened |
| 7 | `--output` or stdout can’t be written | the same |
| 70 | the system gave no random hash key | the same |
| 130 | Ctrl-C: `Interrupted, stopping plugins…`, the running plugins killed | the same |
| 101 | a crash: one line names the report saved under `$XDG_STATE_HOME/systemlint/` (`~/.local/state/systemlint/`) and a pre-filled issue link | the same |
| 141 | stdout closed early (`systemlint facts \| head`): the run ends silently on `SIGPIPE`, which a shell reports as 141 | the same |

## Differences from spiderlint

The format starts from spiderlint’s declarative rules and differs where OS
facts need it:

- a `*` in `fact` binds subjects of any collection, and `when` paths share them,
  where spiderlint knows only `site.origins.*` and `site.hosts.*`;
- `when` takes a list of maps as OR, and an absent fact answers `unknown`
  rather than skipping the rule;
- a fact path may be a JSON Pointer, as file paths hold dots;
- `x-version` adds deb, SemVer, rpm, apk and pacman version ordering to the schema;
- rules carry `tags`, and selectors mix rulesets, IDs and tags, with `!` to
  remove, replacing `--exclude-rules` and the per-level override flags;
- a waiver exempts a rule on a subject until a day;
- `{got}` quotes any string, without spiderlint’s character count, which
  measures web titles;
- `fix` placeholders are the finding’s `{subject}`, `{got}`, `{field}` and
  `{fact}`, not the host or origin of a URL;
- exit code 4 means a refused plugin or file, not a failed fetch;
- `unique: true` sits beside `fact` and fails each subject that shares a value,
  where spiderlint’s `unique: <fact>` gives one finding per value, so a waiver
  or SARIF fingerprint still names one subject;
- there are no `scope`, `hints` or built-in rules; `advice` replaces the `hint` level.
