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
  fix: switch the source to “https://”
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
| `expect` | the JSON Schema the fact must satisfy, `x-version` and `x-cel` included |
| `facts` | instead of `fact` and `expect`: `all`, `any` or `none` over a list of `{fact, expect}`, see [Several facts](#several-facts) |
| `keys` | a JSON Schema the key of the fact’s last `*` must satisfy, or it is no subject, see [Subjects](#subjects) |
| `when` | a guard: a map is AND, a list of maps is OR; each entry is a constant to equal or a schema to satisfy |
| `severity` | `error`, `warning`, `info`, `advice` (a tuning hint, below `info`) or `off`; `warning` when absent |
| `score` | a number from 0.0 to 9.9, or a curve of `[value, score]` points read against the fact’s number |
| `message` | the finding’s sentence, with `{got}`, `{field}`, `{fact}` and `{subject}` filled in, and each `{facts.PATH}` by the fact PATH names, bound like `when` (a list of port ranges spelled as sysctl does, `22,8000-8080`), `none` when absent; `fix` fills the same, absent as nothing |
| `unit` | `bytes` or `count`: what `{got}` measures, so the human report prints it as a quantity (`2 GiB`, `12,345`) in the locale `LC_ALL`, `LC_NUMERIC` or `LANG` names, with no grouping in C or POSIX; JSON, SARIF, plain and textfile keep the number |
| `fix` | how to fix it, with the same placeholders: a sentence, or a list of steps, each a sentence, a `{run: command}` or `{lines: [line, …]}`, which the human report numbers and prints each command and file line of alone below its step; JSON and SARIF keep the list; the human report lists the subjects above it, so a fix that leaves `{subject}` out reads once for all of them |
| `remedy` | a change `systemlint fix` makes to the subject path, see [Remedies](#remedies) |
| `fixes` | a list of `{keys, when, fix}` choices tried in order: the first whose `keys` admits the subject’s key and whose `when`, bound like the rule’s, holds gives that subject its `fix`, else the rule’s `fix` applies; a fact a `when` finds absent passes to the next choice, and a choice with neither `keys` nor `when` is refused |
| `suggest` | `{fact, otherwise}`: the fact, bound like `when`, whose value fills `{suggested}` in `message` and `fix`, and the words used when it is absent or empty |
| `docs` | a link |
| `rationale` | why the rule matters, a `Rationale:` line after the subjects of its human block, and in JSON and SARIF `help` |
| `references` | a list of `{title, url}` sources; an override adds to the list instead of replacing it |
| `tags` | slugs; a tag with `:` names a control of a standard |
| `manual` | `true` for a procedure a person follows: no `fact` or `expect`, the steps in `rationale` |
| `unique` | `true` to fail every subject whose fact value another subject holds too, see [Unique values](#unique-values); `expect` may then be left out |
| `same` | a fact, bound like `when`, the rule’s fact must equal, its value in `{same}`; `expect` may then be left out, see [Joined facts](#joined-facts) |
| `conflicts` | IDs of rules of another standard this rule contradicts, each naming this one back, else the rulesets are refused; while both are selected, every check of either answers `conflict` and none counts, see [Check output](#check-output-and-exit-codes); only a definition takes it |
| `folds` | IDs of looser rules on the same setting, such as a standard’s stricter value: while both are selected, a failure of this rule drops their failing check on the same subject, or any of theirs that has no subject, so one problem prints once; a waived failure folds nothing; only a definition takes it |

A fact path is dotted (`os.release.VERSION_ID`), or a JSON Pointer when it
starts with `/`, for keys holding dots (`/files/~1etc~1ssh~1sshd_config.d~1a.conf/mode`).
A `{path}` segment takes its key from the value of another fact, see
[Joined facts](#joined-facts).

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

### Joined facts

A `{path}` segment in a `when`, `facts`, `suggest` or `same` path reads its
key from the string or number at `path`, bound to the rule’s subject as a
`when` path is; `same` then compares two collections keyed differently:

```yaml
home/not-owned:
  fact: accounts.passwd.*.uid
  same: home.directories.{accounts.passwd.*.home}.uid
  when:
    home.directories.{accounts.passwd.*.home}.kind: directory
  message: "{subject}’s home is owned by uid {same}, not {got}"
```

Each account looks its home up by the path its passwd entry names, dots in
it included. When the named fact is absent, or neither a string nor a number,
the check is `unknown` and its reason names that fact. `same` fails a fact
that differs from the joined one and is `unknown` while that one is absent;
it takes no `facts`. The rule’s own `fact` binds the subjects, so it takes no
`{path}`. In a YAML flow map, quote such a path, since braces end the map there.

A `{~path}` segment joins the other way, by glob: `path` holds one `*`, and
the segment reads the first key there whose string, or list of strings, holds
an absolute glob matching the subject (the rule’s last `*`), as glob(3)
matches, `*` and `?` within one component and never a leading dot:

```yaml
logs/file-mode:
  fact: logs.files.*.mode
  suggest: {fact: 'logrotate.{~logrotate.*.names}.path', otherwise: its logrotate stanza}
  fix: set 0640 on the “create” line in {suggested}
```

A log file finds the logrotate stanza whose names match it. With no match,
`suggest` takes its `otherwise` and `same` is `unknown`, while a `when` judges
`null`, so `not: {type: object}` holds for a log no stanza names; the map at
the `*` absent is `unknown` everywhere.

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

### Expressions

`x-cel` holds a [CEL](https://github.com/google/cel-spec) expression that must
be true, for what a schema cannot say: one fact against another, or
arithmetic. It works wherever a schema does (`expect`, a `facts` entry, `when`,
`keys`):

```yaml
fact: sysctl.settings.vm.dirty_background_ratio
expect: {x-cel: "self < facts.sysctl.settings.vm.dirty_ratio"}
```

| Name | Holds |
| --- | --- |
| `self` | the value the schema judges, a key under `keys` |
| `facts` | the whole facts document |
| `vars` | the ruleset’s vars, typed; `${…}` is never filled inside an expression |
| `bound` | the keys the rule’s `*`s bound, in order: `bound[0]` |

A JSON integer is a CEL `int`, a fraction a `double`, and CEL never mixes the
two: `double(self) * 0.9` compares with a share, `self * 2` with an integer.
An expression that cannot decide (a missing key, a value of the wrong type, a
result that is not `true` or `false`, more than 10 000 iterations of `all`,
`exists`, `map` or `filter`) makes the check `unknown`, naming the expression,
never a failure; `has(facts.a.b)` asks for a key without that. An expression
longer than 1000 characters, one that does not parse, or one reading a name
other than these fails the ruleset load. Keep to a schema keyword where one
says it; CEL is for the second fact.

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
`topic` names the page of `systemlint rules --format markdown` that lists the
ruleset’s rules (`topic: Logging and auditing`); a ruleset without one is listed
under `Other`.

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
`expect`, `when`, `message` and `fix`, and of its ruleset `when`, as it loads:

```yaml
vars:
  ntp: {default: pool.ntp.org, from-env: NTP_SERVER}
  max-days: {default: 90, minimum: 1, maximum: 365}
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
A number var declares its inclusive `minimum` and `maximum`, and the load fails
on a value outside them, so no setting reaches a rule’s arithmetic unchecked.

## Selecting rules

`--tags`, or `check.tags` in the config, is one comma list of selectors. Each
is a glob (`*` any run of characters, `/` and `:` included; `?` one) over rule
IDs and tags; a selector naming a ruleset also picks that ruleset’s rules, so
`ssh` brings the `ssh` ruleset and every rule tagged `ssh`. The list is a union: a ruleset
brings its overrides, an ID or tag pick brings the plain rule unless a ruleset
already brought it, in any order. A ruleset a selector matches by one of its
`tags` (a bare run matching `default`, `all` matching every ruleset) applies its
overrides to the rules picked, bringing no other rule, so a `site` ruleset tagged
`default` changes a bare `check`; a named ruleset beats one its tags select, and
of two its tags select the first by name wins. A rule a `default` ruleset leaves out with `'!default'`,
one a standard alone asks for, is picked only by its exact ID or by a
standard’s tag: a control (`cis-ubuntu-26.04:5.2.*`) or a tag its standard
brings (`cis`), never by a ruleset name, another tag or an ID glob:
`kernel-modules/*` is the default rules of `kernel-modules`,
`kernel-modules/*,cis` adds the CIS ones, so `fix` never
changes what a default `check` did not show. `!x` removes everything `x`
matches, those rules included; `off` rules drop out. With no
selector, or only `!` ones, the rules tagged `default` run: every shipped
ruleset carries it, an opinionated one (performance, a latency profile) does
not. A selector matching nothing is an error.

`--tags performance` replaces the default, `--tags default,performance` extends
it, `--all` (`--tags all`, or `'*'`, and not with `--tags`; `fix` takes it too) runs every rule, the standard-only ones included,
and `check.tags` sets a site’s own default. No ruleset, rule ID or tag may be
named `all`.

Selecting every rule also selects both sides of each conflict.
`--prefer GLOB` (comma-separated or repeated, `check.prefer` in the config)
settles them: in each set of selected rules naming each other in `conflicts`,
when exactly one rule holds a tag the glob matches, it stays and the others
are left out, as if not selected (`-v` logs each). A set where two rules
match, or none does, stays one `Conflict` block. `--tags 'all,!stig-*'` is no
substitute: it also removes every rule that carries a STIG tag beside a CIS
one.
A run on the default counts what it left out in a `Not selected` summary
row, so a rule of your own without `default` never vanishes silently; `-v`
logs the count per defining ruleset:

```text
Not selected      12, run them by naming their ruleset in --tags
```

```sh
systemlint check facts.yaml --tags 'default,performance'
systemlint check facts.yaml --tags 'strict,!experimental'
systemlint check facts.yaml --tags 'cis-ubuntu-26.04:5.2.*'
systemlint check facts.yaml --tags all --prefer cis
```

A ruleset’s `standards` map gives each standard the plain tags its control
tags bring, so every rule tagged `cis-ubuntu-26.04:5.2.1` also carries `cis`,
`ubuntu` and `ubuntu-26.04`, and `--tags cis` or `--prefer nist` names a
standard; a standard the map leaves out brings its own name. The shipped
`standards` ruleset holds the map, and two rulesets giving one standard
different tags fail the load:

```yaml
standards:
  cis-ubuntu-26.04: [cis, ubuntu, ubuntu-26.04]
  nist-sp-800-63b-4: [nist]
```

## Remedies

A rule may name one remedy beside its prose `fix`, which `systemlint fix`
applies to each failing subject that is an absolute path, for `mask` a unit, and for `set-key` its one file:

```yaml
files/world-writable:
  fix: run “chmod o-w” on the file
  remedy: {chmod: o-w}
```

| Remedy | Change |
| --- | --- |
| `chmod` | clears the permission bits a symbolic `who-perms` list names, such as `g-wx,o-rwx`; `+` and `=` are refused |
| `chown` | `0` only: gives the file to root, leaving its group |
| `chgrp` | `0` only: gives the file to the root group, leaving its owner |
| `disable-line` | `authorized-keys` or `apt-list` (one-line sources, never a deb822 paragraph): comments out the subject line, named `path:line`, of a syntax where every line grants access |
| `drop-in` | `{into, name, lines}`: writes `/etc/modprobe.d` (`into: modprobe`, only `install <module> /bin/false` or `/bin/true` and `blacklist <module>`) or `/etc/apt/apt.conf.d` (`into: apt`, only `APT::Install-Recommends` and `APT::Install-Suggests` set to `"0"` or `"false"`) or `/etc/sysctl.d` (`into: sysctl`, only `key = value` at a hardened value the core lists, such as `net.ipv4.conf.<interface>.send_redirects = 0`, which `fix` then loads with `sysctl --load` on the live host) or, for `net.ipv4.ip_local_reserved_ports`, a port list, its line naming no fact but `{facts.sysctl.settings.net.ipv4.ip_local_reserved_ports}`, the ports already reserved, so every failing subject’s port joins them on one line, since a later file replaces the whole value, and a line of the same key in the existing file gives way; or `/etc/sudoers.d` (`into: sudoers`, only `Defaults use_pty` and `Defaults logfile="/var/log/sudo.log"`, mode 0440, written only once `visudo --check` passes it) as `60-systemlint-<name>.conf` in modprobe, `99-systemlint-<name>.conf` in apt and sysctl and `99-systemlint-<name>` in sudoers, which skips a name holding a dot, all letting the last file read win; a line’s `{subject}` takes the failing subject, an interface name of letters, digits, `_` and `-`, and the lines every failing subject asks of one file are written together, `name` lowercase letters, digits and `-` up to 64, 1 to 16 lines; a new file appears whole through a temporary sibling renamed without replacing, a file holding only lines its directory admits gets the missing ones added, swapped in whole and swapped back if it changed meanwhile, one holding anything else is refused, and deleting the file undoes it; `unload: true` (modprobe only) then runs `modprobe -r` on every module its lines name that `/proc/modules` lists, on the live host only, failing when modprobe refuses one still in use; a rule with no `fix` shows that file, its lines and the unload as its fix steps |
| `mask` | the subject is a systemd unit (`.service`, `.socket`, `.timer`, `.path`, `.target`, `.mount`, `.automount`, `.swap`): runs `systemctl mask --now` on the live host, which links it to `/dev/null` and stops it, or `systemctl --root=DIR mask` under `--root`; systemctl refuses a unit file of the admin’s own in `/etc/systemd/system`, and `systemctl unmask` undoes it |
| `set-key` | `{file, key, value}`: `file: login-defs` (`/etc/login.defs`, which has no drop-in directory), only `UMASK` at `027` or `077` and `ENCRYPT_METHOD` at `SHA512` or `YESCRYPT`; sets every line naming the key, comments left alone, or adds one when none does, keeping the file’s mode, and refuses when the key no longer holds the value the lint read |

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
    - {rule: files/owner, target: ci/*, reason: the runner image is rebuilt in January, until: 2027-01-31}
```

A waiver covers the failures of the rules its `rule` glob matches, on every
subject or those its `subject` glob matches, through the `until` day. Under
`--containers`, a `target` glob limits it to the containers whose key it
matches (`web`, `ci/runner`); `host` names the host, and a waiver with no
`target` holds everywhere. Both
`reason` and `until` are required. A waived failure is listed but counts toward
no exit code; after `until` it is a finding again, marked as expired. Waiver
expiry is the only judgement that reads the clock at lint time.

## Check output and exit codes

`--format human` prints one block per rule, an empty line after each: with
`-v`, a `Not run` block per reason a collector was skipped (no root, a refused read,
live-only under `--root`) with its rules wrapped under it, none for an opt-in the
run did not ask for (`--image-config`, `--network`, `--containers`), which only the counts show, a
`Not read` block per path a collector could not read (still `unknown` in the
counts and every machine format), an `Unknown` block per collector error with
the rules it left undecided wrapped under it,
one `Conflict` block per set of selected rules declaring `conflicts` on each other, naming each with its control tags and the `--prefer TAG` that keeps each, the first tag its standard brings that the other side lacks (`--tags '!ID'` when a side has none), then each rule’s rationale (their checks answer `conflict` in every format, `kind: review` in SARIF, and never fail the run),
`Unknown`, `Manual` (with the `Rationale:` procedure) and `Waived` blocks, then the failures, worst first: errors,
then warnings, info and advice, each level highest score first. A failure
lists a `Run:` command under each subject with a remedy, up to two, then from
two on the `systemlint fix --tags <rule>` command that makes every change, on
its own line; from three on that command stands for them, and `-v` keeps every
command. Each quoted value and path is coloured when colour is on, and a fix
of several steps is numbered, each command and file line alone below its
step. The summary
follows, one count per row: the rating, each level, the passes, then what did
not run in two kinds. `Not selected` and `Not run` are yours to turn on (name
the ruleset in `--tags`; run as root, add the opt-in flag, or collect fresh
facts), `Not run` listing its rules under it by what each needs, while `Nothing to check` is a rule this host has nothing for (no
such program, a ruleset whose `when` the host does not meet). One last line
names the rulesets with no rule that applies to the host:

```text
Rating            B
Errors            5
Warnings          9
Info              0
Passed            577
Not run           24
  3 rules need root:
    accounts/shadow-missing, files/owner, logs/file-mode
  1 rule needs an opt-in flag:
    tls/expired
Nothing to check  21, the host has nothing these rules judge

Not applicable to this host: gdm, nftables, tls.
```

A failure block opens with the level, the highest score of the rule and its ID,
then the `title` on its own line, a `Tags:` line of its tags but the control
tags, lists each subject on its own dash line with the value it failed on, then a `Rationale:` line, and
ends with one `Fix:` line, or a fix under each subject when they differ. A rule
with a remedy puts its command under each subject as a `Run:` line with no full
stop, so it pastes into a shell, in place of the `Fix:` line, and closes with the `systemlint fix --tags`
call that makes every change; `-v` adds a `Controls:` line naming its control
tags and a `See:` line per reference.
Failures that name each other, the two sides of `apt/overlap`, list as one
problem. `--plain` prints one tab-separated line per finding instead: outcome
or level, score, rule, subject, message, fix, the message without the subject
it opens with, a rule not run on one `not-run` line per reason whatever its
subjects, and the counts after `rating` and the grade. Subject, `Rationale:` and `Fix:` lines, and the last two fields of every
line, end with a full stop unless they already end a sentence, and
the last field opens with a capital, so a screen reader reading the whole report
pauses between them. Colour marks only the level word, rule IDs and the
`Rationale:`, `Fix:` and `Run:` labels, so the words still carry the meaning; `--color auto`, the
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
- `x-version` adds deb, SemVer, rpm, apk and pacman version ordering to the schema, and `x-cel` a CEL expression over other facts;
- rules carry `tags`, and selectors mix rulesets, IDs and tags, with `!` to
  remove, replacing `--exclude-rules` and the per-level override flags;
- a waiver exempts a rule on a subject until a day;
- `{got}` quotes any string, without spiderlint’s character count, which
  measures web titles;
- `fix` placeholders are the finding’s `{subject}`, `{got}`, `{field}`, `{facts.PATH}` and
  `{fact}`, not the host or origin of a URL;
- exit code 4 means a refused plugin or file, not a failed fetch;
- `unique: true` sits beside `fact` and fails each subject that shares a value,
  where spiderlint’s `unique: <fact>` gives one finding per value, so a waiver
  or SARIF fingerprint still names one subject;
- a `{path}` segment joins two collections by value, and `same` compares the
  facts it reaches;
- there are no `scope`, `hints` or built-in rules; `advice` replaces the `hint` level.
