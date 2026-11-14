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
| `read.exec-from` | `each`, a dotted fact path to a map; `argv`, run once per key, `{key}` replaced by it; `keep`, a JSON Schema the key’s value must pass. Live mode only, never inline; a key holding a comma, `=`, a blank or a control character is left out, so it can’t add a field to a `key=value` list. The `sshd` collector runs `sshd -T -C user={key},…` over `accounts.passwd` |
| `read.image-config` | `true` to pass the file given with `--image-config`; skipped without one |
| `read.files-from` | dotted fact paths, `*` a whole segment, whose strings name files to read, as `env.units.*.environment-files`; `{pattern}/glob` globs below each, as `{accounts.passwd.*.home}/.ssh/*` |
| `read.stat-from` | the same, naming files to pass with their `stat` |
| `read.stat-keep` | a JSON Schema over each `stat`: only the stats it admits reach the plugin, as `{properties: {setuid: {const: true}}}` keeps a walk of `/usr/**` to its set-user-ID files; needs `stat` or `stat-from` |
| `read.stat-parents` | `true` stats every directory above each kept stat, `/` left out, into the same request, so a rule can judge who may replace the file; needs `stat` or `stat-from` |
| `read.statfs-from` | the same, naming paths to pass with their `statfs`, as `mounts.active` |
| `read.hash` | `sha256`, `sha512` or both: adds the file’s lowercase hex digest to the `stat` of each regular file; needs `stat` or `stat-from` |
| `live` | `true` when the collector reads what only a running host has, such as `/proc`; skipped under `--root` |
| `secret` | `true` to replace every string the op returns with its keyed hash, as for values a plugin marks, so a command’s output compares without being stored |
| `partial` | `true` to keep what the run may read: a path it may not read becomes the key `into.<path>`, which every rule under a `*` there answers `unknown` for; only for an op that keys its facts by input path |
| `network` | `true` when it lists `addr`, `dns` or `http`, which only it may; skipped unless the run passes `--network` or sets `collect.network: true`, and under `--root` |
| `containers` | `true` when it reads the environment of running containers, which belongs to their images; skipped unless the run passes `--containers` or sets `collect.containers: true` |
| `read.addr` | `host:port` targets the core opens a TCP connection to |
| `read.dns` | hostnames the core queries, each taken as fully qualified |
| `read.dns-types` | the record types asked for each name: `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT` [default: `A`, `AAAA`] |
| `read.dns-server` | the IP, or `IP:port`, every query goes to [default: the `nameserver` lines of this host’s `/etc/resolv.conf`] |
| `read.dns-server-from` | dotted fact paths, `*` a whole segment, `N` a list’s item and `:N` its first N items holding an IP address, or one with `:port`, whose strings name servers, IPv6 `%zone` dropped and any other string skipped; each server is asked the `read.dns` names on its own, as a `nameserver` probe, instead of resolving them; never beside `dns-server` |
| `read.http` | URLs the core sends one GET to, or maps `{url, username, password-file, ca-file, body: json}` |
| `read.order` | the order `files` reach the plugin: `path` [default], or `drop-in`, as systemd reads a conf directory set: per filename the match of the earliest glob in `files` hides the others, in name order, then each path with no wildcard in listed order |
| `read.prefer` | `exec`: the command alone when it exited 0, else the files alone (under `--root`, with the program absent or failing); needs both `exec` and `files` |
| `privileged` | `true` when only root can read its sources, such as `/proc/1/environ` or a 0600 file under `/etc/default`; skipped when systemlint runs unprivileged |
| `parse.plugin` | the plugin name, `apt` for `systemlint-apt` |
| `parse.op` | an op the plugin lists in `--describe` |
| `parse.with` | the typed options of a family op (`kv`, `words`, `options`, `match`), passed in the request’s `with`; see [Family ops](#family-ops) |
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

Every source is read-only and capped at 16 MiB per file, stream or response; `exec`,
the plugin call and each network attempt time out after 30 seconds, or `collect.timeout`
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

## Network probes

systemlint stays offline unless asked: a `network: true` collector is
`skipped` until the run passes `--network` or the configuration sets
`collect.network: true`. It also never runs under `--root`, since its answers
describe the host running systemlint, not the root being read. Its requests
are made by the core, from the host running systemlint, never by a plugin;
each attempt waits at most `collect.timeout`, and one that fails for a reason
another try may fix is tried 3 times, waiting half a second and then a second,
each wait with up to as much again of random jitter. `-v` logs every attempt
and how long it took, and the closing line names every target asked.

```yaml
id: web
network: true
read:
  addr: ["kiota.ch:443"]
  dns: [kiota.ch]
  dns-types: [A, AAAA, MX]
  http:
    - https://kiota.ch/
    - {url: "https://endoflife.date/api/v1/products/nodejs/releases/26", body: json}
parse: {plugin: formats, op: probes}
into: probes.web
```

| Fact under `into` | Meaning |
| --- | --- |
| `addr.<target>.reachable` | `true` when a connection opened; `false` once every address refused, or timed out on every attempt |
| `dns.<name>.<type>` | the record data, sorted, one string per record (`10 mail.example.`); empty for NXDOMAIN or no record of that type |
| `dns.<name>.resolvable` | `true` when any asked type returned a record |
| `nameserver.<server>.answered` | `true` when the server answered every query, `false` when it answered none, after 3 tries each; answering only some is an `error` |
| `nameserver.<server>.codes` | the response codes it answered, sorted, as IANA names them (`NOERROR`, `NXDOMAIN`, `REFUSED`, `SERVFAIL`) |
| `http.<url>.status` | the status code; a redirect is never followed, its `location` header says where |
| `http.<url>.headers` | each header by its lowercase name, repeated ones joined by a comma and a space; `set-cookie` reads `[redacted]` |
| `http.<url>.body-sha256` | the lowercase hex SHA-256 of the decoded body |
| `http.<url>.json` | the body parsed as JSON, with `body: json` |
| `http.<url>.tls` | `verified`, its `error` when not, `version` (`1.2`, `1.3`), the leaf certificate’s `not-before`, `not-after`, `issuer`, `subject`, `days-left` until `not-after` at `meta.collected-at` and `percent-left` of the validity period, both whole, rounded down and negative once expired |

A target that gives no answer, such as a name that does not resolve or a server
that answered SERVFAIL 3 times, keeps its reason as `error` and a
diagnostic, so every rule on it answers `unknown`, never `fail`. An `https`
URL whose certificate this host would not trust, by its CA certificates or
`ca-file` alone when given, is described under `tls` with `verified: false`
and nothing is sent to it, credentials least of all. `username` and
`password-file` go together and only over `https`; the password is read from
the file at request time and never enters the facts document.

`HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (lowercase first, as cURL reads
them) route `http` probes: an `https` URL through a `CONNECT` tunnel, an
`http` one in absolute form. Only an `http://` proxy without credentials is
supported; any other is an error naming it. `addr` and `dns` always go direct.

The shipped `tls` ruleset judges every `https` URL under
`probes.<name>.http`, so write a network collector `into: probes.<name>`:
`tls/expired` fails a certificate past its end, `tls/expiring` one with under
a tenth of its lifetime left, which a renewal job that runs never lets happen
whatever the lifetime, and `tls/untrusted` one this host would not trust while
it is still valid. With no
collector into `probes` the ruleset is `not-applicable`; with one skipped, its
rules are `not run`.

The shipped `resolv-conf` collector reads `/etc/resolv.conf` with `formats
words` into `resolv.conf.<path>`: every `nameserver` and `options` word in
order, and the last `search` and `domain` lines. The shipped
`resolv-nameservers` collector asks the first 3 nameservers that are IP
addresses, the ones glibc uses, for the root zone’s `NS` records into `resolv.probes`, and
the `resolv` ruleset fails one that answers no query
(`resolv/nameserver-silent`) or answers `REFUSED`
(`resolv/nameserver-refuses`), both covering Lynis NETW-2704. A
`resolv.conf` naming no nameserver leaves the ruleset `not-applicable`.

An inline collector under `collect.collectors` may not set `network`, as it
may not `exec`: a `.systemlint.yaml` arrives with whatever directory
systemlint runs in, and should not choose where this host connects. Put a
network collector in a file under `collect.directories`.

## Outcomes

Each collector records `collectors.<id>.status` and its `into` in the facts
document, with a `reason` when it is not `ok`:

| Status | Meaning |
| --- | --- |
| `ok` | the plugin replied and its facts are under `into` |
| `error` | reading failed for any reason but a refusal, the plugin exited non-zero or replied with invalid JSON; the reason is kept |
| `skipped` | the mode cannot run it, such as `exec` or `live` under `--root`, `image-config` without `--image-config`, `privileged` in an unprivileged run, or `network` without `--network`, a fact it needs or reads from whose collector was skipped (`needs fact sshd, which collector sshd skipped: …`), or the kernel refused a read (`can’t list /etc/cron.hourly without root`); the reason is kept, and `opt-in: true` marks an `image-config`, `network` or `containers` collector the run did not ask for |

An `ok` collector also records its `plugin` and `op`, the plugin’s
`diagnostics`, under `redacted` the JSON Pointers of the values the plugin
marked secret, which are replaced by `[redacted]` in every output, and under
`hashed` how many values were replaced by their keyed hash, and under
`unreadable` each path a `partial` collector could not read.

A rule that reads a fact from a collector that did not finish `ok` answers
`unknown`, naming that collector, rather than passing. The `human` report lists
an `unknown` from a `skipped` collector on no line of its own: it prints one
`not run` line per skip reason, naming the collectors and the rules, and counts
those checks as `not run`; `json`, `sarif` and `textfile` keep them
`unknown`.

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
text), `op: csv` (a list of rows keyed by the header row) and `op: deb822`
(a list of `{line, fields}` paragraphs as apt and dpkg read them, values as
text, continuation lines joined by a newline, the first field of a name kept,
a clear-signed `InRelease` read inside its signature) key each parsed file by
its path, a file that does not parse becoming a diagnostic.

To judge any command, a collector file under `collect.directories` runs it
with `read.exec` and `op: exec`, which returns its `exit-status`, `stdout`,
`stderr` and `stdout-lines`:

```yaml
id: nginx-test
read: {exec: [/usr/sbin/nginx, -t]}
parse: {plugin: formats, op: exec}
into: commands.nginx-test
```

The text ops (`lines`, `kv`, `words`, `options`, `match`, `deb822`, `ini`, `json`, `yaml`, `toml`, `csv`) read a
command’s `stdout` as they read a file when it exits 0, its program path
standing in for a file path; any other exit is a diagnostic naming the status
and the first line of `stderr`:

```yaml
id: mounts-json
read: {exec: [/usr/bin/findmnt, --json]}
parse: {plugin: formats, op: json}
into: commands.mounts
```

## Family ops

`formats` has one op per format family, never one per file or program: most
files that look custom are whitespace records or `key value` lines. A family
op takes a few typed options under `parse.with`, never a pattern, and types
the scalars it reads: a bare decimal integer with no leading zero becomes a
number (`27`, `-1`), anything else stays text (`0644`, `yes`, a quoted
`"27"`).

`op: words` reads whitespace records, `"…"` and `[…]` each one word with
their delimiters dropped (`\"` and `\]` escape the closing mark); a word
opening with a comment marker ends the line, and a `\` at a line end joins
the next one.

| Option | Meaning |
| --- | --- |
| `separator` | split each line on this string instead, keeping empty fields, as `:` tables need; a comment then only opens a line |
| `comments` | the markers that open a comment [default: `["#"]`] |
| `directives` | keep only the lines whose first word is one of these |
| `columns` | name each word in order, `null` dropping one; without it, each input path maps every first word to the list of words after it |
| `required` | the fewest words a line may have [default: every column]; a line with fewer, or with more and no `rest`, is a diagnostic |
| `rest` | the column holding the words past the named ones, as a list |
| `lists` | columns split on `,`, empty items dropped |
| `toggles` | list columns where a later `X` or `noX` drops an earlier `X` or `noX`, as mount(8) lets the later option win |
| `key` | a column, or a list of them for nested keys, keying records across every input instead of listing them per path; each record gets its `path` and `line` |
| `repeat` | for a key seen again: `first` [default] or `last`, the other lines’ numbers in the kept record’s `shadowed`, or `list` keeping every record; without `columns`, also `append`, joining the words, and a map giving a policy per first word, `*` for the rest |
| `octal` | decode `\040`-style escapes, as fstab(5) and the kernel’s mount tables write a space |

`/etc/resolv.conf` as glibc reads it, every `nameserver` kept and the
`resolv-nameservers` collector taking the first 3 with `nameserver.:3`:

```yaml
id: resolv-conf
read: {files: [/etc/resolv.conf]}
parse:
  plugin: formats
  op: words
  with: {comments: ["#", ";"], repeat: {nameserver: append, options: append, search: last, domain: last}}
into: resolv.conf
```

`/etc/group` keyed by name, the password field never read:

```yaml
id: accounts-group
read: {files: [/etc/group]}
parse:
  plugin: formats
  op: words
  with: {separator: ":", columns: [name, null, gid, members], lists: [members], key: name}
into: accounts.group
```

`op: kv` reads one key and its value per line, every input into one object.
A quoted value is unquoted as a shell would and stays text; a bare one is
typed.

| Option | Meaning |
| --- | --- |
| `separator` | the string between key and value, blanks around it trimmed, or `whitespace` for the first run of blanks, a key alone then holding `""` [default: `=`] |
| `comments` | the markers that open a comment line [default: `["#"]`] |
| `repeat` | for a key seen again, in input order: `first` [default], `last`, or `list` keeping every value |
| `nest` | the character that nests a key (`.` puts `net.ipv4.ip_forward` at `net` → `ipv4` → `ip_forward`) |
| `swap` | a character exchanged with `nest` in a key where it comes first, as sysctl.d(5) writes `net/ipv4/conf/eth0.100/rp_filter`; needs `nest` |
| `strip` | characters dropped from a key’s start, such as sysctl.d’s `-` |

Kernel parameters from `sysctl -a`, or from the sysctl.d files in
systemd-sysctl’s order when it cannot run:

```yaml
id: sysctl
read:
  files: [/etc/sysctl.d/*.conf, /run/sysctl.d/*.conf, /usr/local/lib/sysctl.d/*.conf, /usr/lib/sysctl.d/*.conf, /lib/sysctl.d/*.conf, /etc/sysctl.conf]
  order: drop-in
  exec: [/usr/sbin/sysctl, -a]
  prefer: exec
parse:
  plugin: formats
  op: kv
  with: {comments: ["#", ";"], repeat: last, nest: ".", swap: /, strip: "-"}
into: sysctl.settings
```

`op: options` reads getopt lines, as `auditctl -l` and `iptables-save` print
them, one record per line in order under each input path. Each flag keeps its
dashes as its key (`-F`, `--dport`), holding the list of every value it was
given on the line; a flag followed by another flag, or by nothing, holds `[]`.
`--name=value` is its own value, a `!` before a flag negates it into the key
`! -s`, a quoted word is always a value, and words before any flag sit in
`args`. Values are typed as `words` types them, and a `#` word ends the line.

| Option | Meaning |
| --- | --- |
| `split` | flags whose values split on `,` into separate items, as `-S execve,execveat` |
| `comments` | the markers that open a comment [default: `["#"]`] |

The audit rules the kernel runs:

```yaml
id: audit-rules-loaded
privileged: true
read: {exec: [/usr/sbin/auditctl, -l]}
parse: {plugin: formats, op: options, with: {split: [-a, -S]}}
into: audit.loaded
```

`op: match` is for the one line shape no family covers, such as a module’s
base name in `modules.order`: `with.pattern` is one short regular expression,
with no lookaheads, whose named captures become the fields, each line it
matches one fact keyed by its `key` capture; lines it does not match are
dropped, and a key seen again with other fields is a diagnostic, the first
kept. Needing a longer pattern means a family is missing. One package per
pending upgrade:

```yaml
id: apt-upgrades
read: {exec: [/usr/bin/apt-get, --simulate, dist-upgrade]}
parse:
  plugin: formats
  op: match
  with: {pattern: '^Inst (?P<key>\S+) (?:\[(?P<installed>[^\]]+)\] )?\((?P<candidate>\S+)'}
into: apt.upgrades
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
through the same root. A pattern in braces followed by an absolute glob,
`{accounts.passwd.*.home}/.ssh/*`, globs that suffix below each named path: the
named part stays literal, so a home of `/srv/*` matches nothing it would not
match as written, and an absent home, or one that is a file, names nothing. The collector runs after every collector writing under
the pattern’s literal part, the segments before its first `*`; when that part
is absent from the facts, it fails naming the fact and the collector that left
it out, so its rules read as unknown instead of passing on fewer files. A
pattern may not start with `*` or read what its own collector writes.
