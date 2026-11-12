<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Outputs: SARIF and Prometheus metrics

`systemlint lint` prints a human report by default. Two more formats feed
other tools, and `--output PATH` writes any format to a file through a
temporary sibling and a rename, mode 0644 under the umask, so a reader never
sees half a report. `--output -` prints to stdout.

## SARIF

`--format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
log, the format GitHub code scanning and most security dashboards read.

```sh
systemlint lint --root rootfs --format sarif --output systemlint.sarif
```

| Check | SARIF result |
| --- | --- |
| `fail` | `kind: fail`, `level` from the severity: `error`, `warning`, `note` for info and hint |
| `fail` with an active waiver | the same, plus a `suppressions` entry with the reason and `until` |
| `unknown` | `kind: open`, `level: none`, the reason as message |
| `pass`, `skip` | no result |

- Location: the last subject key that is an absolute path becomes a file
  under `uriBaseId: ROOT`, with a trailing `:line` as its region
  (`/etc/apt/sources.list:3`); the fact path and subject are always there as a
  logical location. `ROOT` is `file:///` for a live host and the root
  directory for `--root` when it is absolute.
- Rules: each rule judged gets a descriptor with its `tags`, `docs` as
  `helpUri`, and its score as `security-severity`, which GitHub shows as
  critical, high, medium or low.
- A collector that failed is a tool notification at level `error`, so a run
  that could not read `/etc/shadow` says so beside its results.
- `partialFingerprints.systemlintSubject/v1` is the rule and subject, so an
  alert follows the same source across runs.

## Prometheus textfile

`--format textfile` writes metrics for node-exporter’s
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).
Write into its directory with `--output`, so node-exporter never reads half a
file:

```sh
systemlint --quiet lint --format textfile --fail-on never \
  --output /var/lib/node_exporter/textfile/systemlint.prom
```

| Metric | Labels | Value |
| --- | --- | --- |
| `systemlint_checks` | `outcome`: pass, fail, waived, unknown, skip | checks in the run |
| `systemlint_rule_checks` | `rule`, `outcome` | checks of that rule; absent when zero |
| `systemlint_failures` | `severity`: error, warning, info, hint | failing checks, waived ones apart |
| `systemlint_collector_status` | `collector`, `status`: `ok`, `error`, `skipped` | 1 for the status it ended in, else 0 |
| `systemlint_privileged` | — | 1 when the facts were collected as root |

node-exporter already exports `node_textfile_mtime_seconds` for the file, so
alert on staleness from it rather than from a systemlint metric:

```yaml
- alert: SystemlintFailures
  expr: systemlint_failures{severity="error"} > 0
- alert: SystemlintStale
  expr: time() - node_textfile_mtime_seconds{file=~".*/systemlint.prom"} > 2 * 86400
- alert: SystemlintCollectorError
  expr: systemlint_collector_status{status="error"} == 1 and on(instance) systemlint_privileged == 1
```

`--fail-on never` keeps a timer unit green while findings exist; the metrics
carry them.
