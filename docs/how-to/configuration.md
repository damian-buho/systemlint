<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Configuration: files, layers and precedence

systemlint reads up to five YAML configuration files and merges them. From the
lowest layer to the highest:

1. `/etc/systemlint/config.yaml`, the system configuration.
2. `$XDG_CONFIG_HOME/systemlint/config.yaml`, else
   `~/.config/systemlint/config.yaml`, the user configuration.
3. `.systemlint.yaml` in the working directory, the project configuration: a
   repository that lints its own root filesystem keeps its policy beside it.
4. The file `SYSTEMLINT_CONFIG` names.
5. The file `--config` names.

The first three are read when they exist. The last two must exist: naming a
missing file exits 5. A flag beats every file.

## Merging

A higher layer replaces a lower one key by key. Sections and maps merge, so a
project file that sets only `collect.timeout` keeps the system `check.tags`,
and an inline ruleset keeps the rulesets of lower layers. A list is one value:
`check.waivers` or `plugins.directories` in the project file replaces the
system list, it never extends it.

A relative directory resolves against the directory of the file that names
it. Every directory a configuration names passes the same ownership and mode
check as the shipped ones, so a project configuration in a checkout can’t
load a plugin, collector or ruleset that another user can write.

`systemlint -v` names each file it read, in order, and each absent one it
skipped.

## Untrusted checkouts

Whoever writes `.systemlint.yaml` controls the policy of a run in that
directory: its `check.waivers` can hide any finding. Inside a checkout you do
not trust, such as a pull request from a fork, pass `--no-project-config` to
skip the file. To skip it on every run, set `project-config: false` in the
system or user configuration; the key works only there, since a higher layer
is read after the project file, and setting it anywhere else exits 5. The
shipped `action.yaml` runs systemlint in a container that never reads the
checkout’s file.

## Keys

```yaml
project-config: false  # skip .systemlint.yaml; system or user configuration only
plugins:
  directories: [/opt/systemlint/plugins]
  format: json         # the default plugin list --format: human or json
collect:
  directories: [collectors]
  timeout: 30          # seconds per command, plugin call or network attempt, 1 or more
  jobs: 4              # the default --jobs: collectors run at once, 1 to 64
  network: false       # true runs the network: true collectors, as --network does
  containers: false    # true runs the containers: true collectors, as --containers does
  hash-key: ...        # 16 characters or more
  collectors: []       # inline collectors, never exec nor network; see collectors.md
  format: json         # the default facts --format, over the --output extension: yaml or json
check:
  directories: [rulesets]
  tags: [apt, sshd]    # the default --tags
  vars: {ntp: time.example}  # ruleset var values, under --var, --vars and from-env
  fail-on: warning     # the default --fail-on
  format: sarif        # the default --format: human, json, sarif or textfile
  color: never         # the default --color: auto, always or never
  plain: true          # the default --plain; --no-plain or --format undoes it
  waivers: []
  rulesets: {}
fix:
  enabled: false       # turn systemlint fix off
```

An unknown key, or a value out of range, exits 5 and names the file.
