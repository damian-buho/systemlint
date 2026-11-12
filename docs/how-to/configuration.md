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
project file that sets only `collect.timeout` keeps the system `lint.tags`,
and an inline ruleset keeps the rulesets of lower layers. A list is one value:
`lint.waivers` or `plugins.directories` in the project file replaces the
system list, it never extends it.

A relative directory resolves against the directory of the file that names
it. Every directory a configuration names passes the same ownership and mode
check as the shipped ones, so a project configuration in a checkout can’t
load a plugin, collector or ruleset that another user can write.

`systemlint -v` names each file it read, in order, and each absent one it
skipped.

## Keys

```yaml
plugins:
  directories: [/opt/systemlint/plugins]
collect:
  directories: [collectors]
  timeout: 30          # seconds per command or plugin call, 1 or more
  hash-key: ...        # 16 characters or more
lint:
  directories: [rulesets]
  tags: [apt, sshd]    # the default --tags
  fail-on: warning     # the default --fail-on
  format: sarif        # the default --format: human, json, sarif or textfile
  color: never         # the default --color: auto, always or never
  waivers: []
  rulesets: {}
```

An unknown key, or a value out of range, exits 5 and names the file.
