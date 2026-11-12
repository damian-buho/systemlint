<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Linting images in CI

`action.yaml` at the repository root is a composite action for GitHub Actions
and Forgejo Actions. It lints a container image or a root filesystem with the
systemlint image, prints the human report, writes SARIF, and fails the step at
`fail_on`.

```yaml
jobs:
  systemlint:
    runs-on: ubuntu-26.04
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - run: docker build --tag app:ci .
      - uses: damian-buho/systemlint@0.1.0
        with:
          image: app:ci
          tags: apt,files,env
          upload_sarif: 'true'
```

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `image` | — | Image to lint; set this or `root` |
| `root` | — | Root filesystem directory to lint |
| `tags` | every rule | Selector list, as `lint --tags` |
| `fail_on` | `error` | As `lint --fail-on` |
| `config` | — | A systemlint configuration file in the workspace |
| `upload_sarif` | `false` | Upload to GitHub code scanning |
| `version` | the pinned release, else `latest` | Systemlint image tag |
| `systemlint_image` | — | Full systemlint image reference, for a mirror |

Outputs: `facts` (the facts document, JSON), `sarif`, `result` (`pass` or
`fail`). The human report also goes to the job summary.

## What it runs

1. `systemlint facts` once, in the systemlint image, as root with every
   capability dropped but `DAC_READ_SEARCH`, so it reads 0600 files such as
   `/etc/shadow` and can change nothing; no network, read-only filesystem.
2. `systemlint lint -` twice on those facts, as the runner’s own user: once
   for SARIF, once for the human report and the exit code. Both judge the same
   facts, so they never disagree, and nothing root-owned is left in
   `RUNNER_TEMP`.

An image is mounted with `--mount type=image` (Docker 28 or later), which keeps
every owner and mode as the image ships them; `docker export` piped into an
unprivileged `tar` would rewrite every owner to the runner. The image’s config
from `docker image inspect` goes to `--image-config`, so `env` rules see its
`ENV`.

Collectors that only make sense on a live host (`env-processes`, `sshd -T`)
are skipped under a root, and the rules reading them answer `unknown`, never
`pass`.

## Without the action

The same, by hand:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 \
  --mount type=image,source=app:ci,target=/subject \
  --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest \
  facts --root /subject --json > facts.json
docker run --rm --interactive --network none --read-only --user "$(id --user)" \
  --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest \
  lint - --format sarif < facts.json > systemlint.sarif
```
