<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
pf-cli-managed: yes
-->

[Español](docs/es/README.md) · [Українська](docs/uk/README.md)

# Systemlint

Systemlint collects facts about a host, a root filesystem or a container image, then judges them with declarative rules. Collecting and judging are separate steps, so one saved facts document serves any number of policies.

The core reads every file and runs every command; each plugin is a separate static binary that only turns those bytes into facts. Written in Rust.

[![Stand with Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://damian-buho.github.io/support-ukraine/) [![Projectfile inside](https://badges.kiota.ch/static/v1?label=projectfile&message=inside&labelColor=0d0d0d&color=8c6723&style=flat-square)](https://projectfile.org) [![License](https://badges.kiota.ch/static/v1?label=license&message=AGPL-3.0-only&color=1e5913&style=flat-square)](LICENSE) [![Cosign](https://badges.kiota.ch/static/v1?label=cosign&message=enabled&color=1e5913&style=flat-square)](https://docs.sigstore.dev/cosign/verifying/verify/)

![Project status](https://badges.kiota.ch/static/v1?label=status&message=maintained&color=1d63ed&style=flat-square) [![Last commit on kiota.ch](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://kiota.ch&label=last%20commit%20on%20kiota.ch&style=flat-square)](https://kiota.ch/damian-buho/systemlint)

[![Publish pipeline on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/published.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Vulnerability audit on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/audited.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Dependency freshness on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Analysis sweep on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions)

## Features

- Rules that know which hosts they are for
- Findings a person, a pipeline and a screen reader can read

It also inherits the features of B19 / Ubuntu — see [Features](docs/FEATURES.md) for the full list.

## What this provides

- **Executable** `systemlint` — command `systemlint`
- **Container image** `kiota.ch/damian-buho/systemlint:latest`

## Supported platforms

- `linux/amd64`
- `linux/arm64`

## Installation

### Container image

Pull the published container image:

```sh
docker pull kiota.ch/damian-buho/systemlint:latest
```

Stable releases also publish `X.Y.Z`, `X.Y` and `X` tags — pull the precision you want to pin.

### Prebuilt archive

Download the archive for your architecture and unpack it into `/usr/local`:

```sh
systemlint --version
```

The archive holds the core, its plugins, collectors and rulesets under `bin/`, `lib/systemlint/` and `share/systemlint/`.

## Usage

Lint a container image with its owners and modes intact (Docker 28 or later), as SARIF:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
```

Lint the host it runs on, read-only, as root with only the capability to read every file:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest check --root /host
```

## Building

Clone the repository and run `make` — every build step, target and entry point is in [Building](docs/BUILD.md).

## Documentation

- [Local accounts and groups](docs/how-to/accounts.md)
- [apt sources](docs/how-to/apt.md)
- [Authentication configuration](docs/how-to/auth.md)
- [Linting images in CI](docs/how-to/ci.md)
- [Collectors](docs/how-to/collectors.md)
- [Configuration: files, layers and precedence](docs/how-to/configuration.md)
- [Environment variables](docs/how-to/env.md)
- [File permissions](docs/how-to/files.md)
- [Outputs: SARIF and Prometheus metrics](docs/how-to/outputs.md)
- [Plugin protocol v1](docs/how-to/protocol.md)
- [Rule book: how to write a shipped rule](docs/how-to/rule-book.md)
- [Rules, rulesets and compliance](docs/how-to/rules.md)
- [Kernel parameters, Docker, systemd units and ufw](docs/how-to/services.md)
- [OpenSSH server](docs/how-to/sshd.md)

## Policies

- [How to contribute](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Getting support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [AI and LLM Policy](AI_POLICY.md)

## Links

- [Projectfile Specification](https://projectfile.org)

## License

This project is licensed under AGPL-3.0-only — see the [LICENSE](LICENSE) file for details.
