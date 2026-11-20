<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
pf-cli-managed: yes
-->

[Español](docs/es/README.md) · [Українська](docs/uk/README.md)

# Systemlint

Systemlint collects facts about a host, a root filesystem or a container image, then judges them with declarative rules. Collecting and judging are separate steps, so one saved facts document serves any number of policies.

The core reads every file and runs every command; each plugin is a separate static binary that only turns those bytes into facts. Written in Rust.

[![Stand with Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://damian-buho.github.io/support-ukraine/) [![Projectfile inside](https://badges.kiota.ch/static/v1?label=projectfile&message=inside&labelColor=0d0d0d&color=8c6723&style=flat-square)](https://projectfile.org) [![License](https://badges.kiota.ch/static/v1?label=license&message=AGPL-3.0-only&color=1e5913&style=flat-square)](LICENSE) [![Cosign](https://badges.kiota.ch/static/v1?label=cosign&message=enabled&color=1e5913&style=flat-square)](https://docs.sigstore.dev/cosign/verifying/verify/) ![ClamAV scanned](https://badges.kiota.ch/static/v1?label=clamav&message=scanned&color=1877aa&style=flat-square) [![PRs welcome](https://badges.kiota.ch/static/v1?label=PRs&message=welcome&color=1e5913&style=flat-square)](CONTRIBUTING.md) [![REUSE compliance](https://api.reuse.software/badge/codeberg.org/damian-buho/systemlint)](https://api.reuse.software/info/codeberg.org/damian-buho/systemlint)

![Project status](https://badges.kiota.ch/static/v1?label=status&message=maintained&color=1d63ed&style=flat-square) [![Last commit on kiota.ch](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://kiota.ch&label=last%20commit%20on%20kiota.ch&style=flat-square)](https://kiota.ch/damian-buho/systemlint) [![Last commit on Codeberg](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://codeberg.org&label=last%20commit%20on%20Codeberg&style=flat-square)](https://codeberg.org/damian-buho/systemlint) [![Last commit on GitHub](https://badges.kiota.ch/github/last-commit/damian-buho/systemlint?label=last%20commit%20on%20GitHub&style=flat-square)](https://github.com/damian-buho/systemlint)

[![Publish pipeline on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/published.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Vulnerability audit on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/audited.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Dependency freshness on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Analysis sweep on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions)

[![Publish pipeline on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/published.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Vulnerability audit on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/audited.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Dependency freshness on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Analysis sweep on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions)

## Features

- In every pipeline and on every dashboard
- Collect once, judge anywhere
- The host and every container in one run
- Settings judged as the program applies them
- File permissions that matter, not every bit
- Every finding is real
- Fixes it makes itself, through the tools that own them
- Kernel and CPU hardening, as the running kernel reports it
- What the host exposes to the network
- Findings a person, a pipeline and a screen reader can read
- Secrets and injected code in every environment
- Failing disks and full filesystems before they take the host down
- Rules that cite the standards they satisfy
- Safe to run as root on a host you do not trust

It also inherits the features of B19 / Ubuntu — see [Features](docs/FEATURES.md) for the full list.

## What this provides

- **Executable** `systemlint` — command `systemlint`
- **Container image** `ghcr.io/damian-buho/systemlint:latest`
- **Container image** `damianbuho/systemlint:latest`

## Installation

### Container image

Pull the published container image:

#### Pull from GHCR — linux/amd64, linux/arm64

```sh
docker pull ghcr.io/damian-buho/systemlint:latest
```

#### Pull from DockerHub — linux/amd64

```sh
docker pull damianbuho/systemlint:latest
```

Stable releases also publish `X.Y.Z`, `X.Y` and `X` tags — pull the precision you want to pin.

If the registries above are unreachable, pull from the origin instead:

#### Pull from Kiota — linux/amd64

```sh
docker pull kiota.ch/damian-buho/systemlint:latest
```

### Prebuilt archive

Download the archive for your architecture and unpack it into `/usr/local`:

```sh
curl --fail --location https://github.com/damian-buho/systemlint/releases/latest/download/systemlint-linux-$(uname -m).tar.gz | sudo tar --extract --gzip --directory /usr/local
systemlint --version
```

The archive holds the core, its plugins, collectors and rulesets under `bin/`, `lib/systemlint/` and `share/systemlint/`.

## Usage

Lint a container image with its owners and modes intact (Docker 28 or later), as SARIF:

Lint the host it runs on, read-only, as root with only the capability to read every file:

### From GHCR

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint ghcr.io/damian-buho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint ghcr.io/damian-buho/systemlint:latest check --root /host
```

### From DockerHub

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint damianbuho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint damianbuho/systemlint:latest check --root /host
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
- [Rules and rulesets](docs/how-to/rules.md)
- [Kernel parameters, modules and audit rules, AIDE, AppArmor, Docker, systemd units, plain-text servers, running services, listening sockets, ufw and nftables](docs/how-to/services.md)
- [OpenSSH server](docs/how-to/sshd.md)

## Policies

- [How to contribute](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Getting support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [AI and LLM Policy](AI_POLICY.md)

## Links

- [Issues on Codeberg](https://codeberg.org/damian-buho/systemlint/issues)
- [Issues on GitHub](https://github.com/damian-buho/systemlint/issues)
- [Projectfile Specification](https://projectfile.org)

## License

This project is licensed under AGPL-3.0-only — see the [LICENSE](LICENSE) file for details.
