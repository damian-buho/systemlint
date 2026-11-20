<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
pf-cli-managed: yes
-->

<!-- textlint-disable terminology,common-misspellings -->

[English](../../README.md) · [Українська](../uk/README.md)

# Systemlint

Systemlint recopila datos sobre un equipo, un sistema de archivos raíz o una imagen de contenedor y los evalúa con reglas declarativas. Recopilar y evaluar son pasos separados, así que un mismo documento de datos guardado sirve para cualquier número de políticas.

El núcleo lee cada archivo y ejecuta cada orden; cada complemento es un binario estático aparte que solo convierte esos bytes en datos. Escrito en Rust.

[![Stand with Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://damian-buho.github.io/support-ukraine/) [![Projectfile inside](https://badges.kiota.ch/static/v1?label=projectfile&message=inside&labelColor=0d0d0d&color=8c6723&style=flat-square)](https://projectfile.org) [![License](https://badges.kiota.ch/static/v1?label=license&message=AGPL-3.0-only&color=1e5913&style=flat-square)](../../LICENSE) [![Cosign](https://badges.kiota.ch/static/v1?label=cosign&message=enabled&color=1e5913&style=flat-square)](https://docs.sigstore.dev/cosign/verifying/verify/) ![ClamAV scanned](https://badges.kiota.ch/static/v1?label=clamav&message=scanned&color=1877aa&style=flat-square) [![PRs welcome](https://badges.kiota.ch/static/v1?label=PRs&message=welcome&color=1e5913&style=flat-square)](CONTRIBUTING.md) [![REUSE compliance](https://api.reuse.software/badge/codeberg.org/damian-buho/systemlint)](https://api.reuse.software/info/codeberg.org/damian-buho/systemlint)

![Project status](https://badges.kiota.ch/static/v1?label=status&message=maintained&color=1d63ed&style=flat-square) [![Last commit on kiota.ch](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://kiota.ch&label=last%20commit%20on%20kiota.ch&style=flat-square)](https://kiota.ch/damian-buho/systemlint) [![Last commit on Codeberg](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://codeberg.org&label=last%20commit%20on%20Codeberg&style=flat-square)](https://codeberg.org/damian-buho/systemlint) [![Last commit on GitHub](https://badges.kiota.ch/github/last-commit/damian-buho/systemlint?label=last%20commit%20on%20GitHub&style=flat-square)](https://github.com/damian-buho/systemlint)

[![Publish pipeline on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/published.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Vulnerability audit on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/audited.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Dependency freshness on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions) [![Analysis sweep on GitHub](https://github.com/damian-buho/systemlint/actions/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://github.com/damian-buho/systemlint/actions)

[![Publish pipeline on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/published.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Vulnerability audit on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/audited.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Dependency freshness on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Analysis sweep on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions)

## Características

- Reglas que saben para qué hosts son
- Recolección rápida y de solo lectura
- Arreglos que hace por sí mismo, y solo los que quitan acceso
- Hallazgos que leen una persona, un pipeline y un lector de pantalla
- Reglas que citan los estándares que cumplen

También hereda las características de B19 / Ubuntu; consulta [Características](FEATURES.md) para ver la lista completa.

## Qué entrega este proyecto

- **Ejecutable** `systemlint` — comando `systemlint`
- **Imagen de contenedor** `ghcr.io/damian-buho/systemlint:latest`
- **Imagen de contenedor** `damianbuho/systemlint:latest`

## Instalación

### Imagen de contenedor

Descarga la imagen de contenedor publicada:

#### Descargar de GHCR — linux/amd64, linux/arm64

```sh
docker pull ghcr.io/damian-buho/systemlint:latest
```

#### Descargar de DockerHub — linux/amd64

```sh
docker pull damianbuho/systemlint:latest
```

Las versiones estables también publican las etiquetas `X.Y.Z`, `X.Y` y `X`: descarga el nivel de precisión que quieras fijar.

Si los registros anteriores no están disponibles, descarga desde el origen:

#### Descargar de Kiota — linux/amd64

```sh
docker pull kiota.ch/damian-buho/systemlint:latest
```

### Archivo precompilado

Descarga el archivo para tu arquitectura y descomprímelo en `/usr/local`:

```sh
curl --fail --location https://github.com/damian-buho/systemlint/releases/latest/download/systemlint-linux-$(uname -m).tar.gz | sudo tar --extract --gzip --directory /usr/local
systemlint --version
```

El archivo contiene el núcleo, sus complementos, recolectores y conjuntos de reglas en `bin/`, `lib/systemlint/` y `share/systemlint/`.

## Uso

Analiza una imagen de contenedor con sus propietarios y permisos intactos (Docker 28 o posterior), en SARIF:

Analiza el equipo en el que se ejecuta, en solo lectura, como root y solo con la capacidad de leer cualquier archivo:

### Desde GHCR

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint ghcr.io/damian-buho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint ghcr.io/damian-buho/systemlint:latest check --root /host
```

### Desde DockerHub

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint damianbuho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint damianbuho/systemlint:latest check --root /host
```

## Compilación

Clona el repositorio y ejecuta `make`: cada paso de compilación, destino y punto de entrada está en [Compilación](BUILD.md).

## Documentación

- [Local accounts and groups](../how-to/accounts.md)
- [apt sources](../how-to/apt.md)
- [Authentication configuration](../how-to/auth.md)
- [Linting images in CI](../how-to/ci.md)
- [Collectors](../how-to/collectors.md)
- [Configuration: files, layers and precedence](../how-to/configuration.md)
- [Environment variables](../how-to/env.md)
- [File permissions](../how-to/files.md)
- [Outputs: SARIF and Prometheus metrics](../how-to/outputs.md)
- [Plugin protocol v1](../how-to/protocol.md)
- [Rule book: how to write a shipped rule](../how-to/rule-book.md)
- [Rules and rulesets](../how-to/rules.md)
- [Kernel parameters, modules and audit rules, AIDE, AppArmor, Docker, systemd units, plain-text servers, running services, listening sockets, ufw and nftables](../how-to/services.md)
- [OpenSSH server](../how-to/sshd.md)

## Políticas

- [Cómo contribuir](CONTRIBUTING.md)
- [Política de seguridad](SECURITY.md)
- [Cómo obtener ayuda](SUPPORT.md)
- [Código de conducta](CODE_OF_CONDUCT.md)
- [Política sobre IA y LLM](AI_POLICY.md)

## Enlaces

- [Incidencias en Codeberg](https://codeberg.org/damian-buho/systemlint/issues)
- [Incidencias en GitHub](https://github.com/damian-buho/systemlint/issues)
- [Especificación de Projectfile](https://projectfile.org)

## Licencia

Este proyecto se publica bajo la licencia AGPL-3.0-only — consulta el archivo [LICENSE](../../LICENSE) para más detalles.

<!-- textlint-enable -->
