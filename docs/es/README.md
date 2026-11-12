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

[![Stand with Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://damian-buho.github.io/support-ukraine/) [![Projectfile inside](https://badges.kiota.ch/static/v1?label=projectfile&message=inside&labelColor=0d0d0d&color=8c6723&style=flat-square)](https://projectfile.org) [![License](https://badges.kiota.ch/static/v1?label=license&message=AGPL-3.0-only&color=1e5913&style=flat-square)](LICENSE) [![Cosign](https://badges.kiota.ch/static/v1?label=cosign&message=enabled&color=1e5913&style=flat-square)](https://docs.sigstore.dev/cosign/verifying/verify/)

![Project status](https://badges.kiota.ch/static/v1?label=status&message=maintained&color=1d63ed&style=flat-square) [![Last commit on kiota.ch](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://kiota.ch&label=last%20commit%20on%20kiota.ch&style=flat-square)](https://kiota.ch/damian-buho/systemlint)

[![Publish pipeline on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/published.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Vulnerability audit on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/audited.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Dependency freshness on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Analysis sweep on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions)

## Características

- Caché APT persistente entre compilaciones
- Gestión de procesos de servicio con enrutado de logs (b19-exec)
- Descargas de artefactos con caché y verificación de integridad (b19-fetch)
- Ejecución de comandos temporizada con informe de fallos (b19-run)
- Inicialización de una sola vez (bootstrap.d)
- Hooks de compilación modulares (build.d)
- Autoridades de certificación comprometidas desconfiadas antes que upstream
- Detección automática del número de CPUs (NUMPROCS)
- Gestión declarativa de dependencias (b19-deps)
- Sistema de arranque conectable (entrypoint.d)
- Conmutadores de funcionalidades para todos los subsistemas
- Monitorización de estado integrada (healthcheck.d)
- Salida de shell multilingüe (b19-i18n)
- Seguimiento del linaje de la imagen
- Logging estructurado con filtro por nivel (b19-log)
- Contenedor sin privilegios de root por defecto
- Soporte de compilación y runtime aislados de internet (air-gapped/offline)
- Inyección de overlays en runtime
- Imagen base reproducible (fijada por digest)
- Validación de puertos
- Familia unificada de runners del ciclo de vida
- Autocarga de secretos de Docker (secrets)
- Hooks de shell interactivo (shell.d)
- Gestión elegante de señales
- Plantillas de configuración Jinja2 (minijinja-cli)
- Framework de tests integrado (test.d)
- Nada se cuelga para siempre
- Herramientas de utilidad preinstaladas
- Rutas XDG Base Directory

Consulta [Características](FEATURES.md) para ver la lista completa.

## Qué entrega este proyecto

- **Ejecutable** `target/release/systemlint`
- **Imagen de contenedor** `kiota.ch/damian-buho/systemlint:latest`

## Plataformas admitidas

- `linux/amd64`
- `linux/arm64`

## Instalación

Descarga la imagen de contenedor publicada:

```sh
docker pull kiota.ch/damian-buho/systemlint:latest
```

Las versiones estables también publican las etiquetas `X.Y.Z`, `X.Y` y `X`: descarga el nivel de precisión que quieras fijar.

## Compilación

Clona el repositorio y ejecuta `make`: cada paso de compilación, destino y punto de entrada está en [Compilación](BUILD.md).

## Documentación

- [apt sources](../how-to/apt.md)
- [Collectors](../how-to/collectors.md)
- [Environment variables](../how-to/env.md)
- [File permissions](../how-to/files.md)
- [Kernel parameters, Docker and systemd units](../how-to/services.md)
- [OpenSSH server](../how-to/sshd.md)
- [Plugin protocol v1](../how-to/protocol.md)
- [Rules, rulesets and compliance](../how-to/rules.md)

## Políticas

- [Cómo contribuir](CONTRIBUTING.md)
- [Política de seguridad](SECURITY.md)
- [Cómo obtener ayuda](SUPPORT.md)
- [Código de conducta](CODE_OF_CONDUCT.md)
- [Política sobre IA y LLM](AI_POLICY.md)

## Enlaces

- [Especificación de Projectfile](https://projectfile.org)

## Licencia

Este proyecto se publica bajo la licencia AGPL-3.0-only — consulta el archivo [LICENSE](LICENSE) para más detalles.

<!-- textlint-enable -->
