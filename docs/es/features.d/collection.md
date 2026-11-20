<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Recolectar una vez, juzgar en cualquier lugar

- Recolectar los hechos y juzgarlos son pasos separados: guarda un documento de hechos de un host y júzgalo después contra cuantas políticas quieras, en otra máquina, más tarde, sin acceso al host. Ver [recolectores](../how-to/collectors.md).
- La misma ejecución analiza un host en vivo, un sistema de archivos raíz montado con `--root` o el entorno de una imagen de contenedor con `--image-config`, así una imagen de referencia se revisa antes de publicarse.
- Los recolectores se ejecutan en paralelo y cada archivo, comando y respuesta tiene un límite de tamaño y de tiempo, así un montaje NFS muerto o un registro enorme nunca detiene la ejecución.
- Un documento guardado recuerda cuándo se recolectó: los hechos que caducan, como los procesos en ejecución, expiran y sus reglas informan `Not run` en lugar de juzgar el host de ayer.

<!-- textlint-enable -->
