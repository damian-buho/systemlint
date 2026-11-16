<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Recolección rápida y de solo lectura

- Los recolectores se ejecutan en paralelo, así una revisión completa es lo bastante rápida para cada arranque, despliegue y trabajo de CI. Ver [recolectores](../how-to/collectors.md).
- La recolección solo lee: cada archivo, comando y respuesta tiene un límite de tamaño y de tiempo, así un montaje colgado o un archivo enorme nunca detiene la ejecución.
- Con `--root`, los enlaces simbólicos de una imagen se resuelven dentro de la imagen, así analizar una imagen no confiable nunca lee los archivos del host.

<!-- textlint-enable -->
