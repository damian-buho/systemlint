<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# En cada pipeline y en cada panel

- JSON, SARIF 2.1.0 y el textfile de node-exporter llevan los mismos hallazgos, así el escaneo de código, Prometheus y Alertmanager ven lo mismo que una persona. Ver [salidas](../how-to/outputs.md).
- Una GitHub Action analiza la raíz de una imagen de contenedor sin ejecutarla y sube SARIF con un resumen del trabajo. Ver [CI](../how-to/ci.md).
- Cada tipo de fallo tiene su propio código de salida, así un pipeline distingue un host con fallos de un conjunto de reglas roto o una entrada ilegible.

<!-- textlint-enable -->
