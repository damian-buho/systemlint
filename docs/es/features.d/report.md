<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Hallazgos que leen una persona, un pipeline y un lector de pantalla

- Cada regla que falla es un bloque con su nivel, una puntuación de 0.0 a 9.9, su título y por qué importa, cada sujeto afectado y un arreglo, el peor primero. Ver [reglas](../how-to/rules.md).
- Una calificación de S a F y un recuento por fila cierran la ejecución, y separan las reglas que aún puedes activar de las que no tienen nada que juzgar en el host.
- `--plain` imprime una línea separada por tabuladores por hallazgo, para `grep`, `awk` y lectores de pantalla.
- El color solo marca palabras que ya llevan el significado, y se apaga con `NO_COLOR`, `TERM=dumb` o una tubería.
- JSON, SARIF 2.1.0 y el textfile de node-exporter llevan los mismos hallazgos a CI y a monitoreo. Ver [salidas](../how-to/outputs.md).

<!-- textlint-enable -->
