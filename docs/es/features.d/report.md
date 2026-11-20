<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Hallazgos que leen una persona, un pipeline y un lector de pantalla

- Cada regla que falla es un bloque con su nivel, una puntuación de 0.0 a 9.9, su título, por qué importa, cada sujeto afectado y un arreglo en pasos numerados, el peor primero. Ver [reglas](../how-to/rules.md).
- Una calificación de S a F y un recuento por fila cierran la ejecución, y separan las reglas que aún puedes activar de las que no tienen nada que juzgar en el host.
- `--plain` imprime una línea separada por tabuladores por hallazgo, para `grep`, `awk` y lectores de pantalla, y el color nunca lleva el significado por sí solo y se apaga con `NO_COLOR`, `TERM=dumb` o una tubería.
- Los recuentos y tamaños se agrupan y se escalan como los escribe la configuración regional del lector.

<!-- textlint-enable -->
