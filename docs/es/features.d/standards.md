<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Reglas que citan los estándares que cumplen

- Las reglas llevan como etiquetas los controles de CIS Ubuntu Linux 26.04, DISA STIG, CIS Controls v8, NIST SP 800-53 y 800-171, PCI DSS 4, ISO 27001:2022, HIPAA y las líneas base de dev-sec, así `--tags cis`, `--tags 'cis-ubuntu-26.04:5.2.*'` o `--tags pci-dss` ejecuta un estándar o una de sus secciones. Ver [reglas](../how-to/rules.md).
- Una regla que coincide con una prueba de Lynis la nombra, así un equipo que viene de Lynis conserva sus puntos de referencia.
- Donde dos estándares se contradicen, como la rotación forzada de contraseñas frente a NIST SP 800-63B, la ejecución informa un conflicto y no hace fallar al host por ninguno, y `--prefer 'cis-ubuntu-26.04:*'` permite que un estándar gane cada conflicto. Ver [estándares en conflicto](../how-to/rule-book.md#conflicting-standards).
- Un umbral que elige un estándar toma por defecto el número de ese estándar y cambia con `--var`, y una exención con fecha de caducidad silencia un hallazgo que aceptas hasta que vence de nuevo.

<!-- textlint-enable -->
