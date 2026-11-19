<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Reglas que citan los estándares que cumplen

- Cada regla lleva como etiquetas los controles que cumple, así `--tags 'cis-ubuntu-26.04:5.2.*'` ejecuta un estándar o una de sus secciones. Ver [reglas](../how-to/rules.md).
- Donde dos estándares se contradicen, como la rotación forzada de contraseñas frente a NIST SP 800-63B, la ejecución informa un conflicto y no hace fallar al host por ninguno, y `--tags all --prefer 'cis-ubuntu-26.04:*'` ejecuta todas las reglas con ese estándar ganando cada conflicto. Ver [estándares en conflicto](../how-to/rule-book.md#conflicting-standards).
- Un umbral que elige un estándar toma por defecto el número de ese estándar y cambia con `--var`, así seguir tu propia política no requiere una regla propia.

<!-- textlint-enable -->
