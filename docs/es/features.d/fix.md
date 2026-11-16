<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Arreglos que hace por sí mismo, y solo los que quitan acceso

- `systemlint fix` hace los cambios que un informe imprime como líneas `Run:`, en el host en vivo o en el sistema de archivos raíz de una imagen con `--root`, y pregunta antes. Ver [remedios](../how-to/rules.md#remedies).
- Un arreglo solo quita acceso: borra bits de permiso, da un archivo a root o comenta una línea que concede acceso, así un conjunto de reglas que no escribiste nunca puede entregar un archivo a un usuario.
- Una línea editada desde el análisis se deja intacta, y se conserva la única clave autorizada de una cuenta, así un arreglo nunca te deja fuera.
- Dos fuentes apt que se duplican se listan como un problema con un arreglo, no como dos hallazgos.

<!-- textlint-enable -->
