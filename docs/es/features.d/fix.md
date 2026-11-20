<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Arreglos que hace por sí mismo, con las herramientas que los gestionan

- `systemlint fix` aplica los arreglos que imprime un informe, en el host en vivo o en el sistema de archivos raíz de una imagen con `--root`, y pregunta antes; una segunda ejecución no cambia nada. Ver [remedios](../how-to/rules.md#remedies).
- Cada arreglo pasa por la herramienta que gestiona el ajuste: `sysctl --load` tras un fragmento, `visudo --check` antes de instalar una línea de sudoers, `systemctl mask`, `dockerd --validate` antes de reiniciar Docker.
- Un arreglo solo quita acceso: borra bits de permiso, da un archivo a root, comenta una línea que concede acceso o bloquea un módulo, así un conjunto de reglas que no escribiste nunca puede abrir el host.
- Una línea editada desde el análisis, un módulo del kernel en uso y la única clave autorizada de una cuenta se dejan intactos, así un arreglo nunca te deja fuera.

<!-- textlint-enable -->
