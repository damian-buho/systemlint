<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Endurecimiento del kernel y la CPU, según lo informa el kernel en ejecución

- Los fallos de CPU que el kernel en ejecución informa como no mitigados, y los ajustes del kernel que entregan a usuarios sin privilegios disposiciones de memoria, direcciones del kernel o superficie de ataque adicional, son cada uno un hallazgo.
- Los módulos del kernel de sistemas de archivos, protocolos y dispositivos poco comunes que se cargan bajo demanda se encuentran a partir de los módulos incluidos para cada kernel instalado, y se informa de un controlador USB que confía en cada dispositivo nuevo. Ver [módulos del kernel](../how-to/services.md#kernel-modules).
- Las reglas de auditoría se juzgan por lo que registran, en disco y cargadas, no por la redacción de un estándar, así una regla equivalente escrita de otra manera pasa. Ver [reglas de auditoría del kernel](../how-to/services.md#kernel-audit-rules).
- AppArmor no cargado, un menú de GRUB que cualquiera puede editar, un shell de rescate que no pide contraseña y los volcados de memoria de programas privilegiados son cada uno un hallazgo.

<!-- textlint-enable -->
