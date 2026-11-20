<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Discos que fallan y sistemas de archivos llenos antes de que tumben el host

- Los discos se juzgan por sus propias comprobaciones de salud: fallos y desgaste SMART de NVMe y ATA, matrices RAID por software que perdieron un miembro, errores de dispositivo de Btrfs y sensores de temperatura cuya alarma está activada.
- Los sistemas de archivos casi llenos, las tablas de archivos y de IO asíncrona del kernel cerca de su límite, y los ajustes de memoria virtual que bloquean a los escritores o agotan la memoria antes de tiempo se informan antes de que falle la siguiente escritura.
- Los servicios que aún ejecutan código que una actualización reemplazó en disco, las actualizaciones que solo surten efecto tras un reinicio y las unidades fallidas se listan con el servicio que hay que reiniciar. Ver [servicios en ejecución](../how-to/services.md#running-services).
- La sincronización horaria apagada o sin servidor indicado, y un diario que no conserva nada entre reinicios, se detectan antes de que fallen los registros y los certificados.

<!-- textlint-enable -->
