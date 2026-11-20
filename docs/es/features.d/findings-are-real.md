<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Cada hallazgo es real

- Una regla falla solo ante un riesgo, nunca por la mera presencia: la unidad generada de un snap, el propio entorno de una imagen de contenedor o una ruta de solo lectura propiedad de root son normales para su dueño y no dan aviso. Ver [el libro de reglas](../how-to/rule-book.md).
- Lo que la ejecución no pudo revisar dice por qué: `Not run` nombra el privilegio que faltó, `Unknown` significa que falta un hecho que debería existir, y un programa que no está instalado simplemente no es nada que revisar.
- Un conjunto de reglas nombra los hosts para los que está escrito, así en cualquier otro host sus reglas responden no aplicable y quedan fuera de la calificación. Ver [reglas](../how-to/rules.md).
- Donde un estándar admite que un host puede necesitar algo, la regla lo deja en paz: un módulo del kernel en uso, overlay donde se ejecutan contenedores, squashfs donde se usan snaps, nunca se piden bloqueados.
- Un procedimiento que ningún hecho puede probar es una regla manual, listada para que una persona la revise y nunca contada como superada.

<!-- textlint-enable -->
