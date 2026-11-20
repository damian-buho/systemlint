<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Ajustes juzgados como los aplica el programa

- A OpenSSH se le pregunta por sus propios ajustes efectivos, una vez de forma global y una vez por cuenta, así se encuentra un bloque `Match` que vuelve a activar el acceso por contraseña para un usuario, sin un analizador de configuración al que engañar. Ver [sshd](../how-to/sshd.md).
- Las concesiones de sudo y los `Defaults` vienen del propio sudo, tanto el sudo clásico como sudo-rs, con inclusiones, alias y grupos resueltos, y se informa de una línea de sudoers que sudo omite en silencio por estar rota.
- Las pilas de PAM, `login.defs`, la calidad de contraseñas y los límites de recursos se leen en el orden y con la precedencia que usan sus bibliotecas, así la línea que gana es la línea juzgada. Ver [autenticación](../how-to/auth.md).
- Los ajustes del kernel y las listas de bloqueo de módulos vienen de `sysctl` y `modprobe` cuando se ejecutan, y de sus directorios de fragmentos en el mismo orden en caso contrario, así una imagen montada se juzga como el host arrancado.
- El modo de un archivo de registro se juzga según lo que lo recrea: un registro que logrotate reabrirá con permisos seguros no es un hallazgo, lo es su regla de rotación.

<!-- textlint-enable -->
