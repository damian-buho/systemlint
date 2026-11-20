<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Permisos de archivos que importan, no cada bit

- Los archivos que conceden root, guardan hashes de contraseñas o claves del host, o están en el `PATH`, se reservan a root, y también se revisa cada directorio por encima de un programa con set-user-ID, pues un directorio padre escribible equivale a un programa escribible. Ver [archivos](../how-to/files.md).
- El directorio personal de cada usuario, `~/.ssh` y las claves autorizadas se revisan desde fuera: un archivo de claves escribible por todos, una RSA corta o una clave DSA, un directorio personal al que otros pueden entrar.
- Se nombran los montajes que respetan los bits set-user-ID, los archivos de dispositivo o los programas donde cualquier usuario puede escribir, tanto en `/etc/fstab` como tal como están montados ahora.
- Las cuentas se revisan en conjunto en `passwd`, `shadow` y `group`: un segundo root, un nombre o ID repetido, una cuenta sin contraseña.

<!-- textlint-enable -->
