<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Seguro de ejecutar como root en un host en el que no confías

- Cada ruta se lee dentro de la raíz que se revisa, así un enlace simbólico de una imagen no confiable nunca puede hacer que el escaneo lea los archivos del propio host.
- Cada complemento es un programa estático separado que solo convierte en hechos los bytes que leyó el núcleo; no abre ningún archivo, no ejecuta ningún comando y no toca la red. Ver [protocolo](../how-to/protocol.md).
- Los complementos, recolectores y conjuntos de reglas se cargan solo desde directorios propiedad de root o tuyos y escribibles por nadie más, y un recolector escrito en línea en un archivo de configuración no puede ejecutar un comando.
- Nada sale del host salvo que `--network` lo pida.

<!-- textlint-enable -->
