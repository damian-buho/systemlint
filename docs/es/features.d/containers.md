<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# El host y cada contenedor en una sola ejecución

- `--containers` encuentra cada contenedor en ejecución, incluidos los anidados, y revisa cada uno desde dentro con sus propios espacios de nombres, etiqueta de AppArmor y capacidades, así un contenedor se juzga tal como se ejecuta. Ver [contenedores](../how-to/collectors.md#containers).
- Un hallazgo compartido por muchos contenedores es un solo bloque que los nombra, y los contenedores de una misma imagen se juzgan como uno.
- Un archivo que falla y que el contenedor nunca cambió se atribuye a su imagen, con el paso de construcción que lo arregla, mientras que uno cambiado en ejecución es deriva propia del contenedor.
- Las revisiones exclusivas del host, como el kernel, el cargador de arranque y el hardware, se apartan dentro de los contenedores en lugar de fallar allí.

<!-- textlint-enable -->
