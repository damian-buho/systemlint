<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Secretos y código inyectado en cada entorno

- Se buscan en los entornos de archivos del sistema, archivos de unidad, servicios en ejecución, contenedores e imágenes credenciales, inyección de código con `LD_PRELOAD`, verificaciones TLS desactivadas y una entrada vacía o relativa en `PATH`. Ver [entornos](../how-to/env.md).
- Cada valor se sustituye por un hash con clave antes de llegar a un complemento, al documento de hechos o al informe, así un escaneo nunca copia un secreto a ninguna parte.
- Las contraseñas en texto plano en `~/.netrc`, la confianza `.rhosts` que respeta un rsh instalado y las configuraciones legibles de PostgreSQL, Squid y CUPS se informan cada una donde otros usuarios pueden alcanzarlas.

<!-- textlint-enable -->
