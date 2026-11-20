<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# Lo que el host expone a la red

- Los sockets que escuchan más allá del loopback se asocian con los servicios que responden a cualquiera que los alcance, como la API sin cifrar de Docker, memcached sobre UDP o `cups-browsed`, con el programa que mantiene cada puerto. Ver [sockets en escucha](../how-to/services.md#listening-sockets).
- El cortafuegos se juzga por lo que hace, no por lo que dice: las cadenas de nftables se siguen a través de cada salto para saber si algo enviado al host se descarta alguna vez, y se nombra un ufw instalado pero apagado.
- Un servicio del sistema que escucha en un puerto que el kernel puede asignar a una conexión saliente se detecta antes de que ambos choquen en el arranque.
- Redis y MongoDB abiertos sin contraseña, una comunidad SNMP que cualquiera adivina, Postfix que revela a extraños qué direcciones existen, y los servidores telnet, rsh, TFTP y NIS son cada uno un hallazgo.
- Con `--network`, se pregunta a los servidores de nombres si resuelven para este host y se obtienen certificados para detectar caducidad y confianza rota, con tiempos de espera, reintentos y proxies tomados del entorno. Ver [sondeos de red](../how-to/collectors.md#network-probes).

<!-- textlint-enable -->
