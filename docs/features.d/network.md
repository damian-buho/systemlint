<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# What the host exposes to the network

- Sockets listening beyond the loopback are matched to the services that answer anyone who reaches them, such as Docker’s plain API, memcached over UDP or `cups-browsed`, with the program that holds each port. See [listening sockets](how-to/services.md#listening-sockets).
- The firewall is judged by what it does, not what it says: nftables chains are followed through every jump to tell whether anything sent to the host is ever dropped, and an installed ufw left off is named.
- A system service listening on a port the kernel may hand to an outgoing connection is caught before the two collide at boot.
- Redis and MongoDB open without a password, an SNMP community anyone guesses, Postfix telling strangers which addresses exist, and telnet, rsh, TFTP and NIS servers are each a finding.
- With `--network`, nameservers are asked whether they resolve for this host and certificates are fetched to catch expiry and broken trust, with timeouts, retries and proxies from the environment. See [network probes](how-to/collectors.md#network-probes).
