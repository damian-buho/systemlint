<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Failing disks and full filesystems before they take the host down

- Disks are judged by their own health checks: NVMe and ATA SMART failures and wear, software RAID arrays that lost a member, Btrfs device errors and temperature sensors whose alarm is raised.
- Filesystems close to full, kernel file and async IO tables near their limit, and virtual memory settings that stall writers or run out of memory early are reported before the next write fails.
- Services still running code an upgrade replaced on disk, updates that take effect only after a reboot, and failed units are listed with the service to restart. See [running services](how-to/services.md#running-services).
- Time synchronisation left off or with no server named, and a journal that keeps nothing across reboots, are caught before logs and certificates go wrong.
