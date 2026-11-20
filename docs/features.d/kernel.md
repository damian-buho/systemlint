<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Kernel and CPU hardening, as the running kernel reports it

- CPU flaws the running kernel reports as unmitigated, and kernel settings that hand unprivileged users memory layouts, kernel addresses or extra attack surface, are each a finding.
- Kernel modules for rare filesystems, protocols and devices that load on demand are found from the modules shipped for every installed kernel, and a USB controller that trusts every new device is reported. See [kernel modules](how-to/services.md#kernel-modules).
- Audit rules are judged by what they record, on disk and loaded, not by one standard’s spelling, so an equivalent rule written another way passes. See [kernel audit rules](how-to/services.md#kernel-audit-rules).
- AppArmor not loaded, a GRUB menu anyone may edit, a rescue shell that asks for no password and core dumps of privileged programs are each a finding.
