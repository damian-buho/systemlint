<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Fixes it makes itself, through the tools that own them

- `systemlint fix` applies the fixes a report prints, on the live host or on an image’s root filesystem with `--root`, and asks first; a second run changes nothing. See [remedies](how-to/rules.md#remedies).
- Each fix goes through the tool that owns the setting: `sysctl --load` after a drop-in, `visudo --check` before a sudoers line is installed, `systemctl mask`, `dockerd --validate` before Docker restarts.
- A fix only takes access away: it clears permission bits, gives a file to root, comments out a line that grants access or blocks a module, so a ruleset you did not write can never open the host up.
- A line edited since the lint, a kernel module in use and an account’s only authorized key are left alone, so a fix never locks you out.
