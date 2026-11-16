<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Fixes it makes itself, and only ones that take access away

- `systemlint fix` makes the changes a report prints as `Run:` lines, on the live host or on an image’s root filesystem with `--root`, and asks first. See [remedies](how-to/rules.md#remedies).
- A fix only removes access: it clears permission bits, gives a file to root or comments out a line that grants access, so a ruleset you did not write can never hand a file to a user.
- A line edited since the lint is left alone, and an account’s only authorized key is kept, so a fix never locks you out.
- Two apt sources that duplicate each other list as one problem with one fix, not two findings.
