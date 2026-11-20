<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Every finding is real

- A rule fails only on a risk, never on mere presence: a snap’s generated unit, a container image’s own environment or a root-owned read-only path is normal for its owner and stays quiet. See [the rule book](how-to/rule-book.md).
- What the run could not check says why: `Not run` names the privilege it lacked, `Unknown` means a fact that should exist is missing, and a program that is not installed is simply nothing to check.
- A ruleset names the hosts it is written for, so on any other host its rules answer not applicable and stay out of the rating. See [rules](how-to/rules.md).
- Where a standard admits a host may need something, the rule leaves it alone: a kernel module in use, overlay where containers run, squashfs where snaps do, are never asked to be blocked.
- A procedure no fact can prove is a manual rule, listed for a person to review and never counted as a pass.
