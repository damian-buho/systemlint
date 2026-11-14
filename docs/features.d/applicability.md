<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Rules that know which hosts they are for

- A ruleset names the hosts it is written for, so on any other host its rules answer not applicable, never unknown or failed, and stay out of the rating. See [rules](how-to/rules.md).
- The shipped apt rules judge Debian, Ubuntu and the distributions built on them, and stand aside everywhere else. See [apt sources](how-to/apt.md).
- A procedure no fact can prove is a manual rule, listed for a person to review and never counted as a pass.
