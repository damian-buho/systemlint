<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Rules that cite the standards they satisfy

- Each rule carries the controls it satisfies as tags, so `--tags 'cis-ubuntu-26.04:5.2.*'` runs one standard or one of its sections. See [rules](how-to/rules.md).
- Where two standards contradict each other, such as forced password rotation against NIST SP 800-63B, the run reports one conflict and fails the host on neither, and `--tags all --prefer 'cis-ubuntu-26.04:*'` runs every rule with that standard winning each conflict. See [conflicting standards](how-to/rule-book.md#conflicting-standards).
- A threshold a standard picks defaults to that standard’s number and changes with `--var`, so following your own policy needs no rule of your own.
