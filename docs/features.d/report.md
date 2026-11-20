<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Findings a person, a pipeline and a screen reader can read

- Each failing rule is one block with its level, a 0.0–9.9 score, its title, why it matters, every subject it hit and one fix in numbered steps, the worst first. See [rules](how-to/rules.md).
- An S to F rating and one count per row close the run, and tell the rules you can still turn on apart from those the host has nothing for.
- `--plain` prints one tab-separated line per finding, for `grep`, `awk` and screen readers, and colour never carries meaning alone and turns off under `NO_COLOR`, `TERM=dumb` or a pipe.
- Counts and sizes are grouped and scaled the way the reader’s locale writes them.
