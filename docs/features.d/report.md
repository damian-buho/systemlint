<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Findings a person, a pipeline and a screen reader can read

- Each failing rule is one block with its level, a 0.0–9.9 score, its title and why it matters, every subject it hit and one fix, the worst just above the summary. See [rules](how-to/rules.md).
- An S to F rating and the counts close the run, so one line says how the host stands.
- `--plain` prints one tab-separated line per finding, for `grep`, `awk` and screen readers.
- Colour only marks words that already carry the meaning, and turns off under `NO_COLOR`, `TERM=dumb` or a pipe.
- JSON, SARIF 2.1.0 and node-exporter textfile carry the same findings for CI and monitoring. See [outputs](how-to/outputs.md).
