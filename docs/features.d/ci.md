<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# In every pipeline and on every dashboard

- JSON, SARIF 2.1.0 and node-exporter textfile carry the same findings, so code scanning, Prometheus and Alertmanager see what a person sees. See [outputs](how-to/outputs.md).
- A GitHub Action lints a container image’s root without running it and uploads SARIF with a job summary. See [CI](how-to/ci.md).
- Each kind of failure has its own exit code, so a pipeline tells a failing host from a broken ruleset or an unreadable input.
