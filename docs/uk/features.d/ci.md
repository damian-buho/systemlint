<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

<!-- textlint-disable terminology,common-misspellings -->

# У кожному конвеєрі та на кожній панелі

- JSON, SARIF 2.1.0 і textfile для node-exporter несуть однакові знахідки, тож сканування коду, Prometheus та Alertmanager бачать те саме, що й людина. Див. [виходи](../how-to/outputs.md).
- GitHub Action перевіряє корінь образу контейнера без його запуску та вивантажує SARIF із підсумком завдання. Див. [CI](../how-to/ci.md).
- Кожен вид збою має власний код виходу, тож конвеєр відрізняє хост із порушеннями від зламаного набору правил чи нечитабельного входу.

<!-- textlint-enable -->
