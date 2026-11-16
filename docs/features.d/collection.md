<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Fast, read-only collection

- Collectors run in parallel, so a full check is quick enough for every boot, deploy and CI job. See [collectors](how-to/collectors.md).
- Collection only reads: every file, command and response has a size and time limit, so a hung mount or a huge file never stalls the run.
- With `--root`, an image’s symbolic links resolve inside the image, so linting an untrusted image never reads the host’s files.
