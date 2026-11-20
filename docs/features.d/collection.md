<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Collect once, judge anywhere

- Collecting facts and judging them are separate steps: save one facts document from a host, then judge it against any number of policies, on another machine, later, with no access to the host. See [collectors](how-to/collectors.md).
- The same run lints a live host, a mounted root filesystem with `--root`, or a container image’s environment with `--image-config`, so a golden image is checked before it ships.
- Collectors run in parallel and every file, command and answer has a size and time limit, so a dead NFS mount or a huge log never stalls the run.
- A saved document remembers when it was collected: facts that go stale, such as running processes, expire and their rules report `Not run` instead of judging yesterday’s host.
