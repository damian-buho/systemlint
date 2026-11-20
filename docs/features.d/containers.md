<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# The host and every container in one run

- `--containers` finds every running container, nested ones included, and checks each from inside with its own namespaces, AppArmor label and capabilities, so a container is judged as it really runs. See [containers](how-to/collectors.md#containers).
- A finding shared by many containers is one block that names them, and containers of one image are judged as one.
- A failing file the container never changed is blamed on its image with the build step to fix it, while one changed at runtime is the container’s own drift.
- Host-only checks such as the kernel, the boot loader and the hardware stand aside inside containers instead of failing there.
