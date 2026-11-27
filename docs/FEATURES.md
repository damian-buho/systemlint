<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

[Español](es/FEATURES.md) · [Українська](uk/FEATURES.md)

# Features

## Project Features

### In every pipeline and on every dashboard

- JSON, SARIF 2.1.0 and node-exporter textfile carry the same findings, so code scanning, Prometheus and Alertmanager see what a person sees. See [outputs](how-to/outputs.md).
- A GitHub Action lints a container image’s root without running it and uploads SARIF with a job summary. See [CI](how-to/ci.md).
- Each kind of failure has its own exit code, so a pipeline tells a failing host from a broken ruleset or an unreadable input.

### Collect once, judge anywhere

- Collecting facts and judging them are separate steps: save one facts document from a host, then judge it against any number of policies, on another machine, later, with no access to the host. See [collectors](how-to/collectors.md).
- The same run lints a live host, a mounted root filesystem with `--root`, or a container image’s environment with `--image-config`, so a golden image is checked before it ships.
- Collectors run in parallel and every file, command and answer has a size and time limit, so a dead NFS mount or a huge log never stalls the run.
- A saved document remembers when it was collected: facts that go stale, such as running processes, expire and their rules report `Not run` instead of judging yesterday’s host.

### The host and every container in one run

- `--containers` finds every running container, nested ones included, and checks each from inside with its own namespaces, AppArmor label and capabilities, so a container is judged as it really runs. See [containers](how-to/collectors.md#containers).
- A finding shared by many containers is one block that names them, and containers of one image are judged as one.
- A failing file the container never changed is blamed on its image with the build step to fix it, while one changed at runtime is the container’s own drift.
- Host-only checks such as the kernel, the boot loader and the hardware stand aside inside containers instead of failing there.

### Settings judged as the program applies them

- OpenSSH is asked for its own effective settings, once globally and once per account, so a `Match` block that turns password login back on for one user is found, with no configuration parser to fool. See [sshd](how-to/sshd.md).
- sudo grants and `Defaults` come from sudo itself, classic sudo and sudo-rs alike, with includes, aliases and groups settled, and a sudoers line sudo silently skips as broken is reported.
- PAM stacks, `login.defs`, password quality and resource limits are read in the order and precedence their libraries use, so the line that wins is the line judged. See [authentication](how-to/auth.md).
- Kernel settings and module blocklists come from `sysctl` and `modprobe` when they run, and from their drop-in directories in the same order otherwise, so a mounted image is judged like the booted host.
- A log file’s mode is judged against what recreates it: a log that logrotate will reopen with safe permissions is not a finding, its rotation rule is.

### File permissions that matter, not every bit

- Files that grant root, hold password hashes or host keys, or sit in the `PATH` are kept to root, and every directory above a set-user-ID program is checked too, since a writable parent is as good as a writable program. See [files](how-to/files.md).
- Each user’s home, `~/.ssh` and authorized keys are checked from the outside: a world-writable key file, a short RSA or a DSA key, a home others can enter.
- Mounts that honour set-user-ID bits, device files or programs where every user can write are named, both in `/etc/fstab` and as they are mounted now.
- Accounts are checked across `passwd`, `shadow` and `group` together: a second root, a repeated name or ID, an account with no password.

### Every finding is real

- A rule fails only on a risk, never on mere presence: a snap’s generated unit, a container image’s own environment or a root-owned read-only path is normal for its owner and stays quiet. See [the rule book](how-to/rule-book.md).
- What the run could not check says why: `Not run` names the privilege it lacked, `Unknown` means a fact that should exist is missing, and a program that is not installed is simply nothing to check.
- A ruleset names the hosts it is written for, so on any other host its rules answer not applicable and stay out of the rating. See [rules](how-to/rules.md).
- Where a standard admits a host may need something, the rule leaves it alone: a kernel module in use, overlay where containers run, squashfs where snaps do, are never asked to be blocked.
- A procedure no fact can prove is a manual rule, listed for a person to review and never counted as a pass.

### Fixes it makes itself, through the tools that own them

- `systemlint fix` applies the fixes a report prints, on the live host or on an image’s root filesystem with `--root`, and asks first; a second run changes nothing. See [remedies](how-to/rules.md#remedies).
- Each fix goes through the tool that owns the setting: `sysctl --load` after a drop-in, `visudo --check` before a sudoers line is installed, `systemctl mask`, `dockerd --validate` before Docker restarts.
- A fix only takes access away: it clears permission bits, gives a file to root, comments out a line that grants access or blocks a module, so a ruleset you did not write can never open the host up.
- A line edited since the lint, a kernel module in use and an account’s only authorized key are left alone, so a fix never locks you out.

### Kernel and CPU hardening, as the running kernel reports it

- CPU flaws the running kernel reports as unmitigated, and kernel settings that hand unprivileged users memory layouts, kernel addresses or extra attack surface, are each a finding.
- Kernel modules for rare filesystems, protocols and devices that load on demand are found from the modules shipped for every installed kernel, and a USB controller that trusts every new device is reported. See [kernel modules](how-to/services.md#kernel-modules).
- Audit rules are judged by what they record, on disk and loaded, not by one standard’s spelling, so an equivalent rule written another way passes. See [kernel audit rules](how-to/services.md#kernel-audit-rules).
- AppArmor not loaded, a GRUB menu anyone may edit, a rescue shell that asks for no password and core dumps of privileged programs are each a finding.

### What the host exposes to the network

- Sockets listening beyond the loopback are matched to the services that answer anyone who reaches them, such as Docker’s plain API, memcached over UDP or `cups-browsed`, with the program that holds each port. See [listening sockets](how-to/services.md#listening-sockets).
- The firewall is judged by what it does, not what it says: nftables chains are followed through every jump to tell whether anything sent to the host is ever dropped, and an installed ufw left off is named.
- A system service listening on a port the kernel may hand to an outgoing connection is caught before the two collide at boot.
- Redis and MongoDB open without a password, an SNMP community anyone guesses, Postfix telling strangers which addresses exist, and telnet, rsh, TFTP and NIS servers are each a finding.
- With `--network`, nameservers are asked whether they resolve for this host and certificates are fetched to catch expiry and broken trust, with timeouts, retries and proxies from the environment. See [network probes](how-to/collectors.md#network-probes).

### Findings a person, a pipeline and a screen reader can read

- Each failing rule is one block with its level, a 0.0–9.9 score, its title, why it matters, every subject it hit and one fix in numbered steps, the worst first. See [rules](how-to/rules.md).
- An S to F rating and one count per row close the run, and tell the rules you can still turn on apart from those the host has nothing for.
- `--plain` prints one tab-separated line per finding, for `grep`, `awk` and screen readers, and colour never carries meaning alone and turns off under `NO_COLOR`, `TERM=dumb` or a pipe.
- Counts and sizes are grouped and scaled the way the reader’s locale writes them.

### Secrets and injected code in every environment

- The environments of system files, unit files, running services, containers and images are searched for credentials, `LD_PRELOAD` code injection, turned-off TLS checks and an empty or relative entry in `PATH`. See [environments](how-to/env.md).
- Every value is replaced by a keyed hash before it reaches a plugin, the facts document or the report, so a scan never copies a secret anywhere.
- Plain-text passwords in `~/.netrc`, `.rhosts` trust that an installed rsh honours, and readable PostgreSQL, Squid and CUPS configurations are each reported where other users can reach them.

### Failing disks and full filesystems before they take the host down

- Disks are judged by their own health checks: NVMe and ATA SMART failures and wear, software RAID arrays that lost a member, Btrfs device errors and temperature sensors whose alarm is raised.
- Filesystems close to full, kernel file and async IO tables near their limit, and virtual memory settings that stall writers or run out of memory early are reported before the next write fails.
- Services still running code an upgrade replaced on disk, updates that take effect only after a reboot, and failed units are listed with the service to restart. See [running services](how-to/services.md#running-services).
- Time synchronisation left off or with no server named, and a journal that keeps nothing across reboots, are caught before logs and certificates go wrong.

### Rules that cite the standards they satisfy

- Rules carry the controls of CIS Ubuntu Linux 26.04, DISA STIG, CIS Controls v8, NIST SP 800-53 and 800-171, PCI DSS 4, ISO 27001:2022, HIPAA and the dev-sec baselines as tags, so `--tags cis`, `--tags 'cis-ubuntu-26.04:5.2.*'` or `--tags pci-dss` runs one standard or one of its sections. See [rules](how-to/rules.md).
- A rule that matches a Lynis test names it, so a team moving from Lynis keeps its reference points.
- Where two standards contradict each other, such as forced password rotation against NIST SP 800-63B, the run reports one conflict and fails the host on neither, and `--prefer 'cis-ubuntu-26.04:*'` lets one standard win every conflict. See [conflicting standards](how-to/rule-book.md#conflicting-standards).
- A threshold a standard picks defaults to that standard’s number and changes with `--var`, and a waiver with an expiry date silences a finding you accept until it is due again.

### Safe to run as root on a host you do not trust

- Every path is read inside the root being checked, so a symbolic link in an untrusted image can never make the scan read the host’s own files.
- Each plugin is a separate static program that only turns bytes the core read into facts; it opens no file, runs no command and touches no network. See [protocol](how-to/protocol.md).
- Plugins, collectors and rulesets load only from directories owned by root or by you and writable by no one else, and a collector written inline in a configuration file may not run a command.
- Nothing leaves the host unless `--network` asks for it.

## Inherited from B19 / Ubuntu

### Persistent APT cache across builds

- Package downloads and index caches persist across builds, so repeated builds skip redundant downloads.
- Cache is keyed by Ubuntu series and architecture, avoiding cross-contamination.
- Optional LAN APT cacher proxy can be enabled for faster local builds.

### Service process management with log routing (b19-exec)

- Long-running processes (daemons, servers) have stdout and stderr automatically routed through the structured logger.
- Every signal reaches the service exactly once, so `docker stop` ends it gracefully and its last log lines are kept.
- Log levels for stdout and stderr streams are independently configurable.
- Several daemons share one container: each line is tagged with its daemon, they stop in reverse start order, and a crashed required daemon stops the container so the restart policy acts.
- Passthrough mode hands a service’s own log to the collector byte for byte, so parsers built for that daemon still match.

### Cached artifact downloads with integrity verification

- Downloads are cached locally and in BuildKit persistent storage, so repeated fetches are served from cache.
- SHA-512 hash verification runs at every tier; mismatches fall through to the next source rather than failing.
- Offgrid mode blocks all downloads entirely, failing fast with a clear error on cache miss.
- Supports a near-cache proxy for LAN-only builds that route through a caching proxy.

### Timed command execution with failure reporting (b19-run)

- Any command can be wrapped to get automatic elapsed-time measurement and success/failure reporting.
- Success output is visible only at higher verbosity levels; failure output is always shown.
- In debug mode, command output streams live instead of being buffered.

### Run-once initialization (bootstrap.d)

- One-time setup tasks (database migrations, admin user creation, directory init) run on first container start only.
- Automatic idempotency: completed scripts are never re-run, even across container restarts.
- Failed scripts are retried on next start; successful ones stay locked.
- State can be reset by clearing a volume, triggering a full re-bootstrap.
- Downstream images add their own init scripts by dropping them into a directory.

### Modular build hooks (build.d)

- Build logic lives in composable hook scripts instead of inline Dockerfile commands, making it easy to read, test, and reuse.
- Cross-cutting setup (CA trust, locale, shared installs) is written once and runs on every stage automatically.
- Downstream images inherit parent build logic through the layer overlay — no duplication needed.
- Non-inheritable one-off setup is cleaned up after execution to avoid leaking into later stages.

### Compromised certificate authorities distrusted ahead of upstream

- Certificates listed by SHA-256 fingerprint are removed from the system trust store at build time, before the distribution ships its own fix.
- One list serves the whole image lineage, and `b19-ca-distrust bundle` cuts any vendored PEM bundle from it too.
- Ships distrusting the eMudhra intermediates whose private keys can be recovered (October 2026), together with their cross-signs and roots.
- Downstream images add fingerprints with one variable or one file, and `B19_CA_DISTRUST_ENABLED=false` turns the cut off. [How-to](https://codeberg.org/b19/ubuntu/src/branch/main/docs/how-to/use-ca-distrust.md)

### Automatic CPU count detection

- CPU count is detected automatically across Docker, Kubernetes, and CI environments without manual configuration.
- Eliminates hardcoded job counts — parallel compilation, template rendering, and tests use the right parallelism everywhere.
- The detected count is available throughout build and runtime for any tool that needs it.

### Declarative dependency management (b19-deps)

- External dependency metadata (URL, version, SHA-512 hash) stored as plain text files, completely separate from build scripts.
- Supports architecture-specific downloads, multi-version series, and nested component paths.
- Dependencies are auto-discovered at Makefile parse time — add files to the right directory and the build picks them up without manual declarations.
- `make fetch` pre-downloads everything for offline builds; version bumps trigger automatic re-fetch and hash updates.

### Pluggable startup system (entrypoint.d)

- Composable hook chain handles signal setup, secrets loading, CPU detection, port validation, template rendering, bootstrap, and service start in order.
- Ad-hoc commands bypass the startup chain automatically and execute directly.
- Individual hooks or the entire entrypoint can be skipped at runtime via environment variables, no image rebuild needed.
- Downstream images override a single hook to launch their service; everything else is inherited.

### Feature toggles for all subsystems

- Every major subsystem (entrypoint, healthchecks, bootstrap, tests, secrets, port validation, i18n, shell hooks) can be disabled at runtime via environment variables.
- Individual entrypoint, bootstrap and health-check hooks can be skipped by name without disabling the whole subsystem.
- No image rebuild required — toggles are runtime-only.

### Built-in health monitoring (healthcheck.d)

- Docker-native healthcheck inherited by every downstream image with no extra configuration, plus a separate liveness answer for Kubernetes: a slow dependency only takes the container out of rotation, and only a dead process restarts it.
- Egress checks are opt-in: a container that never reaches the internet carries no check a third party can fail, while one whose job is the internet reports unhealthy the moment the outside is gone.
- Works the same offline as online — egress checks stand down automatically under offgrid mode.
- Adding a check is dropping a script in a directory, not writing Docker plumbing.
- Heavy or rate-limited checks run hourly in the background, so a slow scan never times out the probe or burns a rate limit.

See [use-healthcheck.d](https://codeberg.org/b19/ubuntu/src/branch/main/docs/how-to/use-healthcheck.d.md) for the check list, slot numbering, and configuration.

### Multilingual shell output (b19-i18n)

- All user-facing log messages and script output are translatable via GNU gettext.
- Ships with English, Spanish (`es_CL`), and Ukrainian (`uk_UA`) out of the box.
- Downstream images inherit all parent translations automatically; only new or overridden strings need translating.
- Translations are compiled at build time with no runtime overhead.

### Image lineage tracking

- Every image records its build metadata (namespace, project, version, base image) into a lineage file during build.
- Downstream images chain lineage from their parent, producing a full base-to-current provenance chain.
- The full lineage chain is logged at startup (debug verbosity) and readable from the file at any time, making it easy to trace what a running container was built from.

### Structured, level-filtered logging (b19-log)

- All container output goes through a leveled logger with four thresholds: error, warn, info, debug.
- Messages below the configured verbosity are silently discarded, keeping production logs clean.
- Colors auto-detect terminal support and respect `NO_COLOR=1`.
- Pipable: command output can be routed through the logger to apply level filtering and tags.
- `B19_LOG_FORMAT=json` turns every line into one JSON object a log pipeline reads without a parser; a service’s own lines become fields too, and the native line stays beside them.

### Non-root container by default

- The container runs as a non-root user (`ubuntu`, UID/GID 1000) with all runtime files owned by that user.
- A two-stage build separates root-level system installation from user-level runtime setup.
- User identity is configurable at build time, and an opt-in root start remaps it to the host user so bind mounts keep their ownership.

### Air-gapped / offline build and runtime support

- A single environment variable (`B19_OFFGRID_MODE=Y`) cuts all internet access at build time and runtime.
- Build-time: downloads are blocked, APT updates are skipped, SSH keyscans are skipped. All artifacts must come from cache tiers.
- Runtime: network healthchecks automatically skip with a healthy result, so containers stay green on isolated networks.
- APT package lists can be snapshotted and injected for fully offline image builds.
- LAN services (caching proxies, registries) remain reachable — offgrid blocks internet, not all networking.

### Runtime overlay injection

- Configuration or data files can be injected at container startup by setting `B19_OVERLAY` to a directory name.
- Overlay contents are recursively copied to the container root, overwriting existing files — no image rebuild needed.
- Skipped in immutable mode, preventing runtime modification of production-locked images.

### Reproducible base image (pinned by digest)

- The Ubuntu base image is pinned by SHA-256 digest, not by tag, ensuring deterministic builds.
- Supports multiple Ubuntu series (resolute, noble, jammy) selectable at build time.
- APT mirrors are configurable per architecture for LAN mirrors or air-gapped environments.

### Port validation

- Every environment variable whose name ends in `PORT` is validated at startup against the WHATWG blocklist of forbidden ports and privileged ports (\<1024).
- Catches misconfigurations like `HTTP_PORT=22` early, before the service fails silently.
- Can be disabled at runtime without rebuilding the image.

### Unified lifecycle runner family

- Every lifecycle concern — startup, healthchecks, tests, bootstrap, build, benchmarks, reports, and shell — follows the same discoverable hook pattern.
- Drop a numbered script into a directory and it is auto-discovered and executed, no wiring required.
- Scripts from different image layers merge, so upstream and downstream hooks coexist without conflict.
- Each runner has tailored failure semantics: abort on error, continue and count failures, or always succeed as appropriate.

### Docker secrets auto-loading

- Docker secrets translate to environment variables automatically at container startup, requiring no code changes.
- Dot-notation filenames map to uppercase env vars, keeping naming consistent and predictable.
- Required secrets can be declared by name; the container refuses to start if any are missing.
- Existing environment variables take precedence over secret-derived values, so overrides are straightforward.
- Binary secrets (keys, DER blobs) stay on disk for file-based reads, avoiding Bash truncation issues.

### Interactive shell hooks

- Shell sessions automatically load Docker secrets and any custom hooks added by downstream images.
- Hooks merge via Docker layer overlay, so inherited and project-specific shell setup coexist without conflict.

### Graceful signal handling

- PID 1 is `catatonit -g`, which reaps zombie processes and forwards signals to the full process group.
- A configurable set of Unix signals (TERM, INT, HUP, USR1, USR2, etc.) is trapped and forwarded to every service process, which stop in reverse start order.
- `docker stop` cleanly terminates the service without orphan processes or signal loss.

### Jinja2 configuration templates (minijinja-cli)

- Jinja2-compatible template rendering at both build time and container startup.
- Drop a `.j2` file anywhere in the app directory; it is discovered at build time and rendered at every startup with all environment variables available.
- Runtime rendering is parallel and automatic — downstream images get it with zero configuration.
- Skip specific templates at runtime with `B19_J2_SKIP_FILES` (comma-separated basenames).
- Runs on a read-only root: templates render into the `/run/b19` tmpfs, and a missing tmpfs stops the start instead of serving build-time values.

### Built-in test framework (test.d)

- Tests run inside the running container via `make test` or `docker exec`.
- Automatically waits for healthchecks to pass before executing.
- No test framework dependency — tests are plain shell scripts with exit codes, and a failed check names what it expected and what it found.
- Supports Jinja2 templates in tests, useful for asserting build-time values at runtime.
- Continues on failure and reports the total count; never hides partial results.

### Nothing hangs forever

- Every startup, test and one-shot step has a time bound, so a wedged tool fails loudly instead of blocking a deploy or a CI run.
- Stalled downloads are aborted, while slow ones of any size still complete.
- A flaky call can be retried with backoff in one flag, without a hand-written loop.
- An opt-in restart turns a service stuck unhealthy into a container the restart policy recovers.

See [use-timeouts](https://codeberg.org/b19/ubuntu/src/branch/main/docs/how-to/use-timeouts.md) for the options, defaults and overrides.

### Pre-installed utility tools

- `mold` as default linker (opt-out available).
- `fd` for file finding, `minijinja-cli` for template rendering.
- `aria2c` for multi-connection downloads, `catatonit` as PID 1 for zombie reaping.
- Parallel compression tools: `pbzip2`, `pigz`, `pixz`.
- gettext tools for i18n compilation, `cURL` for network operations.

### XDG Base Directory paths

- Standard XDG paths (`XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`) are set under the app home directory.
- All paths are writable by the non-root user without privilege escalation.
