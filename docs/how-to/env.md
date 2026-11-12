<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Environment variables

The `env-*` collectors read the environment variables a host hands to its
programs, one environment per system file, systemd unit, running service or
image config, and the `env` ruleset judges the variables that inject code,
turn off TLS checks, carry credentials or open the `PATH`.

```sh
sudo systemlint lint --tags env
systemlint lint --root rootfs --image-config config.json --tags env
```

## Collectors

All five use `systemlint-env` and land under `env.<source>.<environment>`.

| Collector | Reads | Facts at |
| --- | --- | --- |
| `env-files` | `/etc/environment`, `/etc/profile.d/*.sh`, `/etc/ld.so.preload` | `env.files.<path>` |
| `env-defaults` | `/etc/default/*`, the usual `EnvironmentFile=` targets | `env.defaults.<path>` |
| `env-units` | `systemctl show` on a live host, else the `.service` files and drop-ins | `env.units.<unit>` |
| `env-processes` | `/proc/<pid>/environ`, `cgroup` and `stat`, live and as root only | `env.processes.<unit or container>` |
| `env-image` | the file given with `--image-config` | `env.image.<path>` |

- **System files**: only plain assignments count, `NAME=value` or
  `export NAME=value` at the start of a line, quoted as a shell reads them;
  an indented line, or any other code, is skipped, since running it would mean
  running the file. `/etc/ld.so.preload` becomes that file’s `LD_PRELOAD`.
- **Units**: `Environment=` and the paths of `EnvironmentFile=`, merged as
  systemd does: the unit file from the highest of `/etc`, `/run`,
  `/usr/local/lib` and `/usr/lib` (`/lib`), then every drop-in by name, an
  empty value resetting the list. `systemctl show` gives the loaded units the
  same way; the contents of an `EnvironmentFile=` are read only where
  `env-defaults` lists them, as `/etc/default/*`.
- **Defaults**: a separate collector, so one file only root may read, such as
  a 0600 `/etc/default/cacerts`, fails `env-defaults` alone in an
  unprivileged run and leaves the other system files judged.
- **Running services**: the environment of the top process of each system
  service and each container, the lowest PID whose parent sits outside its
  cgroup, so a forking daemon’s worker never stands in for it. A container is
  named `container:` and the first 12 characters of its ID (Docker, Podman,
  containerd, CRI-O). Reading another user’s `environ` needs root: an
  unprivileged run fails this collector, and its rules answer `unknown`.
  Under `--root` it is skipped.
- **Image config**: an image’s `ENV` lives in its config, not in its root
  filesystem. `--image-config` takes an OCI image config
  (`skopeo inspect --config`), a Docker image JSON, or `docker inspect` output
  for one image.

Each environment holds:

| Key | Meaning |
| --- | --- |
| `kind` | `file`, `unit`, `process` or `image` |
| `vars` | every variable by name |
| `path` | the `PATH` entries, when `PATH` is set; an entry starting with `$`, an unexpanded reference, is left out |
| `environment-files` | a unit’s `EnvironmentFile=` paths, a leading `-` removed |
| `pid` | a running service’s process ID |

### Values and hashes

A value stays in clear only for the names the rules read and that hold no
secret: `PATH`, `LANG`, `LANGUAGE`, `LC_*`, `LD_*`, every `*_proxy` (any case,
a password in the URL replaced by `[redacted]`), `NODE_OPTIONS`,
`NODE_TLS_REJECT_UNAUTHORIZED`, `GIT_SSL_NO_VERIFY`, `PYTHONHTTPSVERIFY`,
`CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR` and `REQUESTS_CA_BUNDLE`.
Every other non-empty value becomes `hmac-sha256:` and a keyed hash, so a rule
still sees whether a variable is set, empty, or equal to another.

The core draws a random key per run, so a hash of a short secret cannot be
looked up in a table. To compare documents from several hosts, set one key of
16 characters or more:

```yaml
collect:
  hash-key: a long random text kept with the configuration
```

`meta.hash-key` says whether the key was `random` or `configured`, with an
`id` that is equal in two documents exactly when their hashes compare.

## Rules

| Rule | Severity | Fails when an environment sets |
| --- | --- | --- |
| `env/ld-preload` | error | `LD_PRELOAD` or `LD_AUDIT`, `/etc/ld.so.preload` included |
| `env/ld-library-path` | warning | `LD_LIBRARY_PATH` |
| `env/interpreter-injection` | warning | `NODE_OPTIONS` with `--require`, `-r`, `--import` or a loader; `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `BASH_ENV` or `PROMPT_COMMAND` |
| `env/tls-verify` | error | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0` or any `GIT_SSL_NO_VERIFY` |
| `env/ca-override` | info | `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR` or `REQUESTS_CA_BUNDLE` |
| `env/proxy-http` | info | an `http_proxy`, `https_proxy` or `all_proxy` of `http://` to a host other than loopback |
| `env/secret-name` | warning | a non-empty credential-shaped name (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*API_KEY*`, …) in a file, unit or image; a running process is skipped, as it may have read the value from a secret store |
| `env/path-entry` | warning | a relative or empty `PATH` entry |

A subject is the source and the environment, such as
`units, app.service` or `defaults, /etc/default/app`. A rule names the first
offending variable of an environment; the fix of one shows the next.
World-writable `PATH` directories are judged for Debian’s default `PATH` by
`files/world-writable` ([File permissions](files.md)), not yet for the
entries an environment sets.
