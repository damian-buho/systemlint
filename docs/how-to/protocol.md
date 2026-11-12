<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>

SPDX-License-Identifier: AGPL-3.0-only
-->

# Plugin protocol v1

A plugin is a separate executable named `systemlint-<name>` that turns bytes
into facts. It reads one JSON request on stdin and writes one JSON reply on
stdout. It never opens a file, runs a command or touches the network: the
systemlint core reads every input and hands the plugin the bytes, so a plugin
behaves the same on a live host and under `--root`.

Rust plugins use the `systemlint-protocol` crate, which holds the types below
and a `run` helper; a plugin is then one function per op:

```rust
fn main() -> std::process::ExitCode {
    systemlint_protocol::run(&my_plugin::describe(), my_plugin::op)
}
```

A plugin in any other language speaks the same JSON.

## Discovery and trust

The core looks for plugins in two places, in this order, and nowhere else:

1. `../lib/systemlint/plugins/` beside the `systemlint` binary, so
   `/usr/local/bin/systemlint` reads `/usr/local/lib/systemlint/plugins/`;
2. every directory the configuration lists under `plugins.directories`,
   relative paths being read from the configuration file’s own directory.

```yaml
plugins:
  directories:
    - /opt/systemlint/plugins
```

A file is a plugin when its name is `systemlint-` followed by lowercase
letters, digits and `-`, and it is an executable regular file. When two
directories hold the same name, the first one wins.

The core never searches `PATH`: a planted `systemlint-apt` there would run as
root. Like sudo, it refuses a plugin, or any directory above it, symlinks
resolved, that is not owned by root or the user running systemlint, or that
group or others can write. A refusal names the directory and the fix:

```text
refused /opt/systemlint/plugins: group or others can write /opt/systemlint/plugins (mode 0775); run chmod go-w /opt/systemlint/plugins
```

`systemlint plugin list` prints every trusted plugin and its ops, and exits 4
when any plugin was refused or failed to describe itself.

## Running a plugin

The core starts a plugin with an empty environment except `LC_ALL=C`, no
shell, and stdin closed for `--describe`. It reads at most 16 MiB from stdout
and from stderr and kills a plugin that has not answered `--describe` within
30 seconds.

## `--describe`

```console
$ systemlint-formats --describe
{"name":"formats","version":"0.1.0","protocol":1,"ops":[{"op":"ini"},{"op":"kv"},{"op":"lines"},{"op":"regex"},{"op":"toml"}]}
```

| Field | Meaning |
| --- | --- |
| `name` | the plugin name, which must equal the filename after `systemlint-` |
| `version` | the plugin’s own version |
| `protocol` | the protocol version, `1`; the core refuses one it does not speak |
| `ops[].op` | an operation a collector can name in `parse: {plugin, op}` |
| `ops[].needs` | fact paths that must be collected first and are passed in `facts`; omitted when empty |

## Request

```json
{
  "protocol": 1,
  "op": "sources",
  "root": "/",
  "now": "2026-11-11T12:00:00Z",
  "inputs": [
    {"path": "/etc/apt/sources.list.d/docker.sources", "content": "Types: deb\n…", "stat": {"kind": "file", "mode": "0644", "uid": 0, "gid": 0, "size": 112, "world-writable": false, "group-writable": false, "setuid": false, "setgid": false}},
    {"argv": ["dpkg", "--print-architecture"], "stdout": "amd64\n", "stderr": "", "exit": 0}
  ],
  "facts": {"os.release": {"VERSION_CODENAME": "resolute"}}
}
```

| Field | Meaning |
| --- | --- |
| `protocol` | `1` |
| `op` | one of the ops `--describe` lists |
| `root` | `/` on a live host, else the root filesystem being read; paths in `inputs` stay absolute inside it |
| `now` | the collection time, RFC 3339; a plugin computes every age against it, never its own clock |
| `inputs[]` | a file `{path, content \| content-base64, stat}` or a command `{argv, stdout, stderr, exit}` |
| `facts` | the facts the op `needs`, by path |

A file carries `content` when it is valid UTF-8 and `content-base64`
otherwise; `stat` is present when the collector asked for it. `stat.mode` is
the octal permission string, and the four booleans spell out the bits a JSON
Schema cannot test.

## Reply

```json
{
  "facts": {"/etc/apt/sources.list.d/docker.sources": {"suites": ["questing"]}},
  "diagnostics": [{"path": "/etc/apt/sources.list.d/docker.sources", "line": 3, "message": "unknown field Signed-by"}],
  "redact": []
}
```

| Field | Meaning |
| --- | --- |
| `facts` | an object the core places at the collector’s `into`, so the reply above under `into: apt.sources` lands at `apt.sources` |
| `diagnostics[]` | problems in one input: `path`, optional `line`, `message` |
| `redact[]` | JSON Pointers into `facts` of values holding secrets, such as `/netrc/password`; the core replaces each with `[redacted]` |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success: a reply, a `--describe`, `--help` or `--version` on stdout |
| 1 | the op failed; stderr says why |
| 2 | wrong command line |
| 3 | a request the plugin cannot accept: invalid JSON, another protocol, an op it does not list |

The core records a non-zero exit or a reply that is not valid JSON as
`collectors.<id>.status: error` with the reason, so a failed probe never looks
like a missing fact. A request reaches the plugin on stdin under the same
empty environment, 16 MiB cap and a 30-second timeout.
