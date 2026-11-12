// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! env: environment variables, one environment per system file, systemd unit, running service or image config.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use systemlint_formats::{Sections, mask, parse_ini, text, unquote};
use systemlint_protocol::{Describe, Diagnostic, Input, Reply, Request, Result};

/// Names whose values stay in clear: the rules read them, and they hold no secret.
pub const CLEAR: [&str; 11] = ["PATH", "LANG", "LANGUAGE", "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY", "PYTHONHTTPSVERIFY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"];

/// The systemd system unit directories, highest precedence first.
pub const UNIT_DIRS: [&str; 5] = ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"];

/// The ld.so preload list, read as a system-wide `LD_PRELOAD`.
pub const PRELOAD: &str = "/etc/ld.so.preload";

/// Leaf prefixes of the cgroup scopes container engines create, before the container ID.
pub const CONTAINER_SCOPES: [&str; 4] = ["docker-", "libpod-", "cri-containerd-", "crio-"];

/// The ops this plugin offers.
pub fn describe() -> Describe {
    Describe::new("env", &[("files", &[]), ("image", &[]), ("processes", &[]), ("units", &[])])
}

/// Runs one op.
pub fn op(request: Request) -> Result<Reply> {
    match request.op.as_str() {
        "files" => Ok(files(&request.inputs)),
        "units" => Ok(units(&request.inputs)),
        "processes" => Ok(processes(&request.inputs)),
        "image" => image(&request.inputs).map_err(Into::into),
        other => Err(format!("op {other} is not implemented").into()),
    }
}

/// Whether the value of `name` stays in clear rather than hashed.
pub fn clear(name: &str) -> bool {
    CLEAR.contains(&name) || name.starts_with("LD_") || name.starts_with("LC_") || proxy(name)
}

fn proxy(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("_proxy")
}

fn pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// Adds one environment at `key`: `kind`, `vars`, the `path` entries when `PATH` is set, and `extra`; every other value is marked for hashing.
pub fn place(reply: &mut Reply, key: &str, kind: &str, vars: BTreeMap<String, String>, extra: Map<String, Value>) {
    let mut env = json!({"kind": kind});
    if let Some(path) = vars.get("PATH") {
        env["path"] = json!(path.split(':').filter(|e| !e.starts_with('$')).collect::<Vec<_>>());
    }
    let mut shown = Map::new();
    for (name, value) in vars {
        if !value.is_empty() && !clear(&name) {
            reply.hash.push(format!("/{}/vars/{}", pointer(key), pointer(&name)));
        }
        let value = if proxy(&name) { mask(&value) } else { value };
        shown.insert(name, Value::from(value));
    }
    env["vars"] = Value::Object(shown);
    env.as_object_mut().into_iter().for_each(|o| o.extend(extra.clone()));
    reply.facts.insert(key.to_owned(), env);
}

/// Whether `name` is a variable name a shell accepts.
pub fn name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c == '_' || c.is_ascii_alphabetic()) && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The plain assignments of a shell or pam_env file: unindented `NAME=value` or `export NAME=value`, later ones winning; other lines are code and skipped.
pub fn assignments(text: &str, mut diagnose: impl FnMut(u64, String)) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let line = line.trim_end();
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=').filter(|(k, _)| name(k)) else { continue };
        match unquote(value) {
            Ok(value) => drop(vars.insert(key.to_owned(), value)),
            Err(message) => diagnose(index as u64 + 1, format!("{key}: {message}")),
        }
    }
    vars
}

/// One environment per system file with any assignment, `/etc/ld.so.preload` as its `LD_PRELOAD`.
pub fn files(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else { continue };
        let vars = if path == PRELOAD {
            let libraries: Vec<&str> = text.lines().filter(|l| !l.trim_start().starts_with('#')).flat_map(|l| l.split([' ', '\t', ':'])).filter(|w| !w.is_empty()).collect();
            if libraries.is_empty() { BTreeMap::new() } else { BTreeMap::from([("LD_PRELOAD".to_owned(), libraries.join(":"))]) }
        } else {
            let mut problems = Vec::new();
            let vars = assignments(text, |line, message| problems.push(Diagnostic { path: path.to_owned(), line: Some(line), message }));
            reply.diagnostics.extend(problems);
            vars
        };
        if !vars.is_empty() {
            place(&mut reply, path, "file", vars, Map::new());
        }
    }
    reply
}

/// The words of a systemd value: whitespace splits, `"…"` and `'…'` group, `\` escapes the next character.
pub fn words(text: &str) -> std::result::Result<Vec<String>, String> {
    let (mut words, mut word, mut quote, mut started) = (Vec::new(), String::new(), None, false);
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (_, '\\') => {
                word.push(chars.next().ok_or("a trailing \\ escapes nothing")?);
                started = true;
            }
            (None, '"' | '\'') => (quote, started) = (Some(c), true),
            (Some(q), c) if c == q => quote = None,
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                }
                started = false;
            }
            (_, c) => {
                word.push(c);
                started = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!("unterminated {q} quote"));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

/// One unit’s environment as it builds up: `Environment=` assignments and `EnvironmentFile=` paths, an empty value resetting each.
#[derive(Default)]
struct Unit {
    vars: BTreeMap<String, String>,
    files: Vec<String>,
}

impl Unit {
    fn environment(&mut self, value: &str, mut diagnose: impl FnMut(String)) {
        if value.is_empty() {
            self.vars.clear();
            return;
        }
        match words(value) {
            Ok(words) => {
                for word in words {
                    match word.split_once('=').filter(|(k, _)| name(k)) {
                        Some((key, value)) => drop(self.vars.insert(key.to_owned(), value.to_owned())),
                        None => diagnose(format!("Environment {word:?} is no NAME=value")),
                    }
                }
            }
            Err(message) => diagnose(format!("Environment: {message}")),
        }
    }

    fn file(&mut self, value: &str) {
        match value.trim() {
            "" => self.files.clear(),
            path => self.files.push(path.trim_start_matches('-').to_owned()),
        }
    }

    fn place(self, reply: &mut Reply, unit: &str) {
        if !self.vars.is_empty() || !self.files.is_empty() {
            let extra = Map::from_iter([("environment-files".to_owned(), json!(self.files))]);
            place(reply, unit, "unit", self.vars, extra);
        }
    }
}

/// One environment per service with `Environment=` or `EnvironmentFile=`: from `systemctl show` when it exited 0, else from the unit files and drop-ins.
pub fn units(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let shown = inputs.iter().find_map(|i| match i {
        Input::Exec(e) if e.exit == 0 => Some(e),
        Input::Exec(e) if e.exit != 127 => {
            reply.diagnostics.push(Diagnostic { path: e.argv.join(" "), line: None, message: format!("exited {}, read from the files: {}", e.exit, e.stderr.trim()) });
            None
        }
        _ => None,
    });
    if let Some(exec) = shown {
        let command = exec.argv.join(" ");
        for block in exec.stdout.split("\n\n") {
            let (mut id, mut unit) = (None, Unit::default());
            for line in block.lines() {
                match line.split_once('=') {
                    Some(("Id", value)) => id = Some(value.to_owned()),
                    Some(("Environment", value)) => unit.environment(value, |message| reply.diagnostics.push(Diagnostic { path: command.clone(), line: None, message })),
                    Some(("EnvironmentFiles", value)) => unit.file(value.split(" (").next().unwrap_or_default()),
                    _ => {}
                }
            }
            if let Some(id) = id {
                unit.place(&mut reply, &id);
            }
        }
        return reply;
    }
    let files: Vec<(&str, &str)> = inputs.iter().filter(|i| matches!(i, Input::File(_))).filter_map(|i| text(i, &mut reply.diagnostics)).collect();
    for (unit, parts) in unit_files(&files) {
        let mut built = Unit::default();
        for (path, text) in parts {
            let sections: Sections = parse_ini(text, |line, message| reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: Some(line), message }));
            let Some(service) = sections.get("Service") else { continue };
            for value in service.get("Environment").into_iter().flatten() {
                built.environment(value, |message| reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: None, message }));
            }
            for value in service.get("EnvironmentFile").into_iter().flatten() {
                built.file(value);
            }
        }
        built.place(&mut reply, &unit);
    }
    reply
}

/// Each unit’s files in the order systemd reads them: the unit file from the highest directory, then its drop-ins by name, one per name.
pub fn unit_files<'a>(files: &[(&'a str, &'a str)]) -> BTreeMap<String, Vec<(&'a str, &'a str)>> {
    let mut mains: BTreeMap<String, (usize, &str, &str)> = BTreeMap::new();
    let mut drops: BTreeMap<String, BTreeMap<&str, (usize, &str, &str)>> = BTreeMap::new();
    for (path, text) in files {
        let Some((dir, file)) = path.rsplit_once('/') else { continue };
        let (base, unit, dropin) = match dir.rsplit_once('/') {
            Some((base, d)) if d.ends_with(".d") && file.ends_with(".conf") => (base, d.trim_end_matches(".d"), true),
            _ => (dir, file, false),
        };
        let Some(rank) = UNIT_DIRS.iter().position(|d| *d == base) else { continue };
        if !unit.contains('.') {
            continue;
        }
        let slot = if dropin { drops.entry(unit.to_owned()).or_default().entry(file).or_insert((usize::MAX, "", "")) } else { mains.entry(unit.to_owned()).or_insert((usize::MAX, "", "")) };
        if rank < slot.0 {
            *slot = (rank, path, text);
        }
    }
    let mut units: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
    for (unit, (_, path, text)) in mains {
        units.entry(unit).or_default().push((path, text));
    }
    for (unit, confs) in drops {
        units.entry(unit).or_default().extend(confs.into_values().map(|(_, p, t)| (p, t)));
    }
    units
}

/// What owns a cgroup: a system service by its unit name, or a container by `container:` and the first 12 characters of its ID.
pub fn owner(cgroup: &str) -> Option<String> {
    let leaf = cgroup.rsplit('/').next()?;
    if let Some(id) = CONTAINER_SCOPES.iter().find_map(|p| leaf.strip_prefix(p)).and_then(|rest| rest.strip_suffix(".scope")) {
        return Some(format!("container:{}", &id[..id.len().min(12)]));
    }
    (cgroup.starts_with("/system.slice/") && leaf.ends_with(".service")).then(|| leaf.to_owned())
}

/// The unified (or systemd v1) cgroup path in a `/proc/<pid>/cgroup` text.
pub fn cgroup(text: &str) -> Option<&str> {
    let lines: Vec<(&str, &str)> = text.lines().filter_map(|l| l.split_once(':').and_then(|(_, rest)| rest.split_once(':'))).collect();
    lines.iter().find(|(c, _)| c.is_empty()).or_else(|| lines.iter().find(|(c, _)| *c == "name=systemd")).map(|(_, path)| *path)
}

/// The parent PID in a `/proc/<pid>/stat` text, read after the command name’s closing parenthesis.
pub fn parent(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

/// The environment of each service’s and container’s top process, the lowest PID whose parent sits outside its cgroup, from `/proc/<pid>/{environ,cgroup,stat}`.
pub fn processes(inputs: &[Input]) -> Reply {
    let mut reply = Reply::default();
    let mut procs: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else { continue };
        let mut parts = path.trim_start_matches('/').split('/');
        if let (Some("proc"), Some(Ok(pid)), Some(file), None) = (parts.next(), parts.next().map(str::parse::<u32>), parts.next(), parts.next()) {
            procs.entry(pid).or_default().insert(file, text);
        }
    }
    let group = |pid: u32| procs.get(&pid).and_then(|p| p.get("cgroup")).and_then(|t| cgroup(t));
    let mut tops: BTreeMap<String, u32> = BTreeMap::new();
    for (pid, files) in &procs {
        let (Some(own), Some(ppid)) = (group(*pid), files.get("stat").and_then(|s| parent(s))) else { continue };
        let Some(key) = owner(own) else { continue };
        if group(ppid) != Some(own) && !files.get("environ").is_none_or(|e| e.is_empty()) {
            tops.entry(key).or_insert(*pid);
        }
    }
    for (key, pid) in tops {
        let environ = procs[&pid]["environ"];
        let vars = environ.split('\0').filter_map(|e| e.split_once('=')).map(|(k, v)| (k.to_owned(), v.to_owned())).collect();
        place(&mut reply, &key, "process", vars, Map::from_iter([("pid".to_owned(), json!(pid))]));
    }
    reply
}

/// The `Env` of an OCI image config, a Docker image JSON or `docker inspect` output, as one environment keyed by its path.
pub fn image(inputs: &[Input]) -> std::result::Result<Reply, String> {
    let mut reply = Reply::default();
    for input in inputs {
        let Some((path, text)) = text(input, &mut reply.diagnostics) else { continue };
        let document: Value = serde_json::from_str(text).map_err(|e| format!("{path} is not valid JSON: {e}"))?;
        let config = match &document {
            Value::Array(items) if items.len() == 1 => &items[0],
            other => other,
        };
        let section = config.get("config").or_else(|| config.get("Config")).ok_or_else(|| format!("{path} has no config or Config object; give an OCI image config or docker inspect output"))?;
        let mut vars = BTreeMap::new();
        for entry in section.get("Env").and_then(Value::as_array).into_iter().flatten() {
            match entry.as_str().and_then(|e| e.split_once('=')) {
                Some((key, value)) => drop(vars.insert(key.to_owned(), value.to_owned())),
                None => reply.diagnostics.push(Diagnostic { path: path.to_owned(), line: None, message: format!("Env entry {entry} is no NAME=value") }),
            }
        }
        place(&mut reply, path, "image", vars, Map::new());
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemlint_protocol::{ExecInput, FileInput};

    fn file(path: &str, content: &str) -> Input {
        Input::File(FileInput { path: path.to_owned(), content: Some(content.to_owned()), content_base64: None, stat: None })
    }

    fn exec(stdout: &str, exit: i32) -> Input {
        Input::Exec(ExecInput { argv: vec!["/usr/bin/systemctl".into(), "show".into()], stdout: stdout.to_owned(), stderr: "no bus\n".to_owned(), exit })
    }

    #[test]
    fn clear_keeps_the_names_rules_read() {
        for name in ["PATH", "LD_PRELOAD", "LC_ALL", "https_proxy", "ALL_PROXY", "NO_PROXY", "NODE_OPTIONS", "GIT_SSL_NO_VERIFY"] {
            assert!(clear(name), "{name}");
        }
        for name in ["AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "HOME", "proxy", "PATHS"] {
            assert!(!clear(name), "{name}");
        }
    }

    #[test]
    fn place_hashes_all_but_clear_and_empty_values_and_splits_path() {
        let mut reply = Reply::default();
        let vars = BTreeMap::from([("PATH".into(), "/usr/bin::bin:$PATH".into()), ("TOKEN".into(), "s3cret".into()), ("EMPTY".into(), String::new()), ("http_proxy".into(), "http://u:p@proxy:3128".into())]);
        place(&mut reply, "/etc/a~b", "file", vars, Map::new());
        let env = &reply.facts["/etc/a~b"];
        assert_eq!(env["path"], json!(["/usr/bin", "", "bin"]));
        assert_eq!(env["vars"]["http_proxy"], "http://u:[redacted]@proxy:3128");
        assert_eq!(reply.hash, ["/~1etc~1a~0b/vars/TOKEN"]);
        assert!(place_without_path());
    }

    fn place_without_path() -> bool {
        let mut reply = Reply::default();
        place(&mut reply, "k", "file", BTreeMap::from([("A".into(), "1".into())]), Map::new());
        reply.facts["k"].get("path").is_none()
    }

    #[test]
    fn assignments_take_plain_lines_only() {
        let text = "# c\nA=1\nexport B=\"two words\"\n  C=indented\nif [ x ]; then\nD='q'\nPATH=\"$PATH:/snap/bin\"\nA=again\n1X=bad\nE=\"open\n";
        let mut lines = Vec::new();
        let vars = assignments(text, |line, _| lines.push(line));
        assert_eq!(vars, BTreeMap::from([("A".into(), "again".into()), ("B".into(), "two words".into()), ("D".into(), "q".into()), ("PATH".into(), "$PATH:/snap/bin".into())]));
        assert_eq!(lines, [10]);
    }

    #[test]
    fn files_read_ld_so_preload_as_ld_preload_and_skip_empty_files() {
        let reply = files(&[file(PRELOAD, "# lib\n/lib/a.so /lib/b.so:/lib/c.so\n"), file("/etc/profile.d/x.sh", "if true; then\n  X=1\nfi\n"), file("/etc/environment", "LANG=C.UTF-8\n")]);
        assert_eq!(reply.facts[PRELOAD]["vars"]["LD_PRELOAD"], "/lib/a.so:/lib/b.so:/lib/c.so");
        assert_eq!(reply.facts.keys().map(String::as_str).collect::<Vec<_>>(), ["/etc/environment", PRELOAD]);
        assert!(files(&[file(PRELOAD, "\n# none\n")]).facts.is_empty());
    }

    #[test]
    fn words_follow_systemd_quoting() {
        assert_eq!(words(r#"A=1 "B=two words" 'C=x y'  D=a\ b E="q"x"#).unwrap(), ["A=1", "B=two words", "C=x y", "D=a b", "E=qx"]);
        assert!(words("\"open").is_err());
        assert!(words("x\\").is_err());
        assert_eq!(words("  ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn units_read_systemctl_show_when_it_ran() {
        let show = "Id=a.service\nMainPID=10\nEnvironment=A=1 \"B=x y\"\nEnvironmentFiles=/etc/default/a (ignore_errors=yes)\n\nId=b.service\nMainPID=0\nEnvironment=\n\nId=c.service\nEnvironment=bad\n";
        let reply = units(&[file("/etc/systemd/system/z.service", "[Service]\nEnvironment=Z=1\n"), exec(show, 0)]);
        assert_eq!(reply.facts.keys().collect::<Vec<_>>(), ["a.service"]);
        assert_eq!(reply.facts["a.service"]["vars"], json!({"A": "1", "B": "x y"}));
        assert_eq!(reply.facts["a.service"]["environment-files"], json!(["/etc/default/a"]));
        assert_eq!(reply.facts["a.service"]["kind"], "unit");
        assert!(reply.diagnostics[0].message.contains("\"bad\""), "{:?}", reply.diagnostics);
    }

    #[test]
    fn units_merge_files_and_drop_ins_by_precedence() {
        let reply = units(&[
            file("/usr/lib/systemd/system/app.service", "[Service]\nEnvironment=A=usr B=usr\nEnvironmentFile=-/etc/default/app\n"),
            file("/etc/systemd/system/app.service", "[Service]\nEnvironment=A=etc\n"),
            file("/usr/lib/systemd/system/app.service.d/10-x.conf", "[Service]\nEnvironment=C=usr\n"),
            file("/etc/systemd/system/app.service.d/10-x.conf", "[Service]\nEnvironment=C=etc\n"),
            file("/usr/lib/systemd/system/app.service.d/20-reset.conf", "[Service]\nEnvironment=\nEnvironment=D=1\nEnvironmentFile=\n"),
            file("/usr/lib/systemd/system/plain.service", "[Service]\nExecStart=/bin/true\n"),
            file("/etc/systemd/system/service.d/top.conf", "[Service]\nEnvironment=T=1\n"),
            file("/opt/units/other.service", "[Service]\nEnvironment=O=1\n"),
            exec("", 1),
        ]);
        assert_eq!(reply.facts.keys().collect::<Vec<_>>(), ["app.service"]);
        assert_eq!(reply.facts["app.service"]["vars"], json!({"D": "1"}));
        assert_eq!(reply.facts["app.service"]["environment-files"], json!([]));
        assert!(reply.diagnostics[0].message.contains("exited 1, read from the files: no bus"), "{:?}", reply.diagnostics);
        let kept = units(&[file("/usr/lib/systemd/system/app.service", "[Service]\nEnvironment=A=usr B=usr\nEnvironmentFile=-/etc/default/app\n"), file("/etc/systemd/system/app.service.d/10-x.conf", "[Service]\nEnvironment=A=drop\n")]);
        assert_eq!(kept.facts["app.service"]["vars"], json!({"A": "drop", "B": "usr"}));
        assert_eq!(kept.facts["app.service"]["environment-files"], json!(["/etc/default/app"]));
    }

    #[test]
    fn owner_names_system_services_and_containers_only() {
        assert_eq!(owner("/system.slice/nginx.service").as_deref(), Some("nginx.service"));
        assert_eq!(owner("/system.slice/docker-0123456789abcdef0123.scope").as_deref(), Some("container:0123456789ab"));
        assert_eq!(owner("/kubepods.slice/kubepods-pod1.slice/cri-containerd-abc.scope").as_deref(), Some("container:abc"));
        assert_eq!(owner("/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service"), None);
        assert_eq!(owner("/init.scope"), None);
        assert_eq!(cgroup("0::/system.slice/a.service\n"), Some("/system.slice/a.service"));
        assert_eq!(cgroup("12:cpu:/x\n1:name=systemd:/system.slice/b.service\n"), Some("/system.slice/b.service"));
        assert_eq!(parent("42 (a b) c) S 7 42 42"), Some(7));
    }

    #[test]
    fn processes_take_the_top_process_of_each_cgroup() {
        let proc_ = |pid: u32, cg: &str, ppid: u32, env: &str| [file(&format!("/proc/{pid}/cgroup"), &format!("0::{cg}\n")), file(&format!("/proc/{pid}/stat"), &format!("{pid} (x) S {ppid} 1")), file(&format!("/proc/{pid}/environ"), env)];
        let inputs: Vec<Input> = [
            proc_(1, "/init.scope", 0, "TERM=linux\0"),
            proc_(100, "/system.slice/app.service", 1, "PATH=/usr/bin\0SECRET=x\0"),
            proc_(101, "/system.slice/app.service", 100, "CHILD=1\0"),
            proc_(200, "/system.slice/docker-feedfacecafe0000.scope", 150, "NODE_TLS_REJECT_UNAUTHORIZED=0\0"),
            proc_(150, "/system.slice/containerd.service", 1, ""),
        ]
        .into_iter()
        .flatten()
        .chain([file("/proc/self/environ", "ME=1\0"), file("/proc/300/environ", "ORPHAN=1\0")])
        .collect();
        let reply = processes(&inputs);
        assert_eq!(reply.facts.keys().collect::<Vec<_>>(), ["app.service", "container:feedfacecafe"]);
        assert_eq!(reply.facts["app.service"]["pid"], 100);
        assert_eq!(reply.facts["app.service"]["path"], json!(["/usr/bin"]));
        assert_eq!(reply.facts["container:feedfacecafe"]["vars"]["NODE_TLS_REJECT_UNAUTHORIZED"], "0");
        assert_eq!(reply.hash, ["/app.service/vars/SECRET"]);
    }

    #[test]
    fn image_reads_oci_docker_and_inspect_shapes() {
        let oci = image(&[file("/img/config.json", r#"{"config": {"Env": ["PATH=/usr/bin", "NODE_TLS_REJECT_UNAUTHORIZED=0", 3]}}"#)]).unwrap();
        assert_eq!(oci.facts["/img/config.json"]["vars"]["NODE_TLS_REJECT_UNAUTHORIZED"], "0");
        assert_eq!(oci.facts["/img/config.json"]["kind"], "image");
        assert_eq!(oci.diagnostics.len(), 1);
        let inspect = image(&[file("/i.json", r#"[{"Config": {"Env": ["A=1"]}}]"#)]).unwrap();
        assert_eq!(inspect.facts["/i.json"]["vars"], json!({"A": "1"}));
        let bare = image(&[file("/b.json", r#"{"config": {}}"#)]).unwrap();
        assert_eq!(bare.facts["/b.json"]["vars"], json!({}));
        assert!(image(&[file("/x.json", "{}")]).unwrap_err().contains("no config"));
        assert!(image(&[file("/y.json", "nope")]).unwrap_err().contains("not valid JSON"));
    }
}
