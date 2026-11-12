// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol v1 between the systemlint core and its plugins: one JSON request on stdin, one JSON reply on stdout.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol version this crate speaks.
pub const PROTOCOL: u32 = 1;

/// The release version, stamped by the build script as `SYSTEMLINT_VERSION`, else the Cargo.toml one.
pub const VERSION: &str = match option_env!("SYSTEMLINT_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

/// Where the protocol is documented, printed in every plugin’s `--help`.
pub const DOCS: &str = "https://kiota.ch/damian-buho/systemlint/src/branch/main/docs/how-to/protocol.md";

/// Exit code for a request the plugin cannot accept: bad JSON, another protocol, an op it does not list.
pub const EXIT_BAD_REQUEST: u8 = 3;

/// A plugin error, as text the core records under `collectors.<id>.error`.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// The result every op returns.
pub type Result<T> = std::result::Result<T, Error>;

/// The answer to `--describe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Describe {
    pub name: String,
    pub version: String,
    pub protocol: u32,
    pub ops: Vec<OpSpec>,
}

/// One op a plugin offers and the facts it needs collected first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpSpec {
    pub op: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
}

impl Describe {
    /// Describes plugin `name` at this build’s version, with `(op, needs)` pairs.
    pub fn new(name: &str, ops: &[(&str, &[&str])]) -> Self {
        Self {
            name: name.to_owned(),
            version: VERSION.to_owned(),
            protocol: PROTOCOL,
            ops: ops
                .iter()
                .map(|(op, needs)| OpSpec { op: (*op).to_owned(), needs: needs.iter().map(|n| (*n).to_owned()).collect() })
                .collect(),
        }
    }

    /// Whether this plugin lists `op`.
    pub fn offers(&self, op: &str) -> bool {
        self.ops.iter().any(|spec| spec.op == op)
    }
}

/// One call of one op.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub op: String,
    #[serde(default = "live_root")]
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    #[serde(default)]
    pub inputs: Vec<Input>,
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
}

fn live_root() -> String {
    "/".to_owned()
}

/// What the core read for the op: a file or a command’s output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Input {
    File(FileInput),
    Exec(ExecInput),
}

/// A file read by the core, as text or base64, with its stat when collected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInput {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, rename = "content-base64", skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stat: Option<Stat>,
}

/// A command run by the core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecInput {
    pub argv: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit: i32,
}

/// File metadata, with the mode bits a schema cannot test spelled out as booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Stat {
    pub kind: FileKind,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub world_writable: bool,
    pub group_writable: bool,
    pub setuid: bool,
    pub setgid: bool,
}

/// The file type in a [`Stat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// What an op found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    #[serde(default)]
    pub redact: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash: Vec<String>,
}

/// A problem found in one input, by path and line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    pub message: String,
}

/// The whole `main` of a plugin: `--describe`, `--help`, `--version`, or one request on stdin.
pub fn run(describe: &Describe, handler: impl FnOnce(Request) -> Result<Reply>) -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let code = execute(describe, handler, &args, &mut std::io::stdin().lock(), &mut std::io::stdout().lock(), &mut std::io::stderr().lock());
    ExitCode::from(code)
}

/// [`run`] over explicit arguments and streams, returning the exit code.
pub fn execute(
    describe: &Describe,
    handler: impl FnOnce(Request) -> Result<Reply>,
    args: &[String],
    stdin: &mut impl Read,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let bin = format!("systemlint-{}", describe.name);
    let command = clap::Command::new(bin.clone())
        .version(VERSION)
        .about(format!("systemlint plugin {}: reads one JSON request on stdin, writes one JSON reply on stdout", describe.name))
        .after_help(format!("The systemlint core runs this program; run it by hand only to debug.\nProtocol: {DOCS}"))
        .arg(clap::Arg::new("describe").long("describe").action(clap::ArgAction::SetTrue).help("Print name, version, protocol and ops as JSON"));
    let matches = match command.try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) if error.use_stderr() => {
            let _ = write!(stderr, "{}", error.render());
            return 2;
        }
        Err(error) => {
            let _ = write!(stdout, "{}", error.render());
            return 0;
        }
    };
    if matches.get_flag("describe") {
        return emit(&bin, describe, stdout, stderr);
    }
    let mut body = String::new();
    if let Err(error) = stdin.read_to_string(&mut body) {
        let _ = writeln!(stderr, "{bin}: can’t read the request on stdin: {error}");
        return EXIT_BAD_REQUEST;
    }
    let request: Request = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error) => {
            let _ = writeln!(stderr, "{bin}: the request is not valid protocol JSON: {error}");
            return EXIT_BAD_REQUEST;
        }
    };
    if request.protocol != PROTOCOL {
        let _ = writeln!(stderr, "{bin}: speaks protocol {PROTOCOL}, the request asks for {}", request.protocol);
        return EXIT_BAD_REQUEST;
    }
    if !describe.offers(&request.op) {
        let _ = writeln!(stderr, "{bin}: no op {}; --describe lists the ops", request.op);
        return EXIT_BAD_REQUEST;
    }
    let op = request.op.clone();
    match handler(request) {
        Ok(reply) => emit(&bin, &reply, stdout, stderr),
        Err(error) => {
            let _ = writeln!(stderr, "{bin}: op {op}: {error}");
            1
        }
    }
}

fn emit(bin: &str, value: &impl Serialize, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match serde_json::to_writer(&mut *stdout, value).map_err(std::io::Error::from).and_then(|()| writeln!(stdout)) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "{bin}: can’t write the reply: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Describe {
        Describe::new("sample", &[("echo", &[]), ("derive", &["os.release"])])
    }

    fn call(args: &[&str], stdin: &str, handler: impl FnOnce(Request) -> Result<Reply>) -> (u8, String, String) {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = execute(&sample(), handler, &args, &mut stdin.as_bytes(), &mut out, &mut err);
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    fn unused(_: Request) -> Result<Reply> {
        panic!("the handler must not run")
    }

    #[test]
    fn describe_prints_protocol_and_ops() {
        let (code, out, _) = call(&["systemlint-sample", "--describe"], "", unused);
        assert_eq!(code, 0);
        let parsed: Describe = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed, sample());
        assert_eq!(parsed.protocol, 1);
        assert!(out.contains(r#""needs":["os.release"]"#));
        assert!(!out.contains(r#""op":"echo","needs""#));
    }

    #[test]
    fn version_and_help_exit_zero() {
        let (code, out, err) = call(&["systemlint-sample", "--version"], "", unused);
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(out, format!("systemlint-sample {VERSION}\n"));
        let (code, _, _) = call(&["systemlint-sample", "--help"], "", unused);
        assert_eq!(code, 0);
    }

    #[test]
    fn unknown_flag_is_usage_error() {
        let (code, _, err) = call(&["systemlint-sample", "--nope"], "", unused);
        assert_eq!(code, 2);
        assert!(err.contains("--nope"), "{err}");
    }

    #[test]
    fn request_reaches_handler_and_reply_is_json() {
        let request = r#"{"protocol":1,"op":"echo","inputs":[{"path":"/etc/hostname","content":"kiota\n"},{"argv":["uname"],"stdout":"Linux\n","stderr":"","exit":0}]}"#;
        let (code, out, err) = call(&["systemlint-sample"], request, |req| {
            assert_eq!(req.root, "/");
            assert!(matches!(&req.inputs[0], Input::File(f) if f.content.as_deref() == Some("kiota\n")));
            assert!(matches!(&req.inputs[1], Input::Exec(e) if e.argv == ["uname"] && e.exit == 0));
            let mut reply = Reply::default();
            reply.facts.insert("host.name".to_owned(), Value::from("kiota"));
            Ok(reply)
        });
        assert_eq!((code, err.as_str()), (0, ""));
        let reply: Reply = serde_json::from_str(&out).unwrap();
        assert_eq!(reply.facts["host.name"], "kiota");
    }

    #[test]
    fn bad_requests_exit_three_without_calling_handler() {
        for (request, expected) in [
            ("not json", "not valid protocol JSON"),
            (r#"{"protocol":2,"op":"echo"}"#, "speaks protocol 1"),
            (r#"{"protocol":0,"op":"echo"}"#, "speaks protocol 1"),
            (r#"{"protocol":1,"op":"missing"}"#, "no op missing"),
            (r#"{"protocol":1,"op":"echo","extra":true}"#, "unknown field"),
        ] {
            let (code, out, err) = call(&["systemlint-sample"], request, unused);
            assert_eq!(code, EXIT_BAD_REQUEST, "{request}");
            assert!(out.is_empty(), "{request}");
            assert!(err.contains(expected), "{request}: {err}");
        }
    }

    #[test]
    fn handler_error_exits_one_naming_the_op() {
        let (code, out, err) = call(&["systemlint-sample"], r#"{"protocol":1,"op":"derive"}"#, |_| Err("boom".into()));
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert_eq!(err, "systemlint-sample: op derive: boom\n");
    }

    #[test]
    fn stat_uses_kebab_case() {
        let stat = Stat { kind: FileKind::File, mode: "0644".into(), uid: 0, gid: 0, size: 3, world_writable: false, group_writable: false, setuid: false, setgid: false };
        let json = serde_json::to_string(&stat).unwrap();
        assert!(json.contains(r#""world-writable":false"#) && json.contains(r#""kind":"file""#), "{json}");
    }
}
