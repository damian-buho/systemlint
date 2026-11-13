// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Saves a crash report when systemlint panics, and points to it and to a pre-filled issue.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use systemlint_protocol::VERSION;

/// The page a new issue is filed on.
pub const ISSUES: &str = "https://kiota.ch/damian-buho/systemlint/issues/new";

/// Replaces the default panic message with one line naming the saved report, or the whole report when it can’t be saved.
pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_owned());
        let location = info
            .location()
            .map_or_else(String::new, ToString::to_string);
        let args: Vec<String> = std::env::args().collect();
        let text = report(
            &message,
            &location,
            &args,
            &std::backtrace::Backtrace::force_capture().to_string(),
        ) + &crate::trail::dump();
        let saved = directory(|name| std::env::var(name).ok())
            .ok_or_else(|| io::Error::other("neither XDG_STATE_HOME nor HOME is set"))
            .and_then(|dir| save(&dir, &text));
        match saved {
            Ok(path) => eprintln!(
                "systemlint crashed: {message}. The report is in {}; please file it at {}",
                path.display(),
                issue_url(&message, &location)
            ),
            Err(error) => eprintln!(
                "systemlint crashed and can’t save a report ({error}); please file this at {ISSUES}:\n{text}"
            ),
        }
    }));
}

/// `$XDG_STATE_HOME/systemlint` when that is absolute, else `$HOME/.local/state/systemlint`.
pub fn directory(var: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let state = var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    state
        .or_else(|| var("HOME").map(|home| Path::new(&home).join(".local/state")))
        .map(|dir| dir.join("systemlint"))
}

/// The report: version, platform, arguments, the panic and its backtrace.
pub fn report(message: &str, location: &str, args: &[String], backtrace: &str) -> String {
    let kernel = rustix::system::uname();
    let mut text = format!("systemlint {VERSION} crashed\n");
    let _ = writeln!(
        text,
        "platform: {} {}, kernel {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        kernel.release().to_string_lossy()
    );
    let _ = writeln!(
        text,
        "args: {args:?}\npanic: {message}\nat: {location}\n\n{backtrace}"
    );
    text
}

/// Writes `text` to a new `crash-<seconds>-<pid>.txt` in `dir`, mode 0600, the directory made 0700 when missing.
pub fn save(dir: &Path, text: &str) -> io::Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let path = dir.join(format!("crash-{seconds}-{}.txt", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(text.as_bytes())?;
    log::debug!(
        "crash report of {} bytes saved to {}",
        text.len(),
        path.display()
    );
    Ok(path)
}

/// A new-issue link with the title and body filled in, the arguments left out since they may name private paths.
pub fn issue_url(message: &str, location: &str) -> String {
    let title = format!("crash: {message}");
    let body = format!(
        "systemlint {VERSION} on {} {} crashed at {location}.\n\nAttach the crash report it printed the path of.",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    format!("{ISSUES}?title={}&body={}", encode(&title), encode(&body))
}

/// Percent-encodes every byte but the URL’s unreserved characters.
fn encode(text: &str) -> String {
    text.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
        out
    })
}
