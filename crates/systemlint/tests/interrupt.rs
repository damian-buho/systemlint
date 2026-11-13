// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use systemlint::runner::{OUTPUT_CAP, run, running, stop_children};

/// Polls `ready` every 10 ms for up to a minute, failing with `what` when it never holds.
fn wait_for(what: &str, ready: impl Fn() -> bool) {
    for _ in 0..6000 {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{what} never happened");
}

#[test]
fn stopping_the_children_kills_a_running_plugin_and_frees_its_slot() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interrupt");
    std::fs::create_dir_all(&dir).unwrap();
    let (temporary, path) = (
        dir.join(format!("hung.{}.tmp", std::process::id())),
        dir.join("hung"),
    );
    std::fs::write(&temporary, "#!/bin/sh\nexec sleep 600\n").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&temporary, &path).unwrap();
    let plugin =
        std::thread::spawn(move || run(&path, &[], None, Duration::from_secs(600), OUTPUT_CAP));
    wait_for("a tracked child", || !running().is_empty());
    assert_eq!(stop_children(), 1);
    assert_eq!(
        plugin.join().unwrap().unwrap().code(),
        128 + libc::SIGKILL,
        "the plugin died of SIGKILL"
    );
    assert!(running().is_empty(), "its slot is free again");
}
