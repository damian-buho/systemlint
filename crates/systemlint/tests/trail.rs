// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use systemlint::trail::{KEEP, collector, current, dump, keep, plugin, scoped, take};

#[test]
fn a_scope_keeps_its_last_records_dropping_the_oldest() {
    for n in 0..=KEEP {
        keep("collector edge", n.to_string());
    }
    let kept = take("collector edge");
    assert_eq!(kept.len(), KEEP);
    assert_eq!((kept[0].as_str(), kept[KEEP - 1].clone()), ("1", KEEP.to_string()));
}

#[test]
fn a_full_scope_keeps_every_record() {
    for n in 0..KEEP {
        keep("collector full", n.to_string());
    }
    assert_eq!(take("collector full").first().map(String::as_str), Some("0"));
}

#[test]
fn a_scope_ends_with_its_body_and_restores_the_outer_one() {
    assert_eq!((collector("sshd"), plugin("apt")), ("collector sshd".to_owned(), "plugin apt".to_owned()));
    let inner = scoped("outer", || scoped("inner", current));
    assert_eq!((inner.as_deref(), current()), (Some("inner"), None));
}

#[test]
fn the_dump_heads_every_record_with_its_scope() {
    keep("collector dumped", "read /etc/x".to_owned());
    let text = dump();
    assert!(text.starts_with("\nlast debug records:\n") && text.contains("\ncollector dumped: read /etc/x\n"), "{text}");
}
