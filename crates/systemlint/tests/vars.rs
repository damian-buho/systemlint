// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use systemlint::judge::{Outcome, compile, lint};
use systemlint::rules::{Library, Ruleset};
use systemlint::vars::{Supplied, apply};

const NTP: &str = "vars:\n  ntp: {default: pool.ntp.org, from-env: NTP_SERVER}\n  age: {default: 90}\nwhen: {os.release.ID: '${ntp}'}\nrules:\n  t/ntp: {fact: ntp.server, expect: {const: '${ntp}'}, message: 'use ${ntp}, not {got}; costs $5 and $${ntp}'}\n  t/age: {fact: login.max-days, expect: {maximum: '${age}'}, message: 'at most ${age} days', fix: 'set ${age}'}\n  t/all: {facts: {all: [{fact: a, expect: {const: '${age}'}}]}}\n";

fn rulesets(yaml: &str) -> BTreeMap<String, Ruleset> {
    BTreeMap::from([(
        "fleet".to_owned(),
        systemlint::yaml::from_str(yaml).unwrap(),
    )])
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn env(name: &str) -> Option<String> {
    (name == "NTP_SERVER").then(|| "env.example".to_owned())
}

fn filled(supplied: &Supplied) -> Result<Ruleset, String> {
    let mut sets = rulesets(NTP);
    apply(&mut sets, supplied).map(|()| sets.remove("fleet").unwrap())
}

fn ntp(supplied: &Supplied) -> Value {
    filled(supplied).unwrap().rules["t/ntp"]["expect"]["const"].clone()
}

#[test]
fn defaults_fill_expect_when_and_message_keeping_whole_value_types() {
    let set = filled(&Supplied {
        env: no_env,
        ..Supplied::default()
    })
    .unwrap();
    assert_eq!(
        set.rules["t/ntp"]["expect"],
        json!({"const": "pool.ntp.org"})
    );
    assert_eq!(
        set.rules["t/ntp"]["message"],
        "use pool.ntp.org, not {got}; costs $5 and ${ntp}"
    );
    assert_eq!(
        set.rules["t/age"]["expect"],
        json!({"maximum": 90}),
        "a whole-string reference keeps the number"
    );
    assert_eq!(set.rules["t/age"]["message"], "at most 90 days");
    assert_eq!(set.rules["t/age"]["fix"], "set 90");
    assert_eq!(
        set.rules["t/all"]["facts"]["all"][0]["expect"],
        json!({"const": 90})
    );
    assert_eq!(
        serde_json::to_value(set.when.unwrap()).unwrap(),
        json!({"os.release.ID": "pool.ntp.org"})
    );
}

#[test]
fn flags_beat_env_beat_config_beat_default() {
    let flag = |name: &str, v: &str| (name.to_owned(), map(json!({"ntp": v})));
    let config = map(json!({"ntp": "config.example"}));
    assert_eq!(
        ntp(&Supplied {
            env: no_env,
            ..Supplied::default()
        }),
        "pool.ntp.org"
    );
    assert_eq!(
        ntp(&Supplied {
            config: config.clone(),
            env: no_env,
            ..Supplied::default()
        }),
        "config.example"
    );
    assert_eq!(
        ntp(&Supplied {
            config: config.clone(),
            env,
            ..Supplied::default()
        }),
        "env.example"
    );
    assert_eq!(
        ntp(&Supplied {
            flags: vec![flag("--vars f.yaml", "file.example")],
            config: config.clone(),
            env
        }),
        "file.example"
    );
    assert_eq!(
        ntp(&Supplied {
            flags: vec![
                flag("--var", "flag.example"),
                flag("--vars f.yaml", "file.example")
            ],
            config,
            env
        }),
        "flag.example"
    );
}

#[test]
fn a_text_value_takes_the_type_of_its_default() {
    let age = |v: &str| {
        filled(&Supplied {
            flags: vec![("--var".to_owned(), map(json!({"age": v})))],
            env: no_env,
            ..Supplied::default()
        })
    };
    assert_eq!(age("30").unwrap().rules["t/age"]["expect"]["maximum"], 30);
    assert_eq!(age("0.5").unwrap().rules["t/age"]["expect"]["maximum"], 0.5);
    assert_eq!(
        age("thirty").unwrap_err(),
        "ruleset fleet: var age from --var: “thirty” is not a number like its default"
    );
    let mut flag = rulesets(
        "vars:\n  on: {default: false}\nrules:\n  t/x: {fact: x, expect: {const: '${on}'}}\n",
    );
    apply(
        &mut flag,
        &Supplied {
            config: map(json!({"on": "true"})),
            env: no_env,
            ..Supplied::default()
        },
    )
    .unwrap();
    assert_eq!(flag["fleet"].rules["t/x"]["expect"]["const"], true);
    let mut bad = rulesets("vars:\n  on: {default: false}\nrules: {}\n");
    assert!(
        apply(
            &mut bad,
            &Supplied {
                config: map(json!({"on": "yes"})),
                env: no_env,
                ..Supplied::default()
            }
        )
        .unwrap_err()
        .contains("“yes” is not true or false")
    );
}

#[test]
fn every_gap_fails_the_load_naming_the_var_and_ruleset() {
    let refused =
        |yaml: &str, supplied: Supplied| apply(&mut rulesets(yaml), &supplied).unwrap_err();
    assert_eq!(
        refused(
            "vars:\n  site: {from-env: SITE}\nrules: {}\n",
            Supplied {
                env: no_env,
                ..Supplied::default()
            }
        ),
        "ruleset fleet: var site has no default and no value; pass --var site=VALUE, set SITE or set lint.vars.site"
    );
    assert_eq!(
        refused(
            "rules:\n  t/x: {fact: x, expect: {const: '${nope}'}}\n",
            Supplied::default()
        ),
        "ruleset fleet: rule t/x: expect: ${nope} is not a var this ruleset declares"
    );
    assert_eq!(
        refused(
            "rules:\n  t/x: {fact: x, expect: {}, message: 'a ${open'}\n",
            Supplied::default()
        ),
        "ruleset fleet: rule t/x: message: “a ${open” opens ${ without a closing }"
    );
    assert_eq!(
        refused(
            "vars:\n  l: {default: [1]}\nrules:\n  t/x: {fact: x, expect: {}, message: 'is ${l}'}\n",
            Supplied::default()
        ),
        "ruleset fleet: rule t/x: message: var l is not a string, number or boolean, so it fills only a whole value"
    );
    assert_eq!(
        refused(
            "vars:\n  'a b': {default: 1}\nrules: {}\n",
            Supplied::default()
        ),
        "ruleset fleet: var “a b” needs a name of letters, digits, _, - and ."
    );
    assert_eq!(
        refused(
            NTP,
            Supplied {
                flags: vec![("--vars f.yaml".to_owned(), map(json!({"ntpp": "x"})))],
                ..Supplied::default()
            }
        ),
        "--vars f.yaml sets var ntpp, which no ruleset declares"
    );
    assert_eq!(
        refused(
            NTP,
            Supplied {
                config: map(json!({"ntpp": "x"})),
                ..Supplied::default()
            }
        ),
        "lint.vars sets var ntpp, which no ruleset declares"
    );
}

#[test]
fn a_filled_rule_judges_the_supplied_value() {
    let mut sets = rulesets(NTP);
    apply(
        &mut sets,
        &Supplied {
            flags: vec![("--var".to_owned(), map(json!({"ntp": "time.example"})))],
            env: no_env,
            ..Supplied::default()
        },
    )
    .unwrap();
    let spec = Library::new(sets)
        .unwrap()
        .resolve("t/ntp")
        .unwrap()
        .remove("t/ntp")
        .unwrap();
    let document = json!({"meta": {}, "collectors": {}, "os": {"release": {"ID": "time.example"}}, "ntp": {"server": "pool.ntp.org"}});
    let checks = lint(
        &document,
        &[compile("t/ntp", spec).unwrap()],
        &[],
        "2026-11-12",
    );
    assert_eq!(checks[0].outcome, Outcome::Fail);
    assert!(
        checks[0]
            .message
            .as_deref()
            .unwrap()
            .starts_with("use time.example, not “pool.ntp.org”"),
        "{:?}",
        checks[0].message
    );
}

#[test]
fn x_cel_reads_vars_typed_and_its_text_is_never_filled() {
    let mut sets = rulesets(
        "vars:\n  share: {default: 0.5}\n  ntp: {default: pool.ntp.org}\nrules:\n  t/share: {fact: a, expect: {x-cel: 'double(self) <= vars.share * double(facts.b) && \"${ntp}\" != vars.ntp'}}\n",
    );
    apply(
        &mut sets,
        &Supplied {
            env: no_env,
            ..Supplied::default()
        },
    )
    .unwrap();
    let spec = serde_json::from_value(sets["fleet"].rules["t/share"].clone()).unwrap();
    let rule = compile("t/share", spec).unwrap();
    let outcome = |a: i64| {
        lint(
            &json!({"a": a, "b": 10}),
            std::slice::from_ref(&rule),
            &[],
            "2026-11-16",
        )[0]
        .outcome
    };
    assert_eq!((outcome(5), outcome(6)), (Outcome::Pass, Outcome::Fail));
}
