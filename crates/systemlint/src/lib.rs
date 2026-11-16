// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The systemlint core: configuration, plugin discovery, the plugin runner, fact collection and the rule engine.

pub mod collect;
pub mod collector;
pub mod config;
pub mod crash;
pub mod discovery;
pub mod document;
pub mod explain;
pub mod expression;
pub mod fix;
pub mod judge;
pub mod net;
pub mod progress;
pub mod report;
pub mod rules;
pub mod runner;
pub mod source;
pub mod steps;
pub mod trail;
pub mod vars;
pub mod version;
pub mod yaml;
