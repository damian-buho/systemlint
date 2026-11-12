// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The systemlint core: configuration, plugin discovery, the plugin runner and fact collection.

pub mod collect;
pub mod collector;
pub mod config;
pub mod discovery;
pub mod document;
pub mod runner;
pub mod source;
