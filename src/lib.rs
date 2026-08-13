//! ANAJAKKH — AI-powered Red Team Security Agent.
//!
//! This library crate exposes the modules behind the `anajakkh` binary so
//! integration tests can exercise the agent pipeline directly.

pub mod agent;
pub mod ai;
pub mod app;
pub mod cli;
pub mod config;
pub mod evidence;
pub mod findings;
pub mod logging;
pub mod reports;
pub mod security;
pub mod storage;
pub mod tools;
pub mod tui;
