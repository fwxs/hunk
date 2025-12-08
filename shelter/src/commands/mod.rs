//! CLI command definitions and server subcommand modules.
//!
//! This module groups the command-line argument parsing and per-transport
//! server subcommands used by the `shelter` binary. Each transport (for
//! example HTTP) implements its own submodule which provides a `handle`
//! method that starts the server and forwards parsed `ExfiltratedFilePortion`
//! messages into the provided processing channel.
pub mod base;
pub mod dns;
pub mod http;
