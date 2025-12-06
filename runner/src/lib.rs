//! Runner library for the `hunk` project.
//!
//! This crate provides the core pieces used by the `runner` binary:
//! - The `commands` module contains CLI subcommands and wiring to execute different
//!   exfiltration flows (HTTP, DNS, etc.).
//! - The `encoder` module provides utilities for encoding and chunking file payloads
//!   (base64 -> hex encoding, DNS-safe splitting, etc.).
//!
//! The library exposes a small `CommandHandler` trait which CLI types implement to
//! perform their respective operation when invoked by the CLI entrypoint.
//!
//! Design notes:
//! - Ownership is preferred for command handlers: `handle(self)` consumes the command
//!   struct so implementations can move resources (paths, network clients) without cloning.
//! - Encoding utilities are intentionally kept separate from command implementations
//!   so they can be reused and tested independently.
pub mod commands;
pub mod encoder;

/// A thin abstraction implemented by CLI command structs to execute work.
///
/// Implementors should perform whatever IO/networking or processing the command
/// represents inside `handle`. The method takes ownership of `self` so implementors
/// can move owned fields (file paths, configuration, clients) without requiring extra
/// cloning.
///
/// Example use:
/// - Constructed by the `clap`-generated CLI parser and then dispatched from `main`.
pub trait CommandHandler {
    /// Execute the command, consuming the implementor.
    fn handle(self);
}
