//! CLI command definitions and dispatch for the runner.
//!
//! This module contains the top-level CLI wiring used by the `runner` binary.
//! It defines the `Cli` struct parsed by `clap`, an `Operations` enum for the
//! supported subcommands and implements a small dispatch mechanism that calls
//! into the concrete command implementations located in `commands::exfiltrate`.
//!
//! Design goals:
//! - Keep parsing and dispatch logic minimal; command implementations perform
//!   the actual IO/networking work.
//! - Use ownership when invoking handlers so commands can move resources
//!   (paths, clients) without additional cloning.
//!
//! TODOs present in the original codebase remain as notes for future features:
//! - Compression and encryption support
//! - Additional exfiltration methods and scheduling support
//! - Logging, retry and progress indicator options

use crate::CommandHandler;
use clap::{Parser, Subcommand};

/// Top-level CLI structure parsed from program arguments.
///
/// The `Cli` struct is the entry point for command-line parsing and contains a
/// single `operation_type` field which represents one of the supported
/// subcommands. The struct uses `clap`'s `Parser` derive to provide argument
/// parsing and `--version` handling.
#[derive(Parser)]
#[command(version)]
pub struct Cli {
    /// The operation/subcommand to execute.
    #[command(subcommand)]
    pub operation_type: Operations,
}

impl Cli {
    /// Dispatch and execute the selected subcommand.
    ///
    /// This consumes the `Cli` instance and delegates to the underlying
    /// `Operations::handle` implementation.
    pub fn handle(self) -> crate::error::Result<()> {
        self.operation_type.handle()
    }
}

/// Supported top-level operations/subcommands.
///
/// Each variant corresponds to a specific operation (for example, file
/// exfiltration). Variants wrap the concrete argument structs implemented in
/// the `commands` submodules.
#[derive(Debug, Subcommand)]
pub enum Operations {
    /// Exfiltrate files using the available exfiltration subcommands.
    #[command(name = "exfil")]
    Exfiltration(super::exfiltrate::ExfiltrationSubCommandArgs),
}

impl CommandHandler for Operations {
    /// Execute the selected operation.
    ///
    /// The method consumes the `Operations` enum and passes control to the
    /// concrete command handler for the selected variant.
    fn handle(self) -> crate::error::Result<()> {
        match self {
            Operations::Exfiltration(exfil_sub_cmd_args) => exfil_sub_cmd_args.handle()?,
        };

        Ok(())
    }
}
