//! Shelter binary entrypoint and runtime bootstrap.
//!
//! This binary exposes a small CLI used to select and configure a server
//! transport (HTTP or DNS) that accepts encoded file portions from remote agents,
//! forwards them into an internal queue and lets a background task assemble and
//! persist the final files.
//!
//! ## Architecture
//!
//! Shelter uses a dual-channel architecture to decouple reception from processing:
//!
//! **Reception Channel (transport-specific)**:
//! - HTTP POST handler or DNS query handler receives raw payloads
//! - Decodes and parses payloads into typed Node instances
//! - Sends parsed nodes immediately to the transfer channel
//!
//! **Processing Channel (background worker)**:
//! - Spawned at startup as a dedicated tokio task
//! - Receives Node instances from the transfer channel
//! - Maintains file assembly state (root nodes and chunks)
//! - Writes complete files to the loot directory on EOF
//!
//! This design allows rapid transport handling without blocking on I/O operations.
//!
//! The top-level TODOs below identify obvious future improvements such as
//! providing a configuration file, avoiding CLI/config conflicts and
//! enabling TLS for network transports.
// TODO! Add config file
// TODO! Add parameters which conflicts with config file
// TODO! Add TLS support

use clap::Parser;
use tracing_subscriber::prelude::*;

/// Application entrypoint and runtime initialization.
///
/// This async function performs the following initialization steps:
///
/// 1. **Logging Configuration**: Sets up tracing with environment-based filtering
///    (defaults to "info" level if RUST_LOG is not set)
///
/// 2. **Channel Creation**: Creates a bounded tokio::sync::mpsc channel with
///    capacity of 10 `Node` instances. This channel bridges transport handlers
///    (producers) with the background event handler (consumer).
///
/// 3. **Background Handler Spawn**: Spawns `shelter::event_handler::handle_received_data`
///    as a dedicated tokio task. This task runs concurrently, consuming Node instances
///    from the receiver channel and persisting complete files to the loot directory.
///
/// 4. **CLI Dispatch**: Parses command-line arguments and executes the selected
///    server subcommand (HTTP or DNS), passing the sender side of the channel.
///    The transport handler uses this sender to forward parsed payloads.
///
/// The function executes within the Actix-web runtime provided by the
/// `#[actix_web::main]` attribute, enabling async/await syntax and HTTP handling.
///
/// ## Concurrency Model
///
/// - The background handler runs as a spawned task independent of the main thread
/// - Transport handlers execute within the HTTP/DNS server's thread pool
/// - The MPSC channel enforces thread-safe message passing between handlers and processor
/// - Channel backpressure (when full) causes transport handlers to await, naturally
///   limiting reception rate if reassembly falls behind
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::Layer::default().compact())
        .init();

    let (transfer_channel, receiver_channel): (
        tokio::sync::mpsc::Sender<shelter::Node>,
        tokio::sync::mpsc::Receiver<shelter::Node>,
    ) = tokio::sync::mpsc::channel(10);

    let cli_args = shelter::commands::base::Cli::parse();

    log::info!("Launching waiting queue processor tokio channel...");
    tokio::spawn(shelter::event_handler::handle_received_data(
        receiver_channel,
        cli_args.loot_directory.clone(),
    ));

    cli_args.handle(transfer_channel).await
}
