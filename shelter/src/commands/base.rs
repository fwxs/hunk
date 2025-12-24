use tokio::sync::mpsc::Sender;

use crate::nodes::Node;

/// CLI entrypoint and argument definitions for the `shelter` application.
///
/// `Cli` is the top-level clap parser used to select which server backend to
/// run (currently HTTP) and to configure common options such as the directory
/// where recovered files (loot) will be stored.
#[derive(Debug, clap::Parser)]
#[command(version)]
pub struct Cli {
    /// The server type to launch.
    #[command(subcommand)]
    pub server_type: ServerType,

    /// Directory to store exfiltrated files
    #[arg(long = "output-dir", default_value = "loot")]
    pub loot_directory: String,
}

impl Cli {
    /// Execute the configured subcommand and start the selected server.
    ///
    /// This method forwards the provided `transfer_channel` to the underlying
    /// server implementation. Handlers use that channel to send parsed
    /// `ExfiltratedFilePortion` messages to the background processor.
    pub async fn handle(self, transfer_channel: Sender<Node>) -> std::io::Result<()> {
        match self.server_type {
            ServerType::HTTP(http_sub_cmd) => http_sub_cmd.handle(transfer_channel).await,
            ServerType::DNS(dns_sub_cmd) => dns_sub_cmd.handle(transfer_channel).await,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum ServerType {
    /// Launch an HTTP server to receive exfiltrated files.
    #[command(name = "http-server")]
    HTTP(super::http::HTTPServerTypeSubCommand),

    /// Launch a DNS server to receive exfiltrated files.
    #[command(name = "dns-server")]
    DNS(super::dns::DNSServerTypeSubCommand),
}
