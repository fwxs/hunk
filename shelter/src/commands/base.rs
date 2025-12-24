use tokio::sync::mpsc::Sender;

use crate::nodes::Node;

#[derive(Debug, Clone, clap::Args)]
pub struct AdditionalArgs {
    /// Directory to store exfiltrated files
    #[arg(long = "output-dir", default_value = "loot", global = true)]
    pub loot_directory: std::path::PathBuf,

    /// Cipher key string for decrypting received files
    #[arg(long = "cipher-key-string", global = true)]
    pub cipher_key_string: Option<String>,

    /// Path to a file containing the cipher key for decrypting received files
    #[arg(long = "cipher-key-file", global = true)]
    pub cipher_key_file: Option<std::path::PathBuf>,

    /// URL to fetch the cipher key for decrypting received files
    #[arg(long = "cipher-key-url", global = true)]
    pub cipher_key_url: Option<String>,
}

impl AdditionalArgs {
    pub fn validate_cipher_key_existence(&self) {
        match self.cipher_key_string {
            Some(_) => log::info!("Using cipher key from provided string."),
            None => log::warn!("No cipher key string provided."),
        };

        match &self.cipher_key_file {
            Some(path) => {
                log::info!("Using cipher key from file: {}", path.display());

                if !path.exists() {
                    log::error!("Cipher key file does not exist: {}", path.display());
                }
            }
            None => log::warn!("No cipher key file provided."),
        };

        match &self.cipher_key_url {
            Some(url) => {
                log::info!("Using cipher key from URL: {}", url);

                if let Err(e) = reqwest::blocking::get(url) {
                    log::error!("Failed to fetch cipher key from URL: {}: {}", url, e);
                }
            }
            None => log::warn!("No cipher key URL provided."),
        };
    }
}

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

    #[command(flatten)]
    pub additional_args: AdditionalArgs,
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
