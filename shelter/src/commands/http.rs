use actix_web::{web, App, HttpServer};
use tokio::sync::mpsc::Sender;

use crate::nodes::Node;

/// HTTP POST endpoint handler that receives exfiltrated file portions.
///
/// This handler accepts `text/plain` request bodies containing double-encoded
/// payloads with the structure: Base64(Hex(colon-delimited-text))
///
/// ## Payload Format
///
/// The request body must be a single hex-base64 encoded string representing either:
/// - **Root Node**: `r:filename:file_id`
/// - **File Chunk**: `f:root_id:chunk_index:hex_encoded_data`
/// - **End Chunk**: `e:root_id:chunk_index:hex_encoded_data`
///
/// The entire payload is then hex-encoded and base64-encoded before transmission.
///
/// ## Processing
///
/// 1. **Decoding**: The payload is decoded via `Node::try_from()`:
///    - Base64 decode → Hex decode → UTF-8 conversion
/// 2. **Parsing**: Colon-delimited fields are parsed into RootNode or FileChunkNode types
/// 3. **Queuing**: The parsed Node is forwarded to the background handler channel
/// 4. **Response**: On success, HTTP 200 is returned; errors return 400 or 500
///
/// ## Error Handling
///
/// - **Malformed payload** (bad hex/base64/UTF-8): Returns HTTP 400 Bad Request
/// - **Channel send failure** (queue full or closed): Returns HTTP 500 Internal Server Error
/// - All errors are logged for diagnostic purposes
pub async fn post_handler(
    req_body: String,
    tx: actix_web::web::Data<Sender<Node>>,
) -> actix_web::Result<(), crate::error::http::HTTPResponseError> {
    log::info!("{} bytes received", req_body.len());
    log::debug!("Data received: {}", req_body);

    let node_received = Node::try_from(req_body)?;
    log::info!("Sending node {} to queue", node_received.node_type());
    tx.send(node_received).await?;

    Ok(())
}

/// CLI arguments for the HTTP server subcommand.
///
/// Configures the HTTP transport layer for receiving exfiltrated file portions.
/// The server listens on the specified address and exposes a single POST endpoint
/// that accepts double-encoded payloads (Base64(Hex(colon-delimited-fields))).
///
/// ## Configuration
///
/// - `http_server`: Socket address (host:port) where the server binds
///   - Default: 127.0.0.1:8080
///   - Examples: 0.0.0.0:8080 (listen on all interfaces), 192.168.1.100:9000
///
/// ## Endpoint Details
///
/// The server exposes a single POST route at `/` that:
/// - **Accepts**: `Content-Type: text/plain` request bodies
/// - **Body Format**: Double-encoded string (Base64(Hex(colon-delimited-text)))
/// - **Processing**: Decodes and parses incoming payloads into Node instances
/// - **Forwarding**: Sends parsed Node to the background processing channel
/// - **Response**: HTTP 200 OK on success, 400 on decode/parse errors, 500 on queue errors
///
/// ## Payload Examples
///
/// Root node (filename: "secret.txt", id: "abc123"):
/// ```text
/// r:secret.txt:abc123
/// ↓ (hex encode)
/// 723a7365637265742e7478743a616263313233
/// ↓ (base64 encode)
/// base64_encoded_string
/// ```
/// Send as POST body with Content-Type: text/plain
#[derive(Debug, clap::Args)]
pub struct HTTPServerTypeSubCommand {
    /// HTTP server listen address (host:port)
    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1:8080")]
    pub http_server: std::net::SocketAddr,
}

impl HTTPServerTypeSubCommand {
    /// Start the HTTP server and begin receiving exfiltrated file portions.
    ///
    /// This method:
    /// 1. Binds an Actix web server to the configured listen address
    /// 2. Registers a single POST route at `/` with content-type guard
    /// 3. Associates the route with the provided transfer_channel sender
    /// 4. Runs indefinitely, handling incoming requests
    ///
    /// ## Request Processing
    ///
    /// Each POST request to `/` is processed as follows:
    /// - **Guard**: Request must have `Content-Type: text/plain` header
    /// - **Body**: String containing hex-base64 encoded payload
    /// - **Handler**: `post_handler` decodes and parses the payload
    /// - **Channel**: Parsed Node is sent to transfer_channel for assembly
    /// - **Backpressure**: If channel is full (10 items), handler blocks until space available
    /// - **Response**: Client receives HTTP 200 OK or appropriate error code
    ///
    /// ## Server Configuration
    ///
    /// - Single worker thread for serialized processing
    /// - Distributed tracing enabled via `tracing_actix_web` middleware
    /// - Graceful shutdown when the application exits
    ///
    /// ## Error Handling
    ///
    /// - Binding errors (port in use, permission denied) are returned as std::io::Error
    /// - Individual request errors are handled by post_handler and returned as HTTP responses
    pub async fn handle(&self, transfer_channel: Sender<Node>) -> std::io::Result<()> {
        log::info!("Launching shelter application on {}", self.http_server);

        HttpServer::new(move || {
            App::new()
                .wrap(tracing_actix_web::TracingLogger::default())
                .app_data(actix_web::web::Data::new(transfer_channel.clone()))
                .route(
                    "/",
                    web::post()
                        .guard(actix_web::guard::Header("Content-Type", "text/plain"))
                        .to(post_handler),
                )
        })
        .workers(1)
        .bind(&self.http_server)?
        .run()
        .await
    }
}
