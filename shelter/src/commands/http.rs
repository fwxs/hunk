use actix_web::{web, App, HttpServer};

/// HTTP POST endpoint handler that receives a raw payload representing a single
/// exfiltrated file portion and forwards it to the background processing queue.
///
/// Expects `text/plain` bodies containing an encoded payload that can be parsed
/// by `ExfiltratedFilePortion::try_from`. On success the parsed portion is sent
/// to the provided `Sender` and an empty `Ok(())` is returned. Any parsing or
/// queue send errors are converted to the appropriate HTTP response error type.
pub async fn post_handler(
    req_body: String,
    tx: actix_web::web::Data<tokio::sync::mpsc::Sender<crate::ExfiltratedFilePortion>>,
) -> actix_web::Result<(), crate::error::http::HTTPResponseError> {
    log::info!("{} bytes received", req_body.len());
    log::debug!("Data received: {}", req_body);

    let exfil_file = crate::ExfiltratedFilePortion::try_from(req_body)?;
    log::info!("Sending file {} to queue", exfil_file.file_name);
    tx.send(exfil_file).await?;

    Ok(())
}

/// CLI arguments for the HTTP server subcommand.
///
/// Provides configuration for where the Actix web server should listen.
#[derive(Debug, clap::Args)]
pub struct HTTPServerTypeSubCommand {
    /// HTTP server listen address
    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1:8080")]
    pub http_server: std::net::SocketAddr,
}

impl HTTPServerTypeSubCommand {
    /// Start the Actix web server and register the POST endpoint used to receive
    /// exfiltrated file portions.
    ///
    /// The server registers a single route at `/` which requires the
    /// `Content-Type: text/plain` header and forwards incoming payloads to the
    /// provided `transfer_channel` for asynchronous processing.
    pub async fn handle(
        &self,
        transfer_channel: tokio::sync::mpsc::Sender<crate::ExfiltratedFilePortion>,
    ) -> std::io::Result<()> {
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
