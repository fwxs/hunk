// TODO! Add error handling
// TODO! Add config file
// TODO! Add parameters which conflicts with config file
// TODO! Add TLS support

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use clap::Parser;
use env_logger::Env;
use shelter::ExfiltratedFile;

#[derive(clap::Parser)]
#[command(version)]
pub struct Cli {
    #[arg(long = "http-server", default_value = "127.0.0.1:8080")]
    pub http_server: std::net::SocketAddr,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let (tx, rx) = std::sync::mpsc::channel::<shelter::ExfiltratedFilePortion>();
    let mut files: std::collections::HashMap<String, ExfiltratedFile> =
        std::collections::HashMap::new();

    log::info!("Launching waiting queue processor thread...");
    std::thread::spawn(move || {
        let file_portion = rx.recv().unwrap();
        log::info!(
            "File {} portion number {} received!",
            file_portion.file_name,
            file_portion.index
        );

        if !files.contains_key(&file_portion.file_name) {
            files.insert(
                file_portion.file_name.clone(),
                shelter::ExfiltratedFile::new(file_portion.file_name.clone()),
            );
        } else {
            files
                .get_mut(&file_portion.file_name)
                .unwrap()
                .add_portion(file_portion);
        }
    });

    let cli_args = Cli::parse();
    log::info!("Launching shelter application on {}", cli_args.http_server);

    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(tx.clone()))
            .wrap(Logger::default().log_target("shelter"))
            .route(
                "/",
                web::post()
                    .guard(actix_web::guard::Header("Content-Type", "text/plain"))
                    .to(shelter::http::post_handler),
            )
    })
    .workers(1)
    .bind(&cli_args.http_server)?
    .run()
    .await
}
