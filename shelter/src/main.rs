// TODO! Add error handling
// TODO! Add config file
// TODO! Add parameters which conflicts with config file
// TODO! Add TLS support

use std::{io::Write, ops::Not};

use actix_web::{web, App, HttpServer};
use clap::Parser;
use shelter::ExfiltratedFile;
use tracing_subscriber::prelude::*;

#[derive(clap::Parser)]
#[command(version)]
pub struct Cli {
    #[arg(long = "http-server", default_value = "127.0.0.1:8080")]
    pub http_server: std::net::SocketAddr,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::Layer::default().compact())
        .init();

    let (tx, mut rx): (
        tokio::sync::mpsc::Sender<shelter::ExfiltratedFilePortion>,
        tokio::sync::mpsc::Receiver<shelter::ExfiltratedFilePortion>,
    ) = tokio::sync::mpsc::channel(10);
    let mut files_hashmap: std::collections::HashMap<String, ExfiltratedFile> =
        std::collections::HashMap::new();

    log::info!("Launching waiting queue processor tokio channel...");
    tokio::spawn(async move {
        while let Some(file_portion) = rx.recv().await {
            let file_name = file_portion.file_name.clone();
            let is_last_portion = file_portion.is_last_portion;

            log::info!(
                "File {} portion number {} received!",
                file_portion.file_name,
                file_portion.index
            );

            if log::max_level() == log::LevelFilter::Debug {
                log::debug!(
                    "Payload data: {}",
                    String::from_utf8(file_portion.file_content.clone()).unwrap()
                );
            }

            if !files_hashmap.contains_key(&file_name) {
                let mut exfil_file = shelter::ExfiltratedFile::new(file_name.clone());
                exfil_file.add_portion(file_portion);
                files_hashmap.insert(file_name.clone(), exfil_file);
            } else {
                files_hashmap
                    .get_mut(&file_name)
                    .unwrap()
                    .add_portion(file_portion);
            }

            if is_last_portion {
                let loot_directory = std::env::current_dir().unwrap().join("loot");
                loot_directory.exists().not().then(|| {
                    log::info!(
                        "Loot directory not found. Creating at {}",
                        loot_directory.to_string_lossy()
                    );
                    std::fs::create_dir(&loot_directory)
                });
                let exfil_file_path = loot_directory.join(&file_name);

                exfil_file_path.exists().not().then(|| {
                    log::info!("Creating file {}", exfil_file_path.to_string_lossy());
                    std::fs::File::create_new(&exfil_file_path).unwrap();
                });

                log::info!(
                    "Dumping file content in {}",
                    exfil_file_path.to_string_lossy()
                );
                let decoded_data =
                    String::from_utf8(files_hashmap[&file_name].get_file_contents()).unwrap();
                std::fs::write(exfil_file_path, decoded_data).unwrap();

                files_hashmap.remove(&file_name);
            }
        }
    });

    let cli_args = Cli::parse();
    log::info!("Launching shelter application on {}", cli_args.http_server);

    HttpServer::new(move || {
        App::new()
            .wrap(tracing_actix_web::TracingLogger::default())
            .app_data(actix_web::web::Data::new(tx.clone()))
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
