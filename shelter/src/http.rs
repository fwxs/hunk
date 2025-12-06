pub async fn post_handler(
    req_body: String,
    tx: actix_web::web::Data<tokio::sync::mpsc::Sender<crate::ExfiltratedFilePortion>>,
) -> actix_web::Result<(), crate::error::http::HTTPResponseError> {
    log::info!("{} bytes received", req_body.len());
    log::debug!("Data received: {}", req_body);

    let exfil_file = crate::ExfiltratedFilePortion::try_from(req_body)?;
    log::info!("Sending file {} to queue", exfil_file.file_name);
    tx.send(exfil_file)
        .await
        .inspect_err(|error| log::error!("{:?}", error))
        .unwrap();

    Ok(())
}
