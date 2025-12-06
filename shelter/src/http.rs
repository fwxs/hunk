use std::io::Write;
use std::ops::Not;

pub async fn post_handler(
    req_body: String,
    tx: actix_web::web::Data<std::sync::mpsc::Sender<crate::ExfiltratedFilePortion>>,
) -> actix_web::Result<(), crate::error::http::HTTPResponseError> {
    log::info!("{} bytes received", req_body.len());
    log::debug!("Data received: {}", req_body);

    let exfil_file = crate::ExfiltratedFilePortion::try_from(req_body)?;
    log::info!("Sending file {} to queue", exfil_file.file_name);
    tx.send(exfil_file)
        .inspect_err(|error| log::error!("{:?}", error))
        .unwrap();

    // let file_path = std::env::current_dir().unwrap().join(&exfil_file.file_name);

    // file_path.exists().not().then(|| {
    //     log::info!("Creating file {}", file_path.to_string_lossy());
    //     std::fs::File::create_new(exfil_file.file_name)
    // });

    // log::info!("Dumping file content in {}", file_path.to_string_lossy());
    // std::fs::File::options()
    //     .append(true)
    //     .open(file_path)
    //     .unwrap()
    //     .write_all(&exfil_file.file_content.as_slice())
    //     .unwrap();

    Ok(())
}
