//! Event handler utilities for processing incoming exfiltrated file portions.
//!
//! This module provides an async consumer that listens on a tokio mpsc receiver
//! for `ExfiltratedFilePortion` messages, reassembles file chunks in memory, and
//! writes completed files into a configured loot directory on disk.
//!
//! Notes:
//! - The implementation is intentionally tolerant to decoding/writing errors and
//!   will log errors while continuing to process subsequent messages.
//! - Future improvements could add a dead-letter queue and circuit breaker
//!   behavior to avoid infinite retries or resource exhaustion.
// TODO! Add dead-letter queue for unprocessed file portions
// TODO! Add circuit breaker inside the loop to avoid infinite processing until the system errors are fixed

use std::ops::Not;

/// Consume a stream of `ExfiltratedFilePortion` messages and persist completed files.
///
/// The function maintains an in-memory map of partially assembled files keyed by
/// file name. When it receives a portion whose `is_last_portion` flag is true it:
/// 1. Ensures the configured `loot_directory` exists under the current working directory.
/// 2. Reconstructs and decodes the bytes for the file.
/// 3. Writes the decoded file contents to disk.
///
/// Parameters:
/// - `rx`: Receiver for incoming `ExfiltratedFilePortion` messages. The function
///   runs until the sender side of the channel is closed and all messages are consumed.
/// - `loot_directory`: Relative directory path (under current working directory)
///   where recovered files will be stored.
///
/// Behaviour:
/// - Logs informational events and errors. Errors do not stop processing of the loop.
/// - Successfully written files are removed from the internal map after persistence.
pub async fn handle_received_data(
    mut rx: tokio::sync::mpsc::Receiver<crate::ExfiltratedFilePortion>,
    loot_directory: String,
) {
    let mut files_hashmap: std::collections::HashMap<String, crate::ExfiltratedFile> =
        std::collections::HashMap::new();

    while let Some(file_portion) = rx.recv().await {
        let file_name = file_portion.file_name.clone();
        let is_last_portion = file_portion.is_last_portion;

        log::info!(
            "File {} portion number {} received!",
            file_portion.file_name,
            file_portion.index
        );

        if !files_hashmap.contains_key(&file_name) {
            let mut exfil_file = crate::ExfiltratedFile::new(file_name.clone());
            exfil_file.add_portion(file_portion);
            files_hashmap.insert(file_name.clone(), exfil_file);
        } else {
            if let Some(exfil_file) = files_hashmap.get_mut(&file_name) {
                exfil_file.add_portion(file_portion);
            }
        }

        if is_last_portion {
            match std::env::current_dir() {
                Ok(current_dir) => {
                    log::info!(
                        "Current working directory: {}",
                        current_dir.to_string_lossy()
                    );
                    let loot_directory = current_dir.join(&loot_directory);
                    loot_directory.exists().not().then(|| {
                        log::info!(
                            "Loot directory not found. Creating at {}",
                            loot_directory.to_string_lossy()
                        );
                        std::fs::create_dir(&loot_directory)
                    });
                    let exfil_file_path = loot_directory.join(&file_name);

                    exfil_file_path.exists().not().then(|| {
                        match std::fs::File::create_new(&exfil_file_path) {
                            Ok(_) => log::info!(
                                "Created new file at {}",
                                exfil_file_path.to_string_lossy()
                            ),
                            Err(err) => log::error!(
                                "Error creating file {}: {}",
                                exfil_file_path.to_string_lossy(),
                                err
                            ),
                        };
                    });

                    if let Some(exfiltrated_file) = files_hashmap.get(&file_name) {
                        match String::from_utf8(exfiltrated_file.get_file_contents()) {
                            Ok(decoded_data) => {
                                match std::fs::write(&exfil_file_path, decoded_data) {
                                    Ok(_) => log::info!(
                                        "Dumping file content in {}",
                                        exfil_file_path.to_string_lossy()
                                    ),
                                    Err(err) => log::error!(
                                        "Error writing to file {}: {}",
                                        exfil_file_path.to_string_lossy(),
                                        err
                                    ),
                                }
                            }
                            Err(err) => {
                                log::error!(
                                    "Error decoding file contents for {}: {}",
                                    file_name,
                                    err
                                )
                            }
                        }
                    }

                    files_hashmap.remove(&file_name);
                }
                Err(err) => log::error!("Error getting current working directory: {}", err),
            }
        }
    }
}
