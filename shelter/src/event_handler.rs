// TODO! Add dead-letter queue for unprocessed file portions
// TODO! Add circuit breaker inside the loop to avoid infinite processing until the system errors are fixed

use chacha20poly1305::{aead::Aead, KeyInit};
use std::io::Read;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
};

use crate::nodes::{root::RootNode, Node, ThreadSafeFileChunkNode};

/// Background event handler that processes exfiltrated file chunks and reconstructs files.
///
/// This async function runs continuously, consuming `Node` instances from the provided
/// channel. It maintains two primary data structures:
///
/// - `root_nodes`: A set of received root metadata nodes (file names + identifiers)
/// - `file_chunk_nodes`: A map from file_id → BTreeMap of chunks sorted by index
///
/// ## Processing Flow
///
/// When a Root node arrives, it is stored for later matching with chunks.
/// When a FileChunk node arrives, it is inserted into the appropriate index map.
/// When an End chunk (marked with ChunkType::End) arrives:
///
/// 1. The matching RootNode is located by file_identifier
/// 2. All FileChunk nodes for that file are retrieved and sorted by index
/// 3. Each chunk's hex-encoded data is decoded to raw bytes
/// 4. Decoded chunks are concatenated in index order to reconstruct the file
/// 5. The complete file is written to the loot directory with its original filename
/// 6. Both root node and file chunks are removed from memory
///
/// ## Data Format During Assembly
///
/// - Chunks stored in `file_chunk_nodes` have their `data` field as UTF-8 bytes
/// - During assembly, these UTF-8 bytes are passed to `hex::decode()` producing raw file bytes
/// - All chunks are concatenated by sorted index to produce the complete file
/// - Files are written directly to disk without additional encoding
pub async fn handle_received_data(
    mut rx: tokio::sync::mpsc::Receiver<crate::nodes::Node>,
    additional_args: crate::commands::base::AdditionalArgs,
) {
    let mut root_nodes: HashSet<RootNode> = HashSet::new();
    let mut file_chunk_nodes: HashMap<String, BTreeMap<usize, ThreadSafeFileChunkNode>> =
        HashMap::new();

    while let Some(node_received) = rx.recv().await {
        match node_received {
            Node::Root(root_node) => {
                handle_root_node(root_node, &mut root_nodes);
            }
            Node::FileChunk(file_chunk_node) => {
                let ref_file_chunk_node = std::sync::Arc::new(file_chunk_node);
                log::info!(
                    "{:?} chunk node index {} for root {} received!",
                    ref_file_chunk_node.chunk_type,
                    ref_file_chunk_node.index,
                    ref_file_chunk_node.root_node_id
                );

                insert_chunk_into_map(&ref_file_chunk_node, &mut file_chunk_nodes);

                if ref_file_chunk_node.is_last_chunk() {
                    match process_end_chunk(
                        &ref_file_chunk_node,
                        &mut root_nodes,
                        &mut file_chunk_nodes,
                        &additional_args,
                    ) {
                        Ok(_) => log::info!(
                            "File assembly and processing for root {} completed.",
                            ref_file_chunk_node.root_node_id
                        ),
                        Err(err) => log::error!(
                            "Error processing end chunk for root {}: {}",
                            ref_file_chunk_node.root_node_id,
                            err
                        ),
                    }
                }
            }
        }
    }
}

/// Handles the reception of a RootNode by inserting it into the root_nodes set.
///
/// # Arguments
///
/// * `root_node` - The RootNode instance that has been received.
/// * `root_nodes` - A mutable reference to the set of RootNode instances.
fn handle_root_node(root_node: RootNode, root_nodes: &mut HashSet<RootNode>) {
    log::info!("Root node {} received!", root_node.file_name);
    root_nodes.insert(root_node);
}

/// Inserts a FileChunkNode into the file_chunk_nodes map.
///
/// # Arguments
///
/// * `file_chunk_node` - A reference to the ThreadSafeFileChunkNode to be inserted.
/// * `file_chunk_nodes` - A mutable reference to the HashMap storing file chunk nodes.
///
/// This function checks if there is already an entry for the root_node_id in the map.
/// If so, it inserts the chunk into the existing BTreeMap. If not, it creates a new BTreeMap,
/// inserts the chunk, and adds it to the main map.
fn insert_chunk_into_map(
    file_chunk_node: &ThreadSafeFileChunkNode,
    file_chunk_nodes: &mut HashMap<String, BTreeMap<usize, ThreadSafeFileChunkNode>>,
) {
    if let Some(file_nodes) = file_chunk_nodes.get_mut(&file_chunk_node.root_node_id) {
        file_nodes.insert(
            file_chunk_node.index,
            std::sync::Arc::clone(file_chunk_node),
        );
    } else {
        let mut new_map: BTreeMap<usize, ThreadSafeFileChunkNode> = BTreeMap::new();
        new_map.insert(
            file_chunk_node.index,
            std::sync::Arc::clone(file_chunk_node),
        );
        file_chunk_nodes.insert(file_chunk_node.root_node_id.clone(), new_map);
    }
}

/// Processes the end chunk of a file, assembles the complete file, applies any necessary
/// metadata transformations, and saves it to disk.
///
/// # Arguments
///
/// * `file_chunk_node` - A reference to the ThreadSafeFileChunkNode representing the end chunk.
/// * `root_nodes` - A mutable reference to the set of RootNode instances.
/// * `file_chunk_nodes` - A mutable reference to the HashMap storing file chunk nodes.
/// * `loot_directory` - The directory where the assembled file should be saved.
///
/// This function retrieves the corresponding RootNode and all associated FileChunkNodes,
/// assembles the file data, applies any metadata transformations (e.g., decryption),
/// and saves the final file to the specified loot directory.
fn process_end_chunk(
    file_chunk_node: &ThreadSafeFileChunkNode,
    root_nodes: &mut HashSet<RootNode>,
    file_chunk_nodes: &mut HashMap<String, BTreeMap<usize, ThreadSafeFileChunkNode>>,
    additional_args: &crate::commands::base::AdditionalArgs,
) -> crate::error::app::Result<()> {
    log::info!(
        "End chunk received for root {}. Assembling file...",
        file_chunk_node.root_node_id
    );

    if let Some(root_node) = root_nodes.take(&file_chunk_node.root_node_id) {
        log::info!(
            "Root node {} found. Assembling file {}...",
            file_chunk_node.root_node_id,
            root_node.file_name
        );

        if let Some(file_nodes) = file_chunk_nodes.remove(&file_chunk_node.root_node_id) {
            let mut file_data = assemble_file_data(&file_nodes);
            apply_metadata_transformations(&mut file_data, &root_node, &additional_args)?;
            save_file_to_disk(&root_node, &file_data, &additional_args.loot_directory);
        } else {
            log::warn!(
                "No file chunks found for root node {}. Cannot assemble file.",
                file_chunk_node.root_node_id
            );
        }
    } else {
        log::warn!(
            "Root node {} not found. Cannot assemble file.",
            file_chunk_node.root_node_id
        );
    }

    Ok(())
}

/// Assembles the complete file data from the provided file chunk nodes.
///
/// # Arguments
/// * `file_nodes` - A reference to a BTreeMap containing the file chunk nodes sorted by index.
///
/// # Returns
/// A vector of bytes representing the assembled file data.
fn assemble_file_data(file_nodes: &BTreeMap<usize, ThreadSafeFileChunkNode>) -> Vec<u8> {
    file_nodes
        .values()
        .filter_map(|file_chunk| hex::decode(file_chunk.data.to_vec()).ok())
        .flatten()
        .collect()
}

/// Applies metadata transformations (e.g., decryption) to the assembled file data
/// based on the provided RootNode's metadata.
///
/// # Arguments
///
/// * `file_data` - A mutable reference to the vector of bytes representing the file data.
/// * `root_node` - A reference to the RootNode containing metadata information.
/// * `additional_args` - A reference to AdditionalArgs containing any extra parameters.
///
/// This function checks for any additional metadata in the RootNode and applies
/// the corresponding transformations to the file data.
fn apply_metadata_transformations(
    file_data: &mut Vec<u8>,
    root_node: &RootNode,
    additional_args: &crate::commands::base::AdditionalArgs,
) -> crate::error::app::Result<()> {
    if let Some(metadata_list) = &root_node.additional_metadata {
        log::info!(
            "Additional metadata for file {}: {:?}",
            root_node.file_name,
            metadata_list
        );

        for metadata in metadata_list {
            match metadata {
                crate::nodes::root::PayloadMetadata::Encrypted(enc_type) => {
                    apply_decryption(file_data, enc_type, root_node, &additional_args)?;
                }
            }
        }
    }

    Ok(())
}

/// Applies decryption to the file data based on the specified encryption type.
///
/// # Arguments
/// * `file_data` - A mutable reference to the vector of bytes representing the file data.
/// * `enc_type` - A reference to the EncryptionType indicating the type of encryption used.
/// * `root_node` - A reference to the RootNode containing metadata information.
/// * `additional_args` - A reference to AdditionalArgs containing any extra parameters.
///
/// This function matches the encryption type and calls the appropriate decryption method.
fn apply_decryption(
    file_data: &mut Vec<u8>,
    enc_type: &crate::nodes::root::EncryptionType,
    root_node: &RootNode,
    additional_args: &crate::commands::base::AdditionalArgs,
) -> crate::error::app::Result<()> {
    match enc_type {
        crate::nodes::root::EncryptionType::String => {
            match additional_args.cipher_key_string.as_deref() {
                Some(key) => decrypt_with_string_key(file_data, &key, root_node),
                None => {
                    log::error!(
                        "No cipher key string provided for decrypting file {}",
                        root_node.file_name
                    );
                    Ok(())
                }
            }
        }
        crate::nodes::root::EncryptionType::File => match &additional_args.cipher_key_file {
            Some(key_path) => decrypt_with_file_key(file_data, key_path, root_node),
            None => {
                log::error!(
                    "No cipher key file path provided for decrypting file {}",
                    root_node.file_name
                );
                Ok(())
            }
        },
        crate::nodes::root::EncryptionType::Url => {
            match additional_args.cipher_key_url.as_deref() {
                Some(url) => decrypt_with_url_key(file_data, &url, root_node),
                None => {
                    log::error!(
                        "No cipher key URL provided for decrypting file {}",
                        root_node.file_name
                    );
                    Ok(())
                }
            }
        }
    }
}

/// Decrypts the file data using a provided string key.
///
/// # Arguments
///
/// * `file_data` - A mutable reference to the vector of bytes representing the file data.
/// * `key` - A string slice representing the decryption key.
/// * `root_node` - A reference to the RootNode containing metadata information.
///
/// This function logs the decryption attempt and calls the `decrypt` function
/// to perform the actual decryption using the provided key.
///
/// # Errors
/// This function returns an error if the decryption process encounters an error.
fn decrypt_with_string_key(
    file_data: &mut Vec<u8>,
    key: &str,
    root_node: &RootNode,
) -> crate::error::app::Result<()> {
    log::info!(
        "Decrypting file {} with String encryption",
        root_node.file_name
    );

    decrypt(file_data, key, root_node)
}

/// Decrypts the file data using a key read from the specified file path.
///
/// # Arguments
/// * `file_data` - A mutable reference to the vector of bytes representing the file data.
/// * `key_path` - A reference to the PathBuf representing the file path to read the decryption key from.
/// * `root_node` - A reference to the RootNode containing metadata information.
///
/// This function reads the decryption key from the specified file,
/// then calls the `decrypt` function to decrypt the file data using the read key.
///
/// # Errors
/// This function returns an error if reading the key file fails or if the decryption process encounters an error.
fn decrypt_with_file_key(
    file_data: &mut Vec<u8>,
    key_path: &PathBuf,
    root_node: &RootNode,
) -> crate::error::app::Result<()> {
    log::info!(
        "Decrypting file {} with using {} encryption",
        root_node.file_name,
        key_path.to_string_lossy().to_string()
    );

    let mut opened_file = std::fs::File::open(key_path)?;
    let mut file_buffer: Vec<u8> = Vec::new();
    opened_file.read_to_end(&mut file_buffer)?;
    let key = String::from_utf8_lossy(&file_buffer).to_string();

    decrypt(file_data, &key, root_node)
}

/// Decrypts the file data using a key fetched from the provided URL.
/// # Arguments
/// * `file_data` - A mutable reference to the vector of bytes representing the file data
/// * `url` - A string slice representing the URL to fetch the decryption key from.
/// * `root_node` - A reference to the RootNode containing metadata information.
///
/// This function makes an HTTP GET request to the specified URL to retrieve the decryption key,
/// then calls the `decrypt` function to decrypt the file data using the fetched key.
///
/// # Errors
/// This function returns an error if the HTTP request fails or if the decryption process encounters an
/// error.
fn decrypt_with_url_key(
    file_data: &mut Vec<u8>,
    url: &str,
    root_node: &RootNode,
) -> crate::error::app::Result<()> {
    log::info!(
        "Decrypting file {} with URL {} encryption",
        root_node.file_name,
        url
    );

    let response = reqwest::blocking::get(url)?;
    let key = response.text()?;

    decrypt(file_data, &key, root_node)
}

/// Decrypts the file data using ChaCha20-Poly1305 with the provided key and nonce derived
/// from the RootNode.
/// # Arguments
/// * `file_data` - A mutable reference to the vector of bytes representing the file data.
/// * `key` - A string slice representing the decryption key.
/// * `root_node` - A reference to the RootNode containing metadata information.
/// This function constructs the nonce from the file name and identifier,
/// initializes the ChaCha20-Poly1305 cipher, and attempts to decrypt the file data.
/// On success, the decrypted data replaces the original file data. On failure, an error is logged.
fn decrypt(
    file_data: &mut Vec<u8>,
    key: &str,
    root_node: &RootNode,
) -> crate::error::app::Result<()> {
    let key = match std::panic::catch_unwind(|| chacha20poly1305::Key::from_slice(key.as_bytes())) {
        Ok(key) => key,
        Err(_) => {
            return Err(crate::error::app::AppError::chacha20_error(
                "Invalid key length for ChaCha20-Poly1305. Key must be 32 bytes.",
            ))
        }
    };
    let nonce = format!("{}:{}", root_node.file_name, root_node.file_identifier);

    let nonce = match std::panic::catch_unwind(|| {
        chacha20poly1305::Nonce::from_slice(nonce.as_bytes().last_chunk::<12>().unwrap())
    }) {
        Ok(nonce) => nonce,
        Err(_) => {
            return Err(crate::error::app::AppError::chacha20_error(
                "Invalid nonce length for ChaCha20-Poly1305. Nonce must be 12 bytes.",
            ))
        }
    };
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);

    match cipher.decrypt(nonce, file_data.as_ref()) {
        Ok(decrypted_data) => {
            *file_data = decrypted_data;
            log::info!("File {} decrypted successfully", root_node.file_name);
        }
        Err(err) => {
            log::error!(
                "Error decrypting file {}: {}",
                root_node.file_name,
                err.to_string()
            );
        }
    };

    Ok(())
}

/// Saves the assembled file data to disk in the specified loot directory.
///
/// # Arguments
///
/// * `root_node` - A reference to the RootNode containing file metadata.
/// * `file_data` - A slice of bytes representing the assembled file data.
/// * `loot_directory` - A string slice representing the directory where the file should be saved.
///
/// This function checks if the loot directory exists, creates it if necessary,
/// and writes the file data to disk using the original file name from the RootNode.
fn save_file_to_disk(root_node: &RootNode, file_data: &[u8], loot_directory: &PathBuf) {
    match std::env::current_dir() {
        Ok(current_dir) => {
            log::info!(
                "Current working directory: {}",
                current_dir.to_string_lossy()
            );

            let loot_path = current_dir.join(loot_directory);
            if !loot_path.exists() {
                log::info!(
                    "Loot directory not found. Creating at {}",
                    loot_path.to_string_lossy()
                );
                if let Err(err) = std::fs::create_dir(&loot_path) {
                    log::error!(
                        "Error creating loot directory {}: {}",
                        loot_path.to_string_lossy(),
                        err
                    );
                    return;
                }
            }

            let exfil_file_path = loot_path.join(&root_node.file_name);
            match std::fs::write(&exfil_file_path, file_data) {
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
            log::error!("Error getting current working directory: {}", err)
        }
    }
}
