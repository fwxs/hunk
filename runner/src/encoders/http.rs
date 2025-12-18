/// HTTP-based file exfiltration encoder module.
///
/// This module provides functionality to split files into fixed-size chunks suitable for
/// HTTP-based data exfiltration during red team engagements. Each chunk is encoded with
/// base64 and hex to ensure compatibility with HTTP transmission protocols.
use std::path::PathBuf;

use crate::nodes::{file_chunk::FileChunkNode, root::RootNode, Node};

use super::{buffered_read_file, encode_b64_hex};

/// Encodes a file using base64 and hex encoding with a fixed number of chunks.
///
/// Splits the input file into the specified number of equal-sized chunks, creates a root
/// metadata node followed by file chunk nodes, and encodes each node with double encoding
/// (base64 then hex) for HTTP transmission. The final chunk is marked as the end chunk.
///
/// # Arguments
/// * `filepath` - Path to the file to be exfiltrated.
/// * `chunks` - The number of chunks to divide the file into. The file is split such that
///   each chunk contains approximately equal amounts of data.
///
/// # Returns
/// A vector of base64+hex encoded strings, one per node (including the root node).
/// Each string represents an encoded node ready for HTTP exfiltration.
///
/// # Errors
/// Returns an error if the file cannot be read or if node creation fails.
pub fn b64_encode_file(filepath: &PathBuf, chunks: usize) -> crate::error::Result<Vec<String>> {
    let root_node = RootNode::try_from(filepath)?;
    let ref_root_identifier = std::rc::Rc::clone(&root_node.file_identifier);
    let mut nodes = vec![Node::Root(root_node)];
    let file_content = buffered_read_file(filepath)?;

    nodes.extend(
        file_content
            .chunks(file_content.len().div_ceil(chunks))
            .enumerate()
            .map(|(index, chunk)| {
                Node::FileChunk(FileChunkNode::new(
                    std::rc::Rc::clone(&ref_root_identifier),
                    index + 1,
                    chunk.to_vec(),
                ))
            }),
    );

    nodes.last_mut().map(|last_node| {
        if let Node::FileChunk(chunk_node) = last_node {
            chunk_node.set_last_chunk();
        }
    });

    Ok(nodes
        .iter()
        .map(|node| encode_b64_hex(node.to_string()))
        .collect())
}
