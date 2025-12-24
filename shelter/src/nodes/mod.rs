use crate::error::app::ParserErrorStruct;
use base64::Engine;

pub mod file_chunk;
pub mod root;

pub type ThreadSafeFileChunkNode = std::sync::Arc<file_chunk::FileChunkNode>;

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
    Root(root::RootNode),
    /// A file chunk data node containing portion of the file (node_type='f' or 'e').
    /// Payload format: `f:root_id:chunk_index:hex_encoded_data`
    /// The 'e' variant marks the final chunk and triggers file assembly.
    FileChunk(file_chunk::FileChunkNode),
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
                "r" => Ok(Self::Root(root::RootNode::try_from(decoded_payload)?)),
                "f" => Ok(Self::FileChunk(file_chunk::FileChunkNode::try_from(
                    decoded_payload,
                )?)),
                "e" => Ok(Self::FileChunk(
                    file_chunk::FileChunkNode::try_from(decoded_payload)?.mark_as_end(),
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
