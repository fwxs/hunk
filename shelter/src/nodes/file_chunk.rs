use crate::error::app::ParserErrorStruct;

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
