//! Node definitions for hierarchical file exfiltration structure.
//!
//! This module defines the core data structures used to represent files during exfiltration.
//! A file is decomposed into a hierarchical tree structure:
//!
//! - **Root Node**: Contains metadata about the file (filename, unique 4-byte identifier)
//! - **File Chunk Nodes**: Contain sequential portions of the file data
//!
//! Each node is serializable to a string format suitable for encoding and transmission across
//! various exfiltration channels (HTTP, DNS, etc.). The structure supports reconstruction of
//! the original file by reassembling chunks in sequence using their shared file identifier.

pub mod file_chunk;
pub mod root;

/// Represents a single node in the file exfiltration hierarchy.
///
/// A node is either a root metadata node or a file data chunk node. The enum allows
/// heterogeneous collections of both node types, which can be processed uniformly
/// through the Display trait to generate transmission-ready strings.
///
/// The two-node system separates metadata (what file is being exfiltrated) from data
/// (the actual file contents split across chunks). This separation allows decoders to
/// reconstruct files properly even if chunks arrive out of order or with gaps.
#[derive(Debug)]
pub enum Node {
    /// Root metadata node containing the filename and unique file identifier.
    /// Transmitted first to establish which file subsequent chunks belong to.
    Root(root::RootNode),
    /// File chunk node containing a portion of the file data and its metadata.
    /// Multiple chunk nodes are generated per file, numbered sequentially.
    FileChunk(file_chunk::FileChunkNode),
}

impl Node {
    /// Returns the node type character for protocol identification.
    ///
    /// Each node type has a single-character identifier used in the serialized format:
    /// - 'r' for root nodes (metadata)
    /// - 'f' for regular file chunk nodes
    /// - 'e' for end-of-file chunk nodes
    ///
    /// This character is always the first element when a node is serialized, making it
    /// easy for decoders to quickly identify node types during parsing.
    ///
    /// # Returns
    /// The character representing this node's type: 'r', 'f', or 'e'.
    pub fn node_type(&self) -> char {
        match self {
            Self::Root(root) => root.node_type(),
            Self::FileChunk(file_chunk) => file_chunk.node_type(),
        }
    }
}

impl std::fmt::Display for Node {
    /// Serializes the node to its transmission format.
    ///
    /// Delegates formatting to the appropriate variant's Display implementation,
    /// producing a colon-separated string suitable for encoding and transmission.
    /// The format is protocol-agnostic and can be transmitted over HTTP, DNS, or other channels.
    ///
    /// # Output Format
    /// - Root: `r:filename:hexid`
    /// - FileChunk: `f/e:rootid:index:hexdata`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Root(root) => std::fmt::Display::fmt(root, f),
            Node::FileChunk(file_chunk) => std::fmt::Display::fmt(file_chunk, f),
        }
    }
}
