use std::path::PathBuf;

/// Types of encryption used for the payload.
/// This enum represents the different methods of encryption
/// that can be applied to the payload data.
#[derive(Debug)]
pub enum EncryptionType {
    String,
    File,
    Url,
}

impl std::fmt::Display for EncryptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionType::String => write!(f, "s"),
            EncryptionType::File => write!(f, "f"),
            EncryptionType::Url => write!(f, "u"),
        }
    }
}

/// Metadata about the payload, such as encryption or compression.
/// This enum represents additional information about how the payload
/// is processed, which can be useful for decoders to understand the data.
#[derive(Debug)]
pub enum PayloadMetadata {
    Encrypted(EncryptionType),
    Compressed,
}

impl std::fmt::Display for PayloadMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // NOT IMPLEMENTED YET: z-{} for specifying compression type
            PayloadMetadata::Compressed => write!(f, "z"),
            PayloadMetadata::Encrypted(enc_type) => write!(f, "c-{}", enc_type.to_string()),
        }
    }
}

/// Root metadata node establishing file identity during exfiltration.
///
/// The RootNode is the first node transmitted in any file exfiltration session. It serves
/// as the metadata header that identifies the file being exfiltrated and provides a unique
/// 4-byte identifier that links all subsequent file chunk nodes together.
///
/// Without the root node, decoders would have no way to associate chunks with their original
/// file or know the source filename. This node is always transmitted or encoded first,
/// before any file chunk data.
///
/// # Design Notes
/// - The file identifier is reference-counted (`Rc`) to avoid duplication across chunks
/// - The 4-byte identifier is randomly generated, ensuring uniqueness across sessions
/// - The filename is extracted from the file path and preserved as-is for reconstruction
#[derive(Debug)]
pub struct RootNode {
    /// The original filename of the file being exfiltrated (extracted from file path).
    /// Preserved exactly as it appears in the source filesystem path.
    pub file_name: String,
    /// A unique 4-byte randomly-generated identifier shared across all chunks of this file.
    /// Reference-counted to avoid duplication when creating multiple chunk nodes.
    /// Decoders use this to group chunks that belong to the same file.
    pub file_identifier: std::rc::Rc<[u8; 4]>,

    /// Optional additional metadata about the payload, such as encryption or compression.
    /// This field can contain multiple metadata entries to describe how the payload
    /// is processed. It is optional and may be `None` if no additional metadata is provided.
    pub additional_data: Option<Vec<PayloadMetadata>>,
}

impl RootNode {
    /// Creates a new RootNode with a cryptographically random file identifier.
    ///
    /// Generates a new root node with the provided filename and a random 4-byte identifier.
    /// The identifier is generated using the system's random number generator and serves as
    /// a unique session marker for this particular file exfiltration operation.
    ///
    /// Each RootNode created with this function will have a different random identifier,
    /// making it possible to exfiltrate multiple files simultaneously without confusion.
    ///
    /// # Arguments
    /// * `file_name` - The original filename to associate with this root node.
    ///   Should be extracted from the source file path and may contain any valid characters.
    ///
    /// # Returns
    /// A new RootNode instance with a random 4-byte cryptographically secure file identifier.
    pub fn new(file_name: String) -> Self {
        Self {
            file_name,
            file_identifier: std::rc::Rc::new(urandom::new().random_bytes()),
            additional_data: None,
        }
    }

    /// Returns the protocol node type identifier for root nodes.
    ///
    /// The node type character is used as the first element in the serialized format,
    /// allowing decoders to quickly identify what type of node they're processing.
    /// All root nodes use the identifier 'r'.
    ///
    /// # Returns
    /// The character 'r', indicating this is a root node.
    pub fn node_type(&self) -> char {
        'r'
    }

    /// Sets the encryption type metadata for the payload.
    ///
    /// This method adds encryption type information to the additional data
    /// of the RootNode. It indicates how the payload is encrypted, which can be
    /// useful for decoders to understand how to handle the data.
    ///
    /// # Arguments
    /// * `enc_type` - The type of encryption used for the payload.
    ///
    /// # Example
    /// ```
    /// let mut root_node = RootNode::new("example.txt".to_string());
    /// root_node.set_encryption_type(EncryptionType::String);
    /// ```
    /// This will add the encryption type metadata to the RootNode's additional data.
    pub fn set_encryption_type(&mut self, enc_type: EncryptionType) {
        let metadata = PayloadMetadata::Encrypted(enc_type);
        match &mut self.additional_data {
            Some(data) => data.push(metadata),
            None => self.additional_data = Some(vec![metadata]),
        }
    }
}

impl TryFrom<&PathBuf> for RootNode {
    type Error = std::io::Error;

    /// Attempts to create a RootNode by extracting the filename from a file path.
    ///
    /// This is the primary constructor for working with file paths. It extracts the
    /// filename (final path component) and uses it to create a RootNode with a random
    /// file identifier. This approach is convenient when you have a file path and want
    /// to prepare it for exfiltration.
    ///
    /// The filename is extracted using the OS-native path handling, then converted to
    /// a String for storage. This preserves the original filename as the user would see it.
    ///
    /// # Arguments
    /// * `value` - A reference to a PathBuf containing the file path.
    ///
    /// # Returns
    /// `Ok(RootNode)` if a filename can be extracted, or `Err` if the path has no filename component.
    ///
    /// # Errors
    /// Returns `std::io::Error` with `InvalidInput` kind if:
    /// - The path is empty
    /// - The path points to the root directory (no filename component)
    /// - The filename cannot be extracted for any reason
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
    /// Serializes the RootNode to transmission format: `r:filename:hexidentifier`
    ///
    /// Formats the node as a colon-separated string with three components:
    /// 1. Node type character ('r' for root)
    /// 2. The original filename
    /// 3. The 4-byte file identifier encoded as hexadecimal (8 characters)
    /// 4. Optional additional metadata components.
    ///
    /// # Format Example
    /// If exfiltrating a file named "confidential.pdf" with identifier [0xAA, 0xBB, 0xCC, 0xDD]:
    /// Output: `r:confidential.pdf:aabbccdd`
    ///
    /// # Additional Metadata
    /// If additional metadata is present, it is appended as further colon-separated
    /// components after the file identifier.
    ///
    /// # Example with Metadata
    /// If the same file is encrypted as a string and compressed:
    /// Output: `r:confidential.pdf:aabbccdd:c-s|z`
    ///
    /// # Returns
    /// A formatted string representing the root node.
    ///
    /// This format is then base64+hex encoded before transmission, resulting in a
    /// transmission-ready string suitable for HTTP, DNS, or other exfiltration channels.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}{}",
            self.node_type(),
            self.file_name,
            hex::encode(*self.file_identifier),
            match &self.additional_data {
                Some(data) if !data.is_empty() => {
                    format!(
                        ":{}",
                        data.into_iter()
                            .map(|metadata| metadata.to_string())
                            .collect::<Vec<String>>()
                            .join("|")
                    )
                }
                _ => String::new(),
            }
        )
    }
}
