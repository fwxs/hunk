use std::borrow::Borrow;

use crate::error::app::ParserErrorStruct;

type RootFileIdentifier = String;

/// Types of encryption used for the payload.
/// This enum represents the different methods of encryption
/// that can be applied to the payload data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EncryptionType {
    String,
    File,
    Url,
}

impl TryFrom<&str> for EncryptionType {
    type Error = crate::error::app::AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "s" => Ok(EncryptionType::String),
            "f" => Ok(EncryptionType::File),
            "u" => Ok(EncryptionType::Url),
            _ => Err(crate::error::app::AppError::ParserError(
                ParserErrorStruct::new(
                    "encryption_type",
                    format!("Unknown encryption type: {}", value),
                ),
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PayloadMetadata {
    Encrypted(EncryptionType),
}

impl TryFrom<String> for PayloadMetadata {
    type Error = crate::error::app::AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut splitted_value = value.split('-').into_iter();
        if let (Some(metadata_type), Some(metadata_value)) =
            (splitted_value.next(), splitted_value.next())
        {
            match metadata_type {
                "c" => Ok(PayloadMetadata::Encrypted(EncryptionType::try_from(
                    metadata_value,
                )?)),
                _ => {
                    let msg = format!("Unknown metadata type: {}", metadata_type);
                    log::error!("{}", msg);
                    Err(crate::error::app::AppError::ParserError(
                        ParserErrorStruct::new("payload_metadata", msg),
                    ))
                }
            }
        } else {
            let msg = format!("Invalid metadata format: {}", value);
            log::error!("{}", msg);
            Err(crate::error::app::AppError::ParserError(
                ParserErrorStruct::new("payload_metadata", msg),
            ))
        }
    }
}

#[derive(Debug, Default, Eq, Clone)]
pub struct RootNode {
    /// The original filename of the file being exfiltrated.
    /// Sent as the first field in the root node payload: `r:filename:file_id`
    pub file_name: String,
    /// A unique identifier of this file used to correlate chunks.
    /// Sent as the second field in the root node payload.
    pub file_identifier: RootFileIdentifier,
    /// Additional metadata about the payload, such as encryption type.
    pub additional_metadata: Option<Vec<PayloadMetadata>>,
}

impl TryFrom<std::str::Split<'_, char>> for RootNode {
    type Error = crate::error::app::AppError;

    fn try_from(mut value: std::str::Split<'_, char>) -> Result<Self, Self::Error> {
        let file_name = value.next();
        let file_identifier = value.next();
        let additional_metadata = value.next();
        if let (Some(file_name), Some(file_identifier)) = (file_name, file_identifier) {
            Ok(RootNode {
                file_name: file_name.to_string(),
                file_identifier: file_identifier.to_string(),
                additional_metadata: if let Some(meta) = additional_metadata {
                    Some(
                        meta.split('|')
                            .filter_map(|m| PayloadMetadata::try_from(m.to_string()).ok())
                            .collect::<Vec<PayloadMetadata>>(),
                    )
                } else {
                    None
                },
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
