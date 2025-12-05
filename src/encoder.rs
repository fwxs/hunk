use core::str;
use std::path::PathBuf;

use base64::Engine;

const DOMAIN_NAME_MAX_LENGTH: usize = 255;
const DOMAIN_LABEL_MAX_LENGTH: usize = 63;

fn compute_chunk_size_base64_encoding_ratio(chunk_size: f32) -> f32 {
    // https://crypto.stackexchange.com/questions/83952/how-do-i-calculate-base64-conversion-rate
    let base64_chacacters = 4.0 * (chunk_size as f32 / 3.0);
    let padding = 2.0 - ((chunk_size + 2.0) % 3.0);

    return base64_chacacters + padding;
}

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

fn b64_encode(byte_stream: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD.encode(byte_stream)
}

fn b64_hex_encode_bytes(byte_stream: &[u8]) -> String {
    hex::encode(b64_encode(byte_stream))
}

fn b64_hex_encode_string(string: String) -> String {
    hex::encode(b64_encode(string.as_bytes()))
}

fn b64_encode_segmented_payload(splitted_payload: Vec<String>) -> Vec<String> {
    splitted_payload
        .iter()
        .map(|chunk| b64_hex_encode_bytes(chunk.as_bytes()))
        .collect()
}

fn split_file_content(filename: &str, file_content: String, chunk_size: usize) -> Vec<String> {
    let mut chunks = file_content
        .bytes()
        .collect::<Vec<_>>()
        .chunks(chunk_size)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .enumerate()
        .map(|(index, chunk)| format!("{}:{}:{}", filename, index, chunk))
        .collect::<Vec<String>>();

    chunks.last_mut().unwrap().push_str(":end");
    return chunks;
}

pub fn dns_safe_b64_encode_payload(filepath: &PathBuf, domain_name: &str) -> Vec<String> {
    let payload = std::fs::read_to_string(filepath).unwrap();
    let max_chunk_size =
        compute_optimal_hex_base64_chunk_size(payload.len(), domain_name.len(), None);
    let mut payload_iterable = payload.bytes().into_iter();
    let mut index: usize = 0;
    let mut chunks: Vec<String> = Vec::new();
    let file_name = &filepath.file_name().unwrap().to_string_lossy();
    let mut is_last_chunk = false;

    loop {
        let mut buffer = format!("{}:{}:", file_name, index);
        let file_chunk = b64_hex_encode_bytes(
            payload_iterable
                .by_ref()
                .take(max_chunk_size - buffer.len())
                .collect::<Vec<u8>>()
                .as_slice(),
        );

        if file_chunk.is_empty() {
            buffer.push_str(":end");
            is_last_chunk = true;
        }

        buffer.push_str(file_chunk.as_str());
        let encoded_buffer = b64_hex_encode_string(buffer);
        let buffer_chunk_size = encoded_buffer.len() % max_chunk_size;

        chunks.push(
            encoded_buffer
                .bytes()
                .collect::<Vec<_>>()
                .chunks(buffer_chunk_size)
                .filter_map(|chunk| std::str::from_utf8(chunk).ok())
                .collect::<Vec<&str>>()
                .join("."),
        );

        if is_last_chunk {
            break;
        }

        index += 1
    }

    return chunks;
}

pub fn b64_encode_file(filepath: &PathBuf, chunks: usize) -> Vec<String> {
    let encoded_file_content = b64_hex_encode_string(std::fs::read_to_string(filepath).unwrap());
    let chunk_size = encoded_file_content.len().div_ceil(chunks);

    b64_encode_segmented_payload(split_file_content(
        &filepath.file_name().unwrap().to_string_lossy(),
        encoded_file_content,
        chunk_size,
    ))
}
