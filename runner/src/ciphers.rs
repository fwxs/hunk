use chacha20poly1305::aead::{Aead, KeyInit};

/// Encrypts the given plaintext using ChaCha20-Poly1305 with the provided key and nonce.
/// # Arguments
/// * `key_slice` - A bytes slice representing the encryption key (must be 32 bytes).
/// * `nonce_slice` - A byte array slice representing the nonce (must be 12 bytes).
/// * `plaintext` - A vector of bytes representing the plaintext to be encrypted.
///
/// # Returns
/// * A Result containing the encrypted ciphertext as a vector of bytes, or an error if encryption fails.
///
/// # Errors
/// * Returns an error if either key or nonce length are invalid or if encryption fails.
pub fn chacha20_encrypt(
    key_slice: Vec<u8>,
    nonce_slice: &[u8],
    plaintext: Vec<u8>,
) -> crate::error::Result<Vec<u8>> {
    let key = match std::panic::catch_unwind(|| chacha20poly1305::Key::from_slice(&key_slice)) {
        Ok(key) => key,
        Err(_) => {
            return Err(crate::error::RunnerError::chacha20_error(
                "Invalid key length for ChaCha20-Poly1305. Key must be 32 bytes.",
            ))
        }
    };
    let nonce = match std::panic::catch_unwind(|| chacha20poly1305::Nonce::from_slice(nonce_slice))
    {
        Ok(nonce) => nonce,
        Err(_) => {
            return Err(crate::error::RunnerError::chacha20_error(
                "Invalid nonce length for ChaCha20-Poly1305. Nonce must be 12 bytes.",
            ))
        }
    };
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

    Ok(cipher.encrypt(nonce, plaintext.as_ref())?)
}
