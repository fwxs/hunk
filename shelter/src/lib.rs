#![doc = "Core types and helpers used by the `shelter` crate.\n\nThis module exposes the public command, error and event handler modules and\nprovides the typed representations for exfiltrated file portions and\nreconstructed files. It also contains the parsing logic that converts raw\npayload strings into structured `Node` instances.\n\n# Payload Structure\n\nExfiltrated data is encoded as a colon-delimited payload with the following format:\n- **Root Node**: `r:filename:file_id` - Metadata describing the file being exfiltrated\n- **File Chunk**: `f:root_id:chunk_index:hex_encoded_data` - A portion of the file\n- **End Marker**: `e:root_id:chunk_index:hex_encoded_data` - Final chunk marking end of transmission\n\nThe complete payload is then hex-encoded and base64-encoded for transport.\n\n# Data Handling\n\n1. **Reception**: Payloads arrive via HTTP POST or DNS subdomain queries\n2. **Decoding**: Base64 decode → Hex decode → UTF-8 conversion\n3. **Parsing**: Colon-delimited fields parsed into `RootNode` or `FileChunkNode` types\n4. **Queuing**: Parsed nodes forwarded to async processing channel\n5. **Assembly**: Background handler collects chunks by root_id, reassembles file data from hex\n6. **Persistence**: Complete files written to configured loot directory\n"]

/// Commands, used to expose CLI server subcommands.
pub mod commands;
/// Error definitions and conversions for application and HTTP layers.
pub mod error;
/// Event handler that consumes the processing queue and writes loot to disk.
pub mod event_handler;
/// Node types representing exfiltrated file metadata and data chunks.
pub mod nodes;
