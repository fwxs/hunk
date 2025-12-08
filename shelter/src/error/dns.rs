//! DNS error types and conversions for the DNS transport layer.
//!
//! This module defines DNS-specific error types that occur during DNS query processing
//! and implements conversions from internal application errors into appropriate DNS
//! response codes (as per RFC 1035).
//!
//! ## DNS Response Codes
//!
//! The DNS protocol uses standard response codes in the header to indicate success
//! or failure. This module maps application errors to these codes:
//!
//! - **NOERROR (0)**: Query processed successfully, answer returned
//! - **NXDOMAIN (3)**: Non-existent domain (queried domain not under server authority)
//! - **SERVFAIL (2)**: Server failure (internal error processing the query)
//!
//! ## Error Conversion Flow
//!
//! ```
//! DNS Query (subdomain contains payload)
//!   ↓
//! handle_request() validation
//!   ↓ (OpCode/MessageType check)
//! InvalidOpCode/InvalidMessageType → SERVFAIL
//!   ↓ (Zone matching)
//! InvalidZone → NXDOMAIN
//!   ↓ (Payload decoding)
//! handle_root_zone() → Node::try_from()
//!   ↓
//! DecodeError/ParserError/ConverterError → SERVFAIL
//!   ↓
//! DNS Response with appropriate code
//! ```
//!
//! ## Error Handling Strategy
//!
//! DNS errors are categorized by their nature and mapped to appropriate response codes:
//!
//! **Client Errors (NXDOMAIN)**:
//! - Query targets a domain not under server authority
//! - This helps maintain the DNS protocol illusion (server acts authoritative)
//!
//! **Server Errors (SERVFAIL)**:
//! - Request validation failures (invalid opcode/message type)
//! - Payload decode/parse failures (malformed subdomain data)
//! - Channel failures (background processor crashed)
//! - I/O errors (network issues)
//!
//! Unlike HTTP which distinguishes 400 (client error) from 500 (server error),
//! DNS uses response codes that are less granular. Most errors map to SERVFAIL
//! to indicate the server encountered a problem processing the query.

use hickory_server::proto::{
    op::{MessageType, OpCode},
    rr::LowerName,
};

/// DNS-related errors produced by the DNS server and handler.
///
/// This enum represents all failure modes that can occur during DNS request processing,
/// from initial protocol validation through payload decoding and file assembly queuing.
///
/// ## Error Classification
///
/// - **Protocol Errors**: InvalidOpCode, InvalidMessageType
///   - The DNS request violates protocol expectations
///   - Maps to DNS SERVFAIL response
///
/// - **Authority Errors**: InvalidZone
///   - The query targets a domain not under server authority
///   - Maps to DNS NXDOMAIN response
///
/// - **Exfiltration Errors**: InternalError
///   - Payload decoding/parsing failed
///   - Background processor unavailable
///   - Maps to DNS SERVFAIL response
///
/// - **Infrastructure Errors**: Io
///   - Underlying I/O failure (socket error, etc.)
///   - Maps to DNS SERVFAIL response
pub enum DNSError {
    /// The incoming DNS `OpCode` was not a standard `Query` operation.
    ///
    /// DNS defines several operation codes (OpCode) in the message header:
    /// - Query (0): Standard query - EXPECTED
    /// - IQuery (1): Inverse query - REJECTED
    /// - Status (2): Server status request - REJECTED
    /// - Notify (4): Zone change notification - REJECTED
    /// - Update (5): Dynamic DNS update - REJECTED
    ///
    /// Only OpCode::Query is accepted. Other opcodes may indicate:
    /// - Misconfigured DNS client
    /// - DNS protocol deviation
    /// - Potential attack or scanning
    ///
    /// ## Response
    /// Maps to DNS SERVFAIL (server error) because the request is invalid
    /// but not an exfiltration zone error.
    ///
    /// Contains the observed `OpCode` for diagnostics.
    InvalidOpCode(OpCode),

    /// The DNS `MessageType` was not `Query` (request format).
    ///
    /// DNS messages can be either queries (questions from clients) or responses
    /// (answers from servers). The MessageType header field indicates which:
    /// - Query (false): Client is asking questions
    /// - Response (true): Server is providing answers
    ///
    /// Only MessageType::Query is expected. If MessageType::Response is received,
    /// it indicates either:
    /// - A DNS response being mistakenly sent to a query port
    /// - A misconfigured client sending responses instead of queries
    /// - Potential network misconfiguration
    ///
    /// ## Response
    /// Maps to DNS SERVFAIL indicating the server encountered an unexpected
    /// message format.
    ///
    /// Contains the observed `MessageType`.
    InvalidMessageType(MessageType),

    /// A query targeted a zone that this server is not authoritative for.
    ///
    /// The server is authoritative for a specific DNS zone (e.g., "exfil.internal").
    /// Queries for subdomains of this zone are processed for exfiltration.
    /// Queries for other domains should not reach this server or should be rejected.
    ///
    /// If a query targets a zone outside the configured authoritative zone:
    /// - Server is not the appropriate responder
    /// - Client may have misconfigured the DNS resolver
    /// - Query should be forwarded to the authoritative server for that zone
    ///
    /// ## Response
    /// Maps to DNS NXDOMAIN (Non-Existent Domain) to indicate that the server
    /// has no authority over the queried domain. This is the standard DNS response
    /// when a server receives a query for a domain it doesn't manage.
    ///
    /// Carries the `LowerName` of the zone that caused the error.
    InvalidZone(LowerName),

    /// An underlying I/O error occurred while processing the request or response.
    ///
    /// Network I/O errors can occur during:
    /// - Reading from the UDP socket or TCP connection
    /// - Writing response data back to the client
    /// - Binding the server socket to the configured address
    ///
    /// Common causes:
    /// - Network interface going down
    /// - Socket permissions issues
    /// - Port already in use
    /// - System resource exhaustion
    /// - OS-level network errors
    ///
    /// ## Response
    /// Maps to DNS SERVFAIL to indicate the server encountered an error
    /// and cannot process the request.
    ///
    /// Wraps the original `std::io::Error` from the system.
    Io(std::io::Error),

    /// An internal application-level error during exfiltration payload processing.
    ///
    /// This error variant wraps application-level failures that occur after
    /// initial DNS protocol validation. It covers:
    ///
    /// **Payload Decoding Errors**:
    /// - Subdomain extraction failed
    /// - Hex decoding failed (invalid hex characters in subdomain)
    /// - Base64 decoding failed (invalid base64 in hex result)
    ///
    /// **Payload Parsing Errors**:
    /// - Missing required fields in decoded payload
    /// - Invalid field values (e.g., non-hex chunk index)
    /// - Unknown node type (not 'r', 'f', or 'e')
    ///
    /// **Infrastructure Errors**:
    /// - Background processor channel closed (processor crashed)
    /// - Channel send failed
    ///
    /// ## Response
    /// Maps to DNS SERVFAIL to indicate the server encountered an error while
    /// processing the exfiltration data embedded in the query.
    ///
    /// Contains a stringified error message from the application layer for logging.
    InternalError(String),
}

/// Implements user-friendly error formatting for DNS diagnostics.
///
/// The display output is suitable for logging and includes the error variant
/// and its details. This helps operators diagnose DNS server issues.
impl std::fmt::Display for DNSError {
    /// Format the error as a human-readable string for logging.
    ///
    /// Output examples:
    /// - "Invalid DNS OpCode: Update"
    /// - "Invalid DNS Zone: attacker.com."
    /// - "Internal Error: Error decoding hex during payload reception"
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOpCode(opcode) => write!(f, "Invalid DNS OpCode: {:?}", opcode),
            Self::InvalidMessageType(msg_type) => {
                write!(f, "Invalid DNS MessageType: {:?}", msg_type)
            }
            Self::InvalidZone(zone) => write!(f, "Invalid DNS Zone: {}", zone),
            Self::Io(err) => write!(f, "I/O Error: {}", err),
            Self::InternalError(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

/// Convert standard I/O errors into DNS errors.
///
/// I/O errors at the socket level are converted to `DNSError::Io` for consistent
/// error handling. These will ultimately map to DNS SERVFAIL responses.
impl From<std::io::Error> for DNSError {
    fn from(err: std::io::Error) -> Self {
        DNSError::Io(err)
    }
}

/// Convert application-level errors into DNS errors.
///
/// Application errors from the exfiltration pipeline (decoding, parsing, conversion,
/// channel failures) are converted to `DNSError::InternalError` for consistent
/// error handling across the DNS layer. These will map to DNS SERVFAIL responses.
///
/// The application error is stringified to preserve diagnostic information
/// while keeping the DNS layer decoupled from application internals.
impl From<crate::error::app::AppError> for DNSError {
    fn from(err: crate::error::app::AppError) -> DNSError {
        DNSError::InternalError(err.to_string())
    }
}
