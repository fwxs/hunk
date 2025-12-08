#![doc = "Application-level error types and conversions for the shelter exfiltration toolkit.\n\nThis module defines structured error types for all decoding, conversion, parsing,\nand channel operations that occur during the exfiltration data pipeline. It provides\nunified error handling that allows errors from different stages to be propagated\nconsistently.\n\n## Error Flow\n\nErrors originate at different stages of the exfiltration pipeline:\n\n1. **Transport Layer** (HTTP/DNS): Receives raw payload strings\n2. **Decoding Stage**: Hex and Base64 decoding of payloads\n3. **Conversion Stage**: UTF-8 conversion of decoded bytes\n4. **Parsing Stage**: Colon-delimited field extraction and integer parsing\n5. **Channel Stage**: Tokio MPSC channel send failures\n\n## Error Types\n\n- **DecodeError**: Hex or Base64 decoding failures (input format invalid)\n- **ConverterError**: UTF-8 or other type conversion failures\n- **ParserError**: Malformed field structure or invalid values\n- **TokioChannelProducerError**: Channel closed or send failed\n\n## Error Handling Strategy\n\nErrors are converted at layer boundaries:\n- Transport handlers convert AppError → HTTPResponseError or DNSError\n- HTTP handler maps decode/parse errors → HTTP 400 Bad Request\n- HTTP handler maps channel errors → HTTP 500 Internal Server Error\n- DNS handler maps errors → appropriate DNS response codes (SERVFAIL, NXDOMAIN)\n\nThis allows each layer to return protocol-appropriate responses while preserving\ndetailed error information for logging and diagnostics.\n"]

/// Result alias using the crate's `AppError` as the error type.
pub type Result<T> = std::result::Result<T, AppError>;

/// Error information for decoding failures during payload processing.
///
/// Decoding errors occur when the transport layer receives a payload that cannot
/// be decoded as valid hex or base64. This typically indicates:
/// - Malformed payload from the agent
/// - Network corruption in transit
/// - Incorrect encoding parameters
///
/// ## Error Context
///
/// - `decode_type`: The decoding stage where failure occurred
///   - "hex": Hex string decoding failed (invalid hex characters)
///   - "base64": Base64 decoding failed (invalid base64 characters)
/// - `msg`: The underlying error message from the decoder library
///
/// ## HTTP Mapping
/// DecodeError → HTTP 400 Bad Request (client should reformat payload)
///
/// ## DNS Mapping
/// DecodeError → DNS SERVFAIL (server cannot process malformed query)
#[derive(Debug)]
pub struct DecodeErrorStruct {
    decode_type: String,
    msg: String,
}

impl DecodeErrorStruct {
    /// Create a new decode error with the stage identifier and error message.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// DecodeErrorStruct::new("hex", "invalid hex character 'g' at position 5".to_string())
    /// ```
    pub fn new(decode_type: &str, msg: String) -> Self {
        Self {
            decode_type: decode_type.to_string(),
            msg,
        }
    }
}

/// Error information for type conversion failures during decoding.
///
/// Conversion errors occur when successfully decoded bytes cannot be converted
/// to the expected type. In the exfiltration pipeline, this primarily occurs
/// during UTF-8 conversion after base64 decoding.
///
/// ## Error Context
///
/// - `from`: The conversion type that failed
///   - "utf8": UTF-8 decoding failed (invalid UTF-8 byte sequence)
/// - `msg`: The underlying error message from the conversion library
///
/// ## Typical Cause
///
/// After hex and base64 decoding, the resulting bytes are converted to UTF-8 text
/// for field parsing. If the decoded bytes contain invalid UTF-8 sequences, this
/// error is raised. This indicates either:
/// - Corrupt decoding (previous stages failed to catch)
/// - Agent using incorrect encoding
///
/// ## HTTP Mapping
/// ConverterError → HTTP 400 Bad Request (malformed payload)
///
/// ## DNS Mapping
/// ConverterError → DNS SERVFAIL (cannot decode payload)
#[derive(Debug)]
pub struct ConverterErrorStruct {
    from: String,
    msg: String,
}

impl ConverterErrorStruct {
    /// Create a new conversion error with the converter type and message.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// ConverterErrorStruct::new("utf8", "invalid utf-8 sequence at byte 42".to_string())
    /// ```
    pub fn new(from: &str, msg: String) -> Self {
        Self {
            from: from.to_string(),
            msg,
        }
    }
}

/// Error information for payload field parsing failures.
///
/// Parsing errors occur when the UTF-8 decoded payload cannot be parsed into
/// the expected structured format. The payload format is colon-delimited fields:
/// - Root nodes: `r:filename:file_id`
/// - File chunks: `f:root_id:chunk_index:hex_data` or `e:root_id:chunk_index:hex_data`
///
/// Parsing can fail due to:
/// - Missing required fields (malformed payload)
/// - Invalid field values (e.g., chunk_index not a valid hex number)
/// - Unknown node type identifier
///
/// ## Error Context
///
/// - `parse_type`: The parsing stage where failure occurred
///   - "payload_node": Generic node structure parsing
///   - "int": Integer parsing (e.g., invalid hex in chunk_index)
/// - `msg`: Detailed error message describing what was wrong
///
/// ## Common Causes
///
/// - Agent didn't properly format the payload before encoding
/// - Payload was truncated during transmission
/// - Unknown node type (not 'r', 'f', or 'e')
///
/// ## HTTP Mapping
/// ParserError → HTTP 400 Bad Request (client should fix payload format)
///
/// ## DNS Mapping
/// ParserError → DNS SERVFAIL (malformed subdomain query)
#[derive(Debug)]
pub struct ParserErrorStruct {
    parse_type: String,
    msg: String,
}

impl ParserErrorStruct {
    /// Create a new parsing error with the parse stage and error message.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// ParserErrorStruct::new("payload_node", "Missing fields for file chunk node".to_string())
    /// ```
    pub fn new(parse_type: &str, msg: String) -> Self {
        Self {
            parse_type: parse_type.to_string(),
            msg,
        }
    }
}

/// Error information for Tokio MPSC channel failures.
///
/// Channel errors occur when the transport handler cannot forward a parsed Node
/// to the background processing handler via the MPSC channel. This indicates
/// a critical failure in the application infrastructure.
///
/// ## Failure Causes
///
/// - **Channel Closed**: The receiver was dropped (background handler crashed)
/// - **Send Panic**: The send operation panicked (rare, indicates internal error)
///
/// ## Severity
///
/// This is a critical error indicating the server cannot process exfiltration data.
/// The background handler should be running and the channel should remain open
/// for the entire lifetime of the application.
///
/// ## Error Context
///
/// - `msg`: Error message from the Tokio channel implementation
///
/// ## HTTP Mapping
/// TokioChannelProducerError → HTTP 500 Internal Server Error
/// (server-side failure, not client's fault)
///
/// ## DNS Mapping
/// TokioChannelProducerError → DNS SERVFAIL (server cannot process request)
#[derive(Debug)]
pub struct TokioChannelProducerErrorStruct {
    /// Error message describing the channel failure (channel closed, etc.)
    msg: String,
}

impl TokioChannelProducerErrorStruct {
    /// Create a new channel error with the error message.
    ///
    /// ## Example
    ///
    /// ```ignore
    /// TokioChannelProducerErrorStruct::new("receiver dropped".to_string())
    /// ```
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// Unified error type for all application-level failures in the exfiltration pipeline.
///
/// This enum consolidates errors from all stages of payload processing into a
/// single type that can be propagated and converted at layer boundaries.
///
/// ## Error Pipeline
///
/// The exfiltration data pipeline encounters errors at these stages:
///
/// 1. **Decoding** (hex/base64): DecodeError
///    - Payload doesn't match expected encoding
///    - Invalid hex characters or base64 padding
/// 2. **Conversion** (UTF-8): ConverterError
///    - Decoded bytes aren't valid UTF-8
/// 3. **Parsing** (colon-delimited fields): ParserError
///    - Missing required fields
///    - Invalid field values (e.g., non-hex chunk index)
///    - Unknown node type
/// 4. **Channel** (MPSC send): TokioChannelProducerError
///    - Background handler has crashed or channel is closed
///    - Critical infrastructure failure
///
/// ## Error Handling
///
/// Errors are converted at transport boundaries:
/// - HTTP handlers: AppError → HTTPResponseError → HTTP response codes
/// - DNS handlers: AppError → DNSError → DNS response codes
/// - All errors are logged before conversion for diagnostics
#[derive(Debug)]
pub enum AppError {
    /// Hex or Base64 decoding failed during payload reception
    DecodeError(DecodeErrorStruct),
    /// Type conversion (UTF-8) failed after decoding
    ConverterError(ConverterErrorStruct),
    /// Payload field parsing failed (missing fields, invalid values)
    ParserError(ParserErrorStruct),
    /// MPSC channel send failed (background handler crashed or closed)
    TokioChannelProducerError(TokioChannelProducerErrorStruct),
}

impl std::fmt::Display for AppError {
    /// Format a human-readable error description suitable for logging.
    ///
    /// The output includes the error category and underlying message to help
    /// diagnose where in the pipeline the failure occurred.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeError(decode_err) => write!(
                f,
                "Error decoding {} during payload reception. Msg: {}",
                decode_err.decode_type, decode_err.msg
            ),
            Self::ConverterError(converter_error) => write!(
                f,
                "Error converting {} during decoding. Msg: {}",
                converter_error.from, converter_error.msg
            ),
            Self::ParserError(parser_error) => write!(
                f,
                "Error parsing {} from payload. Msg: {}",
                parser_error.parse_type, parser_error.msg
            ),
            Self::TokioChannelProducerError(tokio_error) => {
                write!(
                    f,
                    "Background processor channel error. Msg: {}",
                    tokio_error.msg
                )
            }
        }
    }
}

impl std::error::Error for AppError {}

/// Conversion from hex decoding errors to the unified AppError type.
///
/// Hex decoding is the first stage of payload processing. Invalid hex characters
/// in the incoming payload result in this error.
impl From<hex::FromHexError> for AppError {
    fn from(value: hex::FromHexError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("hex", format!("{}", value)))
    }
}

/// Conversion from base64 decoding errors to the unified AppError type.
///
/// Base64 decoding is the second stage of payload processing, following hex decoding.
/// Invalid base64 characters or incorrect padding result in this error.
impl From<base64::DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("base64", format!("{}", value)))
    }
}

/// Conversion from UTF-8 conversion errors to the unified AppError type.
///
/// UTF-8 conversion is the third stage of payload processing. After hex and base64
/// decoding, the resulting bytes are interpreted as UTF-8 text for field parsing.
/// Invalid UTF-8 sequences result in this error.
impl From<std::string::FromUtf8Error> for AppError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::ConverterError(ConverterErrorStruct::new("utf8", format!("{}", value)))
    }
}

/// Conversion from integer parsing errors to the unified AppError type.
///
/// Integer parsing occurs during field extraction, particularly when parsing the
/// chunk index as a hexadecimal number. Invalid hex digits in the chunk_index
/// field result in this error.
impl From<std::num::ParseIntError> for AppError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParserError(ParserErrorStruct::new("int", format!("{}", value)))
    }
}

/// Conversion from Tokio MPSC channel send errors to the unified AppError type.
///
/// Channel failures indicate that the background processor is not running or has
/// crashed. This is a critical failure that prevents file assembly and persistence.
/// The error is logged immediately for diagnostics.
impl From<tokio::sync::mpsc::error::SendError<crate::Node>> for AppError {
    fn from(value: tokio::sync::mpsc::error::SendError<crate::Node>) -> Self {
        log::error!("Failed to send data to processing queue: {}", value);
        Self::TokioChannelProducerError(TokioChannelProducerErrorStruct::new(format!("{}", value)))
    }
}
