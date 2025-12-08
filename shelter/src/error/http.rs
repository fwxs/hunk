//! HTTP error types and conversions for the Actix web transport layer.
//!
//! This module defines the HTTP-facing error type and implements conversions from
//! internal application errors into appropriate HTTP status codes and responses.
//!
//! ## Error Conversion Strategy
//!
//! The HTTP transport layer sits at the boundary between the network and application.
//! Errors originating from the application layer (decoding, parsing, channel failures)
//! must be converted to appropriate HTTP responses:
//!
//! - **Payload Errors** (decode/parse/convert): HTTP 400 Bad Request
//!   These indicate the client sent malformed data and should reformat the request.
//!
//! - **Infrastructure Errors** (channel closed): HTTP 500 Internal Server Error
//!   These indicate a server-side failure beyond the client's control.
//!
//! ## Error Flow
//!
//! ```
//! POST /
//!   ↓
//! post_handler(req_body, tx)
//!   ↓
//! Node::try_from(req_body)  ← May raise AppError
//!   ↓
//! tx.send(node)             ← May raise SendError
//!   ↓
//! HTTPResponseError          ← Converted via From<AppError> or From<SendError>
//!   ↓
//! HTTP Response (200/400/500)
//! ```
//!
//! ## Response Details
//!
//! - **200 OK**: Payload successfully decoded, parsed, and queued for processing
//! - **400 Bad Request**: Decoding, conversion, or parsing failed. Client should fix payload.
//! - **500 Internal Server Error**: Channel closed or send failed. Server infrastructure issue.
//!
//! All errors are logged at the application layer before conversion to HTTP responses.

#[derive(Debug)]
/// HTTP error response variants for the exfiltration server.
///
/// These variants represent the two broad categories of failures that can occur
/// during request handling and are mapped to appropriate HTTP status codes:
///
/// - `BadRequest`: Payload errors (decode/parse/convert failures)
///   - Mapped to HTTP 400 Bad Request
///   - Indicates client should reformat the payload
///   - Response: "Error parsing data."
///
/// - `InternalError`: Server infrastructure errors (channel closed/send failed)
///   - Mapped to HTTP 500 Internal Server Error
///   - Indicates server cannot process requests
///   - Response: "Internal server error."
pub enum HTTPResponseError {
    /// Internal server error - infrastructure failure (HTTP 500)
    InternalError,
    /// Bad request - malformed client payload (HTTP 400)
    BadRequest,
}

impl std::fmt::Display for HTTPResponseError {
    /// Produce a human-readable message for the HTTP response body.
    ///
    /// These messages are intentionally vague to avoid leaking information about
    /// the server's internal error handling. More detailed error information is
    /// logged at the application layer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "Internal server error."),
            Self::BadRequest => write!(f, "Error parsing data."),
        }
    }
}

impl actix_web::error::ResponseError for HTTPResponseError {
    /// Map the error variant to an HTTP status code.
    ///
    /// ## Status Code Mapping
    ///
    /// - `BadRequest` → 400 (client error, recoverable)
    /// - `InternalError` → 500 (server error, infrastructure issue)
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::InternalError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }

    /// Build a plain-text HTTP response containing the error message.
    ///
    /// The response body contains a short, generic message suitable for
    /// transmission over the network. Detailed error information is logged
    /// separately for server-side diagnostics.
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .content_type(actix_web::http::header::ContentType::plaintext())
            .body(self.to_string())
    }
}

impl From<super::app::AppError> for HTTPResponseError {
    /// Convert an internal `AppError` into an HTTP-friendly error variant.
    ///
    /// This conversion maps application-level errors to appropriate HTTP status codes:
    ///
    /// ## Conversion Rules
    ///
    /// **Payload Errors → HTTP 400 Bad Request**:
    /// - `DecodeError`: Hex or Base64 decoding failed
    ///   - Indicates malformed payload from client
    ///   - Client should reformat the request
    /// - `ConverterError`: UTF-8 conversion failed
    ///   - Indicates decoded data isn't valid UTF-8
    ///   - Client should verify encoding parameters
    /// - `ParserError`: Field parsing failed
    ///   - Indicates payload structure is invalid (missing fields, wrong format)
    ///   - Client should check payload format against specification
    ///
    /// **Infrastructure Errors → HTTP 500 Internal Server Error**:
    /// - `TokioChannelProducerError`: Channel send failed
    ///   - Indicates background processor has crashed or channel is closed
    ///   - Client should retry later; server needs restart
    ///
    /// All errors are logged with full details before conversion.
    fn from(value: super::app::AppError) -> Self {
        log::error!("Application error: {}", value.to_string());

        match value {
            super::app::AppError::ParserError(_) => Self::BadRequest,
            super::app::AppError::ConverterError(_) => Self::BadRequest,
            super::app::AppError::DecodeError(_) => Self::BadRequest,
            crate::error::app::AppError::TokioChannelProducerError(_) => Self::InternalError,
        }
    }
}

impl From<tokio::sync::mpsc::error::SendError<crate::Node>> for HTTPResponseError {
    /// Convert Tokio MPSC channel send failures into HTTP 500.
    ///
    /// Channel send errors indicate that the background processor task is no longer
    /// running or the channel has been closed. This is a critical infrastructure
    /// failure that prevents file assembly and persistence.
    ///
    /// ## Failure Modes
    ///
    /// 1. **Receiver Dropped**: Background event_handler task has crashed or exited
    ///    - No files can be assembled or written to disk
    ///    - Server should be restarted
    ///
    /// 2. **Channel Full**: All 10 buffer slots are occupied
    ///    - Temporary condition that should resolve as processor catches up
    ///    - Awaiting in the send causes backpressure (handler blocks)
    ///
    /// If send fails after await, the channel must be permanently broken (receiver dropped).
    ///
    /// ## Response
    ///
    /// HTTP 500 Internal Server Error is returned to indicate this is not the client's
    /// fault. The server should be restarted to recover. The error is logged for
    /// diagnostic purposes.
    fn from(value: tokio::sync::mpsc::error::SendError<crate::Node>) -> Self {
        log::error!("Failed to send data to processing queue: {}", value);
        Self::InternalError
    }
}
