//! HTTP error types and conversions used by Actix handlers.
//!
//! This module defines the HTTP-facing error type returned by request handlers
//! and implements conversions from internal application errors and channel send
//! failures into appropriate HTTP response codes and messages.

#[derive(Debug)]
/// Error variants returned by Actix web handlers in this crate.
///
/// - `InternalError`: Unexpected internal failure (mapped to 500).
/// - `BadRequest`: Errors caused by malformed client input (mapped to 400).
pub enum HTTPResponseError {
    InternalError,
    BadRequest,
}

impl std::fmt::Display for HTTPResponseError {
    /// Produce a short human-readable message for the HTTP response body.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "Internal server error."),
            Self::BadRequest => write!(f, "Error parsing data."),
        }
    }
}

impl actix_web::error::ResponseError for HTTPResponseError {
    /// Map the error variant to an HTTP status code.
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::InternalError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }

    /// Build a plain-text HTTP response containing the error message.
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .content_type(actix_web::http::header::ContentType::plaintext())
            .body(self.to_string())
    }
}

impl From<super::app::AppError> for HTTPResponseError {
    /// Convert an internal `AppError` into an HTTP-friendly error variant.
    ///
    /// Application-level decode/parse/convert errors are treated as client
    /// errors (`BadRequest`) and logged for diagnostics. This allows the HTTP
    /// layer to return a meaningful status code while preserving internal logs.
    fn from(value: super::app::AppError) -> Self {
        log::error!("Application error: {}", value.to_string());

        match value {
            super::app::AppError::ParserError(_) => Self::BadRequest,
            super::app::AppError::ConverterError(_) => Self::BadRequest,
            super::app::AppError::DecodeError(_) => Self::BadRequest,
        }
    }
}

impl From<tokio::sync::mpsc::error::SendError<crate::ExfiltratedFilePortion>>
    for HTTPResponseError
{
    /// Convert channel send failures into an internal server error.
    ///
    /// If the handler cannot forward a parsed file portion to the background
    /// processing queue, this is treated as an internal failure (500) and
    /// the condition is logged.
    fn from(value: tokio::sync::mpsc::error::SendError<crate::ExfiltratedFilePortion>) -> Self {
        log::error!("Failed to send data to processing queue: {}", value);
        Self::InternalError
    }
}
