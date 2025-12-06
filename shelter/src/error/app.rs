#![doc = "Application-level error types and conversions used throughout the shelter crate.\n\nThis module defines structured error kinds for decoding, conversion and parsing\noperations and provides conversions from common low-level errors into the\n`AppError` enum so they can be propagated in a unified way.\n"]

/// Result alias using the crate's `AppError` as the error type.
pub type Result<T> = std::result::Result<T, AppError>;

/// Container describing a decoding error and its context.
///
/// `decode_type` identifies the decoding stage (for example \"hex\" or \"base64\") and
/// `msg` carries the underlying error message.
#[derive(Debug)]
pub struct DecodeErrorStruct {
    decode_type: String,
    msg: String,
}

impl DecodeErrorStruct {
    /// Create a new `DecodeErrorStruct` with the given type and message.
    pub fn new(decode_type: &str, msg: String) -> Self {
        Self {
            decode_type: decode_type.to_string(),
            msg,
        }
    }
}

/// Container describing a conversion error and its origin.
///
/// `from` indicates the conversion attempted (for example \"utf8\") and `msg` is the
/// underlying error message.
#[derive(Debug)]
pub struct ConverterErrorStruct {
    from: String,
    msg: String,
}

impl ConverterErrorStruct {
    /// Create a new `ConverterErrorStruct` with the originating converter name and message.
    pub fn new(from: &str, msg: String) -> Self {
        Self {
            from: from.to_string(),
            msg,
        }
    }
}

/// Container describing a parsing error and its context.
///
/// `parse_type` is a short identifier for what was being parsed (for example \"int\")
/// and `msg` carries the underlying error details.
#[derive(Debug)]
pub struct ParserErrorStruct {
    parse_type: String,
    msg: String,
}

impl ParserErrorStruct {
    /// Construct a new `ParserErrorStruct`.
    pub fn new(parse_type: &str, msg: String) -> Self {
        Self {
            parse_type: parse_type.to_string(),
            msg,
        }
    }
}

/// Unified application error enum.
///
/// This enum wraps the structured error containers above to provide a single
/// error type that can be returned from higher-level application logic.
#[derive(Debug)]
pub enum AppError {
    DecodeError(DecodeErrorStruct),
    ConverterError(ConverterErrorStruct),
    ParserError(ParserErrorStruct),
}

impl std::fmt::Display for AppError {
    /// Format a human-readable description for the error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeError(decode_err) => write!(
                f,
                "Error decoding {}. Msg: {}",
                decode_err.decode_type, decode_err.msg
            ),
            Self::ConverterError(converter_error) => write!(
                f,
                "Error converting {}. Msg: {}",
                converter_error.from, converter_error.msg
            ),
            Self::ParserError(parser_error) => write!(
                f,
                "Error parsing {}. Msg: {}",
                parser_error.parse_type, parser_error.msg
            ),
        }
    }
}

impl std::error::Error for AppError {}

/// Convert a hex decoding error into the application error type.
impl From<hex::FromHexError> for AppError {
    fn from(value: hex::FromHexError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("hex", format!("{}", value)))
    }
}

/// Convert a base64 decoding error into the application error type.
impl From<base64::DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("base64", format!("{}", value)))
    }
}

/// Convert a UTF-8 conversion error into the application error type.
impl From<std::string::FromUtf8Error> for AppError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::ConverterError(ConverterErrorStruct::new("utf8", format!("{}", value)))
    }
}

/// Convert an integer parse error into the application error type.
impl From<std::num::ParseIntError> for AppError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParserError(ParserErrorStruct::new("int", format!("{}", value)))
    }
}
