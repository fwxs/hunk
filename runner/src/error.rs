pub type Result<T> = std::result::Result<T, RunnerError>;

/// Struct to represent IO errors.
#[derive(Debug)]
pub struct IoErrorStruct {
    /// The type of IO error.
    error_type: String,

    /// The error message.
    msg: String,
}

/// Struct to represent validation errors.
#[derive(Debug)]
pub struct ValidationErrorStruct {
    /// The error message.
    msg: String,
}

/// Struct to represent request errors.
#[derive(Debug)]
pub struct RequestErrorStruct {
    /// The error message.
    msg: String,
}

/// Struct to represent DNS errors.
#[derive(Debug)]
pub struct DNSErrorStruct {
    /// The error message.
    msg: String,
}

/// Enum to represent different types of runner errors.
#[derive(Debug)]
pub enum RunnerError {
    IoError(IoErrorStruct),
    ValidationError(ValidationErrorStruct),
    RequestError(RequestErrorStruct),
    DNSError(DNSErrorStruct),
}

impl RunnerError {
    /// Create a new validation error.
    ///
    /// # Arguments
    /// * `msg` - The error message.
    ///
    /// # Returns
    /// A `RunnerError` instance representing a validation error.
    pub fn validation_error(msg: &str) -> Self {
        RunnerError::ValidationError(ValidationErrorStruct {
            msg: msg.to_string(),
        })
    }
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::IoError(io_err) => {
                write!(f, "IO {} Error: {}", io_err.error_type, io_err.msg)
            }
            RunnerError::ValidationError(validation_err) => {
                write!(f, "Validation Error: {}", validation_err.msg)
            }
            RunnerError::RequestError(request_err) => {
                write!(f, "Request Error: {}", request_err.msg)
            }
            RunnerError::DNSError(dns_err) => {
                write!(f, "DNS Error: {}", dns_err.msg)
            }
        }
    }
}

impl From<std::io::Error> for RunnerError {
    fn from(error: std::io::Error) -> Self {
        RunnerError::IoError(IoErrorStruct {
            error_type: error.kind().to_string(),
            msg: error.to_string(),
        })
    }
}

impl From<reqwest::Error> for RunnerError {
    fn from(error: reqwest::Error) -> Self {
        RunnerError::RequestError(RequestErrorStruct {
            msg: error.to_string(),
        })
    }
}

impl From<hickory_resolver::ResolveError> for RunnerError {
    fn from(error: hickory_resolver::ResolveError) -> Self {
        RunnerError::DNSError(DNSErrorStruct {
            msg: error.to_string(),
        })
    }
}
