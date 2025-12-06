pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub struct DecodeErrorStruct {
    decode_type: String,
    msg: String,
}

impl DecodeErrorStruct {
    pub fn new(decode_type: &str, msg: String) -> Self {
        Self {
            decode_type: decode_type.to_string(),
            msg,
        }
    }
}

#[derive(Debug)]
pub struct ConverterErrorStruct {
    from: String,
    msg: String,
}

impl ConverterErrorStruct {
    pub fn new(from: &str, msg: String) -> Self {
        Self {
            from: from.to_string(),
            msg,
        }
    }
}

#[derive(Debug)]
pub struct ParserErrorStruct {
    parse_type: String,
    msg: String,
}

impl ParserErrorStruct {
    pub fn new(parse_type: &str, msg: String) -> Self {
        Self {
            parse_type: parse_type.to_string(),
            msg,
        }
    }
}

#[derive(Debug)]
pub enum AppError {
    DecodeError(DecodeErrorStruct),
    ConverterError(ConverterErrorStruct),
    ParserError(ParserErrorStruct),
}

impl std::fmt::Display for AppError {
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

impl From<hex::FromHexError> for AppError {
    fn from(value: hex::FromHexError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("hex", format!("{}", value)))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        Self::DecodeError(DecodeErrorStruct::new("base64", format!("{}", value)))
    }
}

impl From<std::string::FromUtf8Error> for AppError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::ConverterError(ConverterErrorStruct::new("utf8", format!("{}", value)))
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParserError(ParserErrorStruct::new("int", format!("{}", value)))
    }
}
