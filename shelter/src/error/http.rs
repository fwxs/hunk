#[derive(Debug)]
pub enum HTTPResponseError {
    InternalError,
    BadRequest,
}

impl std::fmt::Display for HTTPResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "Internal server error."),
            Self::BadRequest => write!(f, "Error parsing data."),
        }
    }
}

impl actix_web::error::ResponseError for HTTPResponseError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::InternalError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .content_type(actix_web::http::header::ContentType::plaintext())
            .body(self.to_string())
    }
}

impl From<super::app::AppError> for HTTPResponseError {
    fn from(value: super::app::AppError) -> Self {
        log::error!("{}", value.to_string());

        match value {
            super::app::AppError::ParserError(_) => Self::BadRequest,
            super::app::AppError::ConverterError(_) => Self::BadRequest,
            super::app::AppError::DecodeError(_) => Self::BadRequest,
            _ => Self::InternalError,
        }
    }
}
