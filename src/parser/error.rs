use std::fmt;

#[derive(Debug)]
pub enum ParseError {
    BufferUnderflow {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    UnconsumedBytes {
        remaining: usize,
    },
    InvalidData {
        message: String,
        context: Option<String>,
    },
    // Wrapper for anyhow errors during migration
    Anyhow(anyhow::Error),
}

impl ParseError {
    pub fn with_context<S: Into<String>>(self, context: S) -> Self {
        match self {
            ParseError::InvalidData { message, context: existing_context } => {
                let new_context = if let Some(existing) = existing_context {
                    format!("{}: {}", context.into(), existing)
                } else {
                    context.into()
                };
                ParseError::InvalidData {
                    message,
                    context: Some(new_context),
                }
            }
            ParseError::Anyhow(err) => {
                ParseError::Anyhow(err.context(context.into()))
            }
            other => ParseError::InvalidData {
                message: other.to_string(),
                context: Some(context.into()),
            }
        }
    }

    pub fn invalid_data<S: Into<String>>(message: S) -> Self {
        ParseError::InvalidData {
            message: message.into(),
            context: None,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BufferUnderflow { offset, needed, remaining } => {
                write!(f, "Buffer underflow at offset {}, needed {} bytes, only {} remaining", offset, needed, remaining)
            }
            ParseError::UnconsumedBytes { remaining } => {
                write!(f, "Buffer has {} bytes left", remaining)
            }
            ParseError::InvalidData { message, context } => {
                if let Some(ctx) = context {
                    write!(f, "{}: {}", ctx, message)
                } else {
                    write!(f, "{}", message)
                }
            }
            ParseError::Anyhow(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<anyhow::Error> for ParseError {
    fn from(err: anyhow::Error) -> Self {
        ParseError::Anyhow(err)
    }
}

// No need for explicit From implementation - anyhow already provides one
// via its blanket impl for types that implement std::error::Error

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> Self {
        ParseError::invalid_data(err.to_string())
    }
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(err: std::str::Utf8Error) -> Self {
        ParseError::invalid_data(format!("UTF-8 decode error: {}", err))
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParseError::invalid_data(format!("UTF-8 decode error: {}", err))
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub trait ResultExt<T> {
    fn with_context<S: Into<String>>(self, context: S) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn with_context<S: Into<String>>(self, context: S) -> Result<T> {
        self.map_err(|e| e.with_context(context))
    }
}

impl<T> ResultExt<T> for anyhow::Result<T> {
    fn with_context<S: Into<String>>(self, context: S) -> Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(ParseError::Anyhow(err.context(context.into()))),
        }
    }
}