use std::fmt;

#[derive(Debug, Clone)]
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
        kind: InvalidDataKind,
        context: Option<String>,
    },
    // Wrapper for anyhow errors during migration (clone by converting to string)
    Anyhow(String),
}

#[derive(Debug, Clone)]
pub enum InvalidDataKind {
    LengthInvalid {
        expected: usize,
        actual: usize,
    },
    InvalidBooleanValue {
        value: u8,
    },
    InvalidEnumValue {
        enum_name: &'static str,
        value: u8,
    },
    InvalidBitPattern {
        description: &'static str,
        value: u8,
    },
    InvalidOptionalDiscriminant {
        value: u8,
    },
    InvalidCompactSize {
        prefix: u8,
        value: u64,
        minimum: u64,
    },
    InvalidKeySize {
        key_type: &'static str,
        expected: Vec<usize>,
        actual: usize,
    },
    Utf8Error {
        error: std::string::FromUtf8Error,
    },
    Other {
        message: String,
    },
}

impl ParseError {
    pub fn with_context<S: Into<String>>(self, context: S) -> Self {
        match self {
            ParseError::InvalidData { kind, context: existing_context } => {
                let new_context = if let Some(existing) = existing_context {
                    format!("{}: {}", context.into(), existing)
                } else {
                    context.into()
                };
                ParseError::InvalidData {
                    kind,
                    context: Some(new_context),
                }
            }
            ParseError::Anyhow(err) => {
                ParseError::Anyhow(format!("{}: {}", context.into(), err))
            }
            other => ParseError::InvalidData {
                kind: InvalidDataKind::Other {
                    message: other.to_string(),
                },
                context: Some(context.into()),
            }
        }
    }

    pub fn invalid_data<S: Into<String>>(message: S) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: message.into(),
            },
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
            ParseError::InvalidData { kind, context } => {
                if let Some(ctx) = context {
                    write!(f, "{}: {}", ctx, kind)
                } else {
                    write!(f, "{}", kind)
                }
            }
            ParseError::Anyhow(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl fmt::Display for InvalidDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidDataKind::LengthInvalid { expected, actual } => {
                write!(f, "Invalid data length: expected {}, got {}", expected, actual)
            }
            InvalidDataKind::InvalidBooleanValue { value } => {
                write!(f, "Invalid boolean value: {}", value)
            }
            InvalidDataKind::InvalidEnumValue { enum_name, value } => {
                write!(f, "Invalid {} value: 0x{:02x}", enum_name, value)
            }
            InvalidDataKind::InvalidBitPattern { description, value } => {
                write!(f, "Invalid bit pattern for {}: 0x{:02x}", description, value)
            }
            InvalidDataKind::InvalidOptionalDiscriminant { value } => {
                write!(f, "Invalid optional discriminant: 0x{:02x}", value)
            }
            InvalidDataKind::InvalidCompactSize { prefix, value, minimum } => {
                write!(f, "Compact size with 0x{:02x} prefix must be >= {}, got {}", prefix, minimum, value)
            }
            InvalidDataKind::InvalidKeySize { key_type, expected, actual } => {
                write!(f, "Invalid {} size: expected one of {:?}, got {}", key_type, expected, actual)
            }
            InvalidDataKind::Utf8Error { error } => {
                write!(f, "UTF-8 decode error: {}", error)
            }
            InvalidDataKind::Other { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<anyhow::Error> for ParseError {
    fn from(err: anyhow::Error) -> Self {
        ParseError::Anyhow(err.to_string())
    }
}

// No need for explicit From implementation - anyhow already provides one
// via its blanket impl for types that implement std::error::Error

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: err.to_string(),
            },
            context: None,
        }
    }
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(err: std::str::Utf8Error) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: format!("UTF-8 decode error: {}", err),
            },
            context: None,
        }
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Utf8Error { error: err },
            context: None,
        }
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
            Err(err) => Err(ParseError::Anyhow(format!("{}: {}", context.into(), err))),
        }
    }
}