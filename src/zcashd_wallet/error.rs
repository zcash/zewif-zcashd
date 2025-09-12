use std::fmt;

#[derive(Debug, Clone)]
pub enum ZcashdWalletError {
    InvalidLength {
        expected: usize,
        actual: usize,
        type_name: &'static str,
    },
    InvalidHexString {
        hex_string: String,
        expected_length: usize,
    },
    InvalidData {
        message: String,
        type_name: &'static str,
    },
    ParseError(crate::parser::error::ParseError),
}

impl fmt::Display for ZcashdWalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZcashdWalletError::InvalidLength { expected, actual, type_name } => {
                write!(f, "Invalid length for {}: expected {} bytes, got {}", type_name, expected, actual)
            }
            ZcashdWalletError::InvalidHexString { hex_string, expected_length } => {
                write!(f, "Invalid hex string '{}', expected {} characters", hex_string, expected_length)
            }
            ZcashdWalletError::InvalidData { message, type_name } => {
                write!(f, "Invalid data for {}: {}", type_name, message)
            }
            ZcashdWalletError::ParseError(err) => {
                write!(f, "Parse error: {}", err)
            }
        }
    }
}

impl std::error::Error for ZcashdWalletError {}

impl From<crate::parser::error::ParseError> for ZcashdWalletError {
    fn from(err: crate::parser::error::ParseError) -> Self {
        ZcashdWalletError::ParseError(err)
    }
}

impl From<hex::FromHexError> for ZcashdWalletError {
    fn from(err: hex::FromHexError) -> Self {
        ZcashdWalletError::InvalidData {
            message: err.to_string(),
            type_name: "hex",
        }
    }
}

pub type Result<T> = std::result::Result<T, ZcashdWalletError>;