use std::fmt;

#[derive(Debug, Clone)]
pub enum ParseError {
    BufferUnderflow {
        offset: usize,
        needed: usize,
        remaining: usize,
        context: Option<String>,
    },
    UnconsumedBytes {
        remaining: usize,
        context: Option<String>,
    },
    InvalidData {
        kind: InvalidDataKind,
        context: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Key,
    SapzKey,
    ZKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataType {
    KeyMeta,
    SapzKeyMeta, 
    ZKeyMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedMetadataType {
    Address,
    Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateEntryType {
    AddressName,
    AddressPurpose,
    PaymentAddress,
    Transaction,
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
    // Database record inconsistencies
    RecordCountMismatch {
        record_type: RecordType,
        metadata_type: MetadataType,
        record_count: usize,
        metadata_count: usize,
    },
    // Unexpected metadata values
    UnexpectedUnifiedMetadataValue {
        metadata_type: UnifiedMetadataType,
        expected: u32,
        actual: u32,
    },
    // Duplicate entries in collections
    DuplicateEntry {
        entry_type: DuplicateEntryType,
        key: String,
    },
    // Database dump parsing errors
    KeyNotFound {
        key: String,
    },
    KeynameNotFound {
        keyname: String,
    },
    RecordCountError {
        keyname: String,
        expected: String, // "exactly one", "at least one", etc.
        actual: usize,
    },
    Other {
        message: String,
    },
}

impl ParseError {
    pub fn with_context<S: Into<String>>(self, context: S) -> Self {
        let context_str = context.into();
        match self {
            ParseError::BufferUnderflow { offset, needed, remaining, context: existing_context } => {
                let new_context = if let Some(existing) = existing_context {
                    format!("{}: {}", context_str, existing)
                } else {
                    context_str
                };
                ParseError::BufferUnderflow {
                    offset,
                    needed,
                    remaining,
                    context: Some(new_context),
                }
            }
            ParseError::UnconsumedBytes { remaining, context: existing_context } => {
                let new_context = if let Some(existing) = existing_context {
                    format!("{}: {}", context_str, existing)
                } else {
                    context_str
                };
                ParseError::UnconsumedBytes {
                    remaining,
                    context: Some(new_context),
                }
            }
            ParseError::InvalidData { kind, context: existing_context } => {
                let new_context = if let Some(existing) = existing_context {
                    format!("{}: {}", context_str, existing)
                } else {
                    context_str
                };
                ParseError::InvalidData {
                    kind,
                    context: Some(new_context),
                }
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
            ParseError::BufferUnderflow { offset, needed, remaining, context } => {
                let base_msg = format!("Buffer underflow at offset {}, needed {} bytes, only {} remaining", offset, needed, remaining);
                if let Some(ctx) = context {
                    write!(f, "{}: {}", ctx, base_msg)
                } else {
                    write!(f, "{}", base_msg)
                }
            }
            ParseError::UnconsumedBytes { remaining, context } => {
                let base_msg = format!("Buffer has {} bytes left", remaining);
                if let Some(ctx) = context {
                    write!(f, "{}: {}", ctx, base_msg)
                } else {
                    write!(f, "{}", base_msg)
                }
            }
            ParseError::InvalidData { kind, context } => {
                if let Some(ctx) = context {
                    write!(f, "{}: {}", ctx, kind)
                } else {
                    write!(f, "{}", kind)
                }
            }
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::Key => write!(f, "key"),
            RecordType::SapzKey => write!(f, "sapzkey"),
            RecordType::ZKey => write!(f, "zkey"),
        }
    }
}

impl fmt::Display for MetadataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataType::KeyMeta => write!(f, "keymeta"),
            MetadataType::SapzKeyMeta => write!(f, "sapzkeymeta"),
            MetadataType::ZKeyMeta => write!(f, "zkeymeta"),
        }
    }
}

impl fmt::Display for UnifiedMetadataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnifiedMetadataType::Address => write!(f, "UnifiedAddressMetadata"),
            UnifiedMetadataType::Account => write!(f, "UnifiedAccountMetadata"),
        }
    }
}

impl fmt::Display for DuplicateEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DuplicateEntryType::AddressName => write!(f, "address name"),
            DuplicateEntryType::AddressPurpose => write!(f, "address purpose"),
            DuplicateEntryType::PaymentAddress => write!(f, "payment address"),
            DuplicateEntryType::Transaction => write!(f, "transaction"),
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
            InvalidDataKind::RecordCountMismatch { record_type, metadata_type, record_count, metadata_count } => {
                write!(f, "Mismatched {} and {} records: {} records vs {} metadata entries", 
                       record_type, metadata_type, record_count, metadata_count)
            }
            InvalidDataKind::UnexpectedUnifiedMetadataValue { metadata_type, expected, actual } => {
                write!(f, "Unexpected value for {}: expected 0x{:08x}, got 0x{:08x}", 
                       metadata_type, expected, actual)
            }
            InvalidDataKind::DuplicateEntry { entry_type, key } => {
                write!(f, "Duplicate {} found: {}", entry_type, key)
            }
            InvalidDataKind::KeyNotFound { key } => {
                write!(f, "No record found for key: {}", key)
            }
            InvalidDataKind::KeynameNotFound { keyname } => {
                write!(f, "No record found for keyname: {}", keyname)
            }
            InvalidDataKind::RecordCountError { keyname, expected, actual } => {
                write!(f, "Expected {} record(s) for keyname: {}, got {}", expected, keyname, actual)
            }
            InvalidDataKind::Other { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for ParseError {}

// Handle errors from external crates that still use anyhow
impl From<anyhow::Error> for ParseError {
    fn from(err: anyhow::Error) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: err.to_string(),
            },
            context: None,
        }
    }
}


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

impl From<zcash_address::ParseError> for ParseError {
    fn from(err: zcash_address::ParseError) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: format!("Address parse error: {}", err),
            },
            context: None,
        }
    }
}

impl From<zcash_address::ConversionError<std::convert::Infallible>> for ParseError {
    fn from(err: zcash_address::ConversionError<std::convert::Infallible>) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: format!("Address conversion error: {}", err),
            },
            context: None,
        }
    }
}

impl From<zcash_keys::keys::AddressGenerationError> for ParseError {
    fn from(err: zcash_keys::keys::AddressGenerationError) -> Self {
        ParseError::InvalidData {
            kind: InvalidDataKind::Other {
                message: format!("Address generation error: {}", err),
            },
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

