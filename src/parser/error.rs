//! Error types for the binary parsing layer.
//!
//! Parse failures carry a semantic [`ParseErrorKind`] describing what went
//! wrong, plus a stack of structural context frames recording what was being
//! parsed when the failure occurred (innermost first). The kind is the
//! semantic channel — match on it to react to specific failures; the frames
//! are diagnostic breadcrumbs for humans reading the rendered error.

use std::fmt;

/// A convenience `Result` whose error type defaults to [`ParseError`].
///
/// This alias is re-exported by the parser prelude so that `Parse`
/// implementations can use `Result<Self>` directly.
pub type Result<T, E = ParseError> = core::result::Result<T, E>;

/// A structural violation encountered while walking a DER-encoded ECDSA
/// private key (the SEC1 layout zcashd stores under `key` records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DerPrivKeyError {
    /// The encoding does not begin with the outer SEQUENCE tag (0x30).
    #[error("expected outer SEQUENCE tag (0x30)")]
    ExpectedSequence,

    /// The SEQUENCE length byte is missing.
    #[error("truncated SEQUENCE length")]
    TruncatedLength,

    /// A long-form SEQUENCE length has fewer bytes than it declares.
    #[error("truncated long-form SEQUENCE length")]
    TruncatedLongFormLength,

    /// The SEQUENCE length overflows `usize`.
    #[error("SEQUENCE length overflow")]
    LengthOverflow,

    /// The end of the SEQUENCE lies beyond the end of the encoding.
    #[error("SEQUENCE end overflow")]
    EndOverflow,

    /// The SEQUENCE body ends before its declared length.
    #[error("SEQUENCE body extends past end of data")]
    TruncatedBody,

    /// The INTEGER 1 version field expected after the SEQUENCE is absent.
    #[error("expected INTEGER 1 version field after SEQUENCE")]
    ExpectedVersion,

    /// The OCTET STRING(32) holding the private scalar is absent.
    #[error("expected OCTET STRING(32) holding private scalar")]
    ExpectedScalar,

    /// The private scalar's offset overflows `usize`.
    #[error("scalar offset overflow")]
    ScalarOffsetOverflow,

    /// The OCTET STRING(32) holding the private scalar is truncated.
    #[error("OCTET STRING(32) truncated")]
    TruncatedScalar,
}

/// The semantic cause of a parse failure.
#[derive(Debug, thiserror::Error)]
pub enum ParseErrorKind {
    /// The data stream ended before a read could complete.
    #[error(
        "unexpected end of data at offset {offset}: needed {needed} bytes, {remaining} remaining"
    )]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        remaining: usize,
    },

    /// The buffer contains bytes beyond the end of the parsed value.
    #[error("{remaining} unconsumed bytes after parsed value")]
    TrailingData { remaining: usize },

    /// A boolean field held a byte other than 0x00 or 0x01.
    #[error("invalid boolean value: {0:#04x}")]
    InvalidBool(u8),

    /// A byte string is not valid UTF-8.
    #[error("invalid UTF-8 string")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// A string's declared length does not fit in `usize` on this platform.
    #[error("string length does not fit in usize")]
    StringLengthOverflow,

    /// A `CompactSize` used a longer encoding than its value requires.
    #[error("non-canonical compact size: {prefix:#04x}-prefixed encoding holds {value}")]
    NonCanonicalCompactSize { prefix: u8, value: u64 },

    /// An optional-value discriminant byte was neither 0x00 nor 0x01.
    #[error("invalid optional discriminant: {0:#04x}")]
    InvalidOptionalDiscriminant(u8),

    /// A fixed-size field was presented with the wrong number of bytes.
    #[error("invalid data length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// An amount was outside the valid Zat balance range.
    #[error("invalid Zat balance: {0}")]
    InvalidAmount(i64),

    /// Bytes did not form a valid Orchard incoming viewing key.
    #[error("not a valid Orchard incoming viewing key")]
    InvalidOrchardIvk,

    /// A transparent public key had a length other than 33 or 65 bytes.
    #[error("invalid public key length: {0}")]
    InvalidPubKeyLength(usize),

    /// A DER-encoded private key had an invalid overall length.
    #[error("invalid private key length: {0}")]
    InvalidPrivKeyLength(usize),

    /// A DER-encoded private key violated the expected SEC1 structure.
    #[error("invalid DER private key: {0}")]
    DerPrivKey(#[from] DerPrivKeyError),

    /// A key record's public and private halves do not correspond.
    #[error("public key and private key do not match")]
    KeyPairMismatch,

    /// A `u252` value had its most significant four bits set.
    #[error("first four bits of u252 must be zero")]
    U252Overflow,

    /// An unknown unified address receiver type discriminant.
    #[error("invalid receiver type: {0:#04x}")]
    InvalidReceiverTypeValue(u32),

    /// An unknown unified address receiver type name.
    #[error("invalid receiver type name: {0:?}")]
    InvalidReceiverTypeName(String),

    /// An unrecognized zcashd network identifier string.
    #[error("unrecognized zcashd network identifier: {0:?}")]
    UnrecognizedNetwork(String),

    /// An embedded structure read via `std::io` could not be decoded.
    #[error("decoding embedded structure: {0}")]
    Io(#[from] std::io::Error),

    /// A value violated an invariant enforced by the `zewif` data model.
    #[error(transparent)]
    Zewif(#[from] zewif::Error),

    /// A unified full viewing key string could not be decoded.
    #[error("decoding unified full viewing key: {0}")]
    UfvkDecode(#[from] zcash_address::unified::ParseError),

    /// A unified full viewing key could not be interpreted.
    #[error("interpreting unified full viewing key: {0}")]
    UfvkInterpret(#[from] zcash_keys::keys::DecodingError),
}

/// A parse failure: the semantic cause plus the stack of structural contexts
/// that were being parsed when it occurred, innermost first.
#[derive(Debug)]
pub struct ParseError {
    kind: ParseErrorKind,
    frames: Vec<String>,
}

impl ParseError {
    /// The semantic cause of the failure.
    pub fn kind(&self) -> &ParseErrorKind {
        &self.kind
    }

    /// The structural context frames, innermost first (e.g.
    /// `["seed_fp", "KeyMetadata"]`).
    pub fn frames(&self) -> &[String] {
        &self.frames
    }

    /// Returns this error with an additional (outer) context frame.
    ///
    /// The `parse!` macro pushes a frame for each enclosing parse site, so a
    /// rendered error reads from the innermost field outward.
    pub fn with_frame(mut self, frame: impl Into<String>) -> Self {
        self.frames.push(frame.into());
        self
    }
}

impl<K: Into<ParseErrorKind>> From<K> for ParseError {
    fn from(kind: K) -> Self {
        Self {
            kind: kind.into(),
            frames: Vec::new(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.frames.is_empty() {
            write!(f, "parsing ")?;
            for (i, frame) in self.frames.iter().enumerate() {
                if i > 0 {
                    write!(f, " in ")?;
                }
                write!(f, "{}", frame)?;
            }
            write!(f, ": ")?;
        }
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.kind)
    }
}

/// Extends parse results with the ability to attach a context frame.
///
/// This provides `.with_frame(...)` on any `Result` whose error converts into
/// [`ParseError`], mirroring what the `parse!` macro does for its callers.
pub trait ParseResultExt<T> {
    /// Attaches an (outer) context frame to the error, if any.
    fn with_frame(self, frame: impl Into<String>) -> Result<T, ParseError>;
}

impl<T, E: Into<ParseError>> ParseResultExt<T> for core::result::Result<T, E> {
    fn with_frame(self, frame: impl Into<String>) -> Result<T, ParseError> {
        self.map_err(|e| e.into().with_frame(frame))
    }
}
