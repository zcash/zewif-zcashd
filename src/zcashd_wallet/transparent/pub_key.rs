use zewif::Data;

use crate::{parse, parser::{prelude::*, error::{ParseError, InvalidDataKind}}, zcashd_wallet::CompactSize};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PubKey(Data);

impl PubKey {
    pub const PUBLIC_KEY_SIZE: usize = 65;
    pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn is_compressed(&self) -> bool {
        self.0.as_slice().len() == Self::COMPRESSED_PUBLIC_KEY_SIZE
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PubKey({:?})", &self.0)
    }
}

impl AsRef<Data> for PubKey {
    fn as_ref(&self) -> &Data {
        &self.0
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Parse for PubKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        let size = *parse!(p, CompactSize, "PubKey size")?;
        if size != 33 && size != 65 {
            return Err(ParseError::InvalidData {
                kind: InvalidDataKind::InvalidKeySize {
                    key_type: "PubKey",
                    expected: vec![33, 65],
                    actual: size,
                },
                context: None,
            });
        }

        let key_data = p.next(size).map(Data::from_slice)?;
        Ok(Self(key_data))
    }
}
