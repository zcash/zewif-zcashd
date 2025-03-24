use anyhow::{Context, Result, bail};

use zewif::{parse, parser::prelude::*};
use zewif::{CompactSize, Data};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PubKey(Data);

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
            bail!("Invalid PubKey size: {}", size);
        }
        let key_data = Data::parse_len(p, size).context("PubKey")?;
        Ok(Self(key_data))
    }
}
