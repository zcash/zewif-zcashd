use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::CompactSize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReceiverType {
    P2PKH = 0x00,
    P2SH = 0x01,
    Sapling = 0x02,
    Orchard = 0x03,
}

impl Parse for ReceiverType {
    fn parse(p: &mut Parser) -> Result<Self> {
        let byte = *parse!(p, CompactSize, "ReceiverType")?;
        match byte {
            0x00 => Ok(ReceiverType::P2PKH),
            0x01 => Ok(ReceiverType::P2SH),
            0x02 => Ok(ReceiverType::Sapling),
            0x03 => Ok(ReceiverType::Orchard),
            _ => Err(anyhow::anyhow!("Invalid ReceiverType byte: 0x{:02x}", byte)),
        }
    }
}
