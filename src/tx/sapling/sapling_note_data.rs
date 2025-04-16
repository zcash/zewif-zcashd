use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{
    sapling::{SaplingIncomingViewingKey, SaplingWitness},
    u256,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SaplingNoteData {
    version: i32,
    incoming_viewing_key: SaplingIncomingViewingKey,
    nullifer: Option<u256>,
    witnesses: Vec<SaplingWitness>,
    witness_height: i32,
}

impl SaplingNoteData {
    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn incoming_viewing_key(&self) -> &SaplingIncomingViewingKey {
        &self.incoming_viewing_key
    }

    pub fn nullifer(&self) -> Option<u256> {
        self.nullifer
    }

    pub fn witnesses(&self) -> &[SaplingWitness] {
        &self.witnesses
    }

    pub fn witness_height(&self) -> i32 {
        self.witness_height
    }
}

impl Parse for SaplingNoteData {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            version: parse!(p, "version")?,
            incoming_viewing_key: parse!(p, "incoming_viewing_key")?,
            nullifer: parse!(p, "nullifer")?,
            witnesses: parse!(p, "witnesses")?,
            witness_height: parse!(p, "witness_height")?,
        })
    }
}
