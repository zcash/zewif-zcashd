use std::collections::HashMap;

use anyhow::Result;

use zewif::Blob64;
use zewif::{parse, parser::prelude::*};

use super::super::super::ClientVersion;

#[derive(Debug, Clone, PartialEq)]
pub struct OrchardTxMeta {
    version: ClientVersion,
    action_data: HashMap<u32, Blob64>,
    actions_spending_my_nodes: Vec<u32>,
}

impl OrchardTxMeta {
    /// Returns the client version
    pub fn version(&self) -> ClientVersion {
        self.version
    }

    /// Returns action data for the given index
    pub fn action_data(&self, index: u32) -> Option<&Blob64> {
        self.action_data.get(&index)
    }

    /// Returns the entire action data map
    pub fn all_action_data(&self) -> &HashMap<u32, Blob64> {
        &self.action_data
    }

    /// Returns the list of actions spending nodes owned by this wallet
    pub fn actions_spending_my_nodes(&self) -> &[u32] {
        &self.actions_spending_my_nodes
    }
}

impl Parse for OrchardTxMeta {
    fn parse(parser: &mut Parser) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            version: parse!(parser, "version")?,
            action_data: parse!(parser, "action_data")?,
            actions_spending_my_nodes: parse!(parser, "actions_spending_my_nodes")?,
        })
    }
}
