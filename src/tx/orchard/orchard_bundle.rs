use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Amount, Blob32, Data};

use super::{OrchardAction, OrchardAuthorized, OrchardFlags};

#[derive(Debug, Clone, PartialEq)]
pub struct OrchardBundle(Option<OrchardBundleInner>);

impl OrchardBundle {
    pub fn new() -> Self {
        Self(None)
    }

    pub fn inner(&self) -> Option<&OrchardBundleInner> {
        self.0.as_ref()
    }
}

impl Default for OrchardBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl From<OrchardBundleInner> for OrchardBundle {
    fn from(inner: OrchardBundleInner) -> Self {
        Self(Some(inner))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrchardBundleInner {
    pub actions: Vec<OrchardAction>,
    pub flags: OrchardFlags,
    pub value_balance: Amount,
    pub anchor: Blob32,
    pub authorization: OrchardAuthorized,
}

impl Parse for OrchardBundle {
    fn parse(p: &mut Parser) -> Result<Self> {
        let actions_without_auth = parse!(p, Vec<OrchardAction>, "actions_without_auth")?;
        if actions_without_auth.is_empty() {
            return Ok(Self(None));
        }
        let flags = parse!(p, "flags")?;
        let value_balance = parse!(p, "balance")?;
        let anchor = parse!(p, "anchor")?;
        let proof_bytes = parse!(p, Data, "proof")?;

        let actions = actions_without_auth
            .into_iter()
            .map(|mut action| {
                let spend_auth_sig = parse!(p, "spend_auth_sig")?;
                action.set_authorization(spend_auth_sig);
                Ok(action)
            })
            .collect::<Result<Vec<OrchardAction>>>()?;

        let binding_sig = parse!(p, "binding_sig")?;
        let authorization =
            OrchardAuthorized::new(proof_bytes, binding_sig);

        Ok(Self(Some(OrchardBundleInner {
            actions,
            flags,
            value_balance,
            anchor,
            authorization,
        })))
    }
}
