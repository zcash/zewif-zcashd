use super::{SaplingBundleV4, SaplingBundleV5};

#[derive(Debug, Clone, PartialEq)]
pub enum SaplingBundle {
    V4(SaplingBundleV4),
    V5(SaplingBundleV5),
}
