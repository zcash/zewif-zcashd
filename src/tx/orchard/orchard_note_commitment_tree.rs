use zewif::parser::prelude::*;
use zewif::{Data, u256};
use anyhow::{Context, Result, bail};
use byteorder::{ByteOrder, LittleEndian};

/// Represents a node in the Orchard note commitment tree
#[derive(Debug, Clone, PartialEq)]
pub struct NoteCommitmentTreeNode {
    hash: u256,
    left: Option<Box<NoteCommitmentTreeNode>>,
    right: Option<Box<NoteCommitmentTreeNode>>,
}

impl NoteCommitmentTreeNode {
    /// Get the node hash
    pub fn hash(&self) -> u256 {
        self.hash
    }

    /// Get the left child node, if any
    pub fn left(&self) -> Option<&NoteCommitmentTreeNode> {
        self.left.as_deref()
    }

    /// Get the right child node, if any
    pub fn right(&self) -> Option<&NoteCommitmentTreeNode> {
        self.right.as_deref()
    }
}

/// Represents the complete Orchard note commitment tree
#[derive(Debug, Clone, PartialEq)]
pub struct OrchardNoteCommitmentTree {
    unparsed_data: Data,
    root: Option<NoteCommitmentTreeNode>,
    tree_size: u64,
    nodes: Vec<Option<u256>>,
    depth: usize,
}

impl OrchardNoteCommitmentTree {
    /// Get the root node of the tree, if any
    pub fn root(&self) -> Option<&NoteCommitmentTreeNode> {
        self.root.as_ref()
    }

    /// Get the size of the tree (number of notes)
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Get the nodes vector
    pub fn nodes(&self) -> &[Option<u256>] {
        &self.nodes
    }

    /// Get the depth of the tree
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get the unparsed raw data
    pub fn unparsed_data(&self) -> &Data {
        &self.unparsed_data
    }
}

impl OrchardNoteCommitmentTree {
    /// Parse the raw tree data into a structured format
    pub fn parse_tree_data(&mut self) -> Result<()> {
        if self.unparsed_data.is_empty() {
            return Ok(());
        }

        let data = &self.unparsed_data;

        // Check the tree format version - first 4 bytes
        let format_version = LittleEndian::read_u32(&data[0..4]);
        if format_version != 1 {
            bail!("Unsupported tree format version: {}", format_version);
        }

        // Parse tree size (number of notes) - next 8 bytes
        let tree_size = LittleEndian::read_u64(&data[4..12]);
        self.tree_size = tree_size;

        // The depth of the tree - 1 byte
        let depth = data[12] as usize;
        self.depth = depth;

        // The rest of the data is the serialized tree structure
        // A valid tree should have at least (2^depth - 1) possible node positions
        let expected_node_count = (1 << depth) - 1;
        self.nodes = Vec::with_capacity(expected_node_count);

        // Parse the node structure
        let mut position = 13; // starting after header

        while position < data.len() {
            // Each node entry starts with a flag byte indicating if it's present
            let has_node = data[position] != 0;
            position += 1;

            if has_node {
                // Read the 32-byte node hash
                if position + 32 <= data.len() {
                    let node_hash = u256::try_from(&data[position..position + 32])
                        .context("Failed to parse node hash")?;
                    self.nodes.push(Some(node_hash));
                    position += 32;
                } else {
                    bail!("Invalid tree data: truncated node hash");
                }
            } else {
                // No node at this position
                self.nodes.push(None);
            }
        }

        // Reconstruct the tree structure
        if !self.nodes.is_empty() {
            self.root = self.build_tree_node(0);
        }

        Ok(())
    }

    /// Recursively build the tree structure from the flat nodes array
    fn build_tree_node(&self, index: usize) -> Option<NoteCommitmentTreeNode> {
        if index >= self.nodes.len() {
            return None;
        }

        if let Some(hash) = self.nodes[index] {
            // Calculate left and right child indices
            let left_idx = 2 * index + 1;
            let right_idx = 2 * index + 2;

            let left = if left_idx < self.nodes.len() {
                self.build_tree_node(left_idx).map(Box::new)
            } else {
                None
            };

            let right = if right_idx < self.nodes.len() {
                self.build_tree_node(right_idx).map(Box::new)
            } else {
                None
            };

            Some(NoteCommitmentTreeNode { hash, left, right })
        } else {
            None
        }
    }

    /// Convert to Zewif IncrementalMerkleTree format
    pub fn to_zewif_tree(&self) -> zewif::IncrementalMerkleTree {
        let mut tree = zewif::IncrementalMerkleTree::new();

        // Convert the root node
        if let Some(root_node) = &self.root {
            // The root node's left and right children are the first level
            if let Some(left) = &root_node.left {
                tree.set_left(left.hash);
            }

            if let Some(right) = &root_node.right {
                tree.set_right(right.hash);
            }

            // Add parents (ancestors) from the tree
            // In a simple implementation, we'll just add all non-empty parent nodes
            for idx in 0..self.depth.saturating_sub(1) {
                let parent_idx = (1 << idx) - 1; // Formula for perfect binary tree indices
                if parent_idx < self.nodes.len() {
                    tree.push_parent(self.nodes[parent_idx]);
                } else {
                    tree.push_parent(None);
                }
            }
        }

        tree
    }
}

impl Parse for OrchardNoteCommitmentTree {
    fn parse(p: &mut Parser) -> Result<Self> {
        let mut tree = Self {
            unparsed_data: p.rest(),
            root: None,
            tree_size: 0,
            nodes: Vec::new(),
            depth: 0,
        };

        // Parse the tree data immediately during construction
        // We'll ignore errors here - if we can't parse it, we'll have the unparsed data
        let _ = tree.parse_tree_data();

        Ok(tree)
    }
}
