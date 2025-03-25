use std::collections::HashMap;
use zewif::parser::prelude::*;
use zewif::{Data, Position, u256};
use anyhow::{Context, Result, bail, ensure};
use byteorder::{ByteOrder, LittleEndian};

// Constants for tree validation
const ORCHARD_TREE_DEPTH: usize = 32;
const MIN_HEADER_SIZE: usize = 13; // 4 bytes version + 8 bytes size + 1 byte depth

/// Represents a node in the Orchard note commitment tree
#[derive(Debug, Clone, PartialEq)]
pub struct NoteCommitmentTreeNode {
    hash: u256,
    position: usize, // Index position in the binary tree
    left: Option<Box<NoteCommitmentTreeNode>>,
    right: Option<Box<NoteCommitmentTreeNode>>,
    // Flags to identify leaf nodes (containing actual commitments)
    is_leaf: bool,
}

impl NoteCommitmentTreeNode {
    /// Create a new tree node
    pub fn new(hash: u256, position: usize, is_leaf: bool) -> Self {
        Self {
            hash,
            position,
            left: None,
            right: None,
            is_leaf,
        }
    }

    /// Get the node hash
    pub fn hash(&self) -> u256 {
        self.hash
    }

    /// Get the node position in the tree
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get the left child node, if any
    pub fn left(&self) -> Option<&NoteCommitmentTreeNode> {
        self.left.as_deref()
    }

    /// Get the right child node, if any
    pub fn right(&self) -> Option<&NoteCommitmentTreeNode> {
        self.right.as_deref()
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.is_leaf
    }

    /// Set the left child node
    pub fn set_left(&mut self, node: NoteCommitmentTreeNode) {
        self.left = Some(Box::new(node));
    }

    /// Set the right child node
    pub fn set_right(&mut self, node: NoteCommitmentTreeNode) {
        self.right = Some(Box::new(node));
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
    // Maps commitment hashes to their positions in the tree
    commitment_positions: HashMap<u256, Position>,
    // Track leaf nodes separately for efficient access
    leaf_nodes: Vec<(u256, Position)>,
    // Parsing state
    is_fully_parsed: bool,
}

impl OrchardNoteCommitmentTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        Self {
            unparsed_data: Data::new(),
            root: None,
            tree_size: 0,
            nodes: Vec::new(),
            depth: 0,
            commitment_positions: HashMap::new(),
            leaf_nodes: Vec::new(),
            is_fully_parsed: false,
        }
    }
    
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
    
    /// Check if the tree data has been fully parsed
    pub fn is_fully_parsed(&self) -> bool {
        self.is_fully_parsed
    }
    
    /// Get all leaf nodes (commitments) with their positions
    pub fn leaf_nodes(&self) -> &[(u256, Position)] {
        &self.leaf_nodes
    }
    
    /// Get the position for a specific commitment hash
    pub fn position_for_commitment(&self, commitment: &u256) -> Option<Position> {
        self.commitment_positions.get(commitment).copied()
    }
    
    /// Check if a specific commitment exists in the tree
    pub fn contains_commitment(&self, commitment: &u256) -> bool {
        self.commitment_positions.contains_key(commitment)
    }
}

impl OrchardNoteCommitmentTree {
    /// Parse the raw tree data into a structured format
    pub fn parse_tree_data(&mut self) -> Result<()> {
        // Reset any previous parsing state
        self.commitment_positions.clear();
        self.leaf_nodes.clear();
        self.is_fully_parsed = false;
        
        if self.unparsed_data.is_empty() {
            return Ok(());
        }

        let data = &self.unparsed_data;
        
        // Validate minimum header size
        ensure!(data.len() >= MIN_HEADER_SIZE, 
                "Tree data too small: expected at least {} bytes for header, got {}",
                MIN_HEADER_SIZE, data.len());

        // Check the tree format version - first 4 bytes
        let format_version = LittleEndian::read_u32(&data[0..4]);
        ensure!(format_version == 1, 
                "Unsupported tree format version: {}", format_version);

        // Parse tree size (number of notes) - next 8 bytes
        let tree_size = LittleEndian::read_u64(&data[4..12]);
        self.tree_size = tree_size;

        // The depth of the tree - 1 byte
        let depth = data[12] as usize;
        ensure!(depth <= ORCHARD_TREE_DEPTH, 
                "Invalid tree depth: {}, maximum supported is {}", 
                depth, ORCHARD_TREE_DEPTH);
        
        self.depth = depth;

        // Calculate the maximum number of nodes based on the tree depth
        let max_nodes = (1u64 << depth) - 1;
        
        // Each node requires 1 flag byte + potentially 32 bytes for the hash
        // So the theoretical maximum size would be:
        let max_theoretical_size = MIN_HEADER_SIZE + (max_nodes as usize) * (1 + 32);
        
        // The actual size might be less if not all nodes have data
        ensure!(data.len() <= max_theoretical_size,
                "Tree data suspiciously large: {} bytes", data.len());

        // The rest of the data is the serialized tree structure
        // A valid tree should have at least (2^depth - 1) possible node positions
        let expected_node_count = (1 << depth) - 1;
        self.nodes = Vec::with_capacity(expected_node_count);

        // Parse the node structure
        let mut position = 13; // starting after header
        let mut node_index = 0;

        while position < data.len() && node_index < expected_node_count {
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
                    bail!("Invalid tree data: truncated node hash at position {}", position);
                }
            } else {
                // No node at this position
                self.nodes.push(None);
            }
            
            node_index += 1;
        }
        
        // Ensure we parsed the correct number of nodes
        ensure!(self.nodes.len() == expected_node_count || 
                self.nodes.len() == (tree_size as usize),
                "Parsed {} nodes, expected {} based on tree depth",
                self.nodes.len(), expected_node_count);

        // Fill missing nodes if any (sparse tree representation)
        while self.nodes.len() < expected_node_count {
            self.nodes.push(None);
        }

        // Reconstruct the tree structure with position information
        if !self.nodes.is_empty() {
            self.root = self.build_tree_node(0);
            
            // Now populate our commitment-to-position map
            self.build_commitment_position_map();
        }
        
        self.is_fully_parsed = true;
        Ok(())
    }

    /// Recursively build the tree structure from the flat nodes array
    fn build_tree_node(&self, index: usize) -> Option<NoteCommitmentTreeNode> {
        if index >= self.nodes.len() {
            return None;
        }

        if let Some(hash) = self.nodes[index] {
            // Calculate the depth of this node in the tree
            let node_depth = calculate_depth_from_index(index);
            
            // Determine if this is a leaf node
            // In a perfect binary tree, leaf nodes are at maximum depth and have no children
            let is_leaf = node_depth >= self.depth - 1;
            
            // Create the node with its index position
            let mut node = NoteCommitmentTreeNode::new(hash, index, is_leaf);
            
            // Only attach children if this is not a leaf node
            if !is_leaf {
                // Calculate left and right child indices
                let left_idx = 2 * index + 1;
                let right_idx = 2 * index + 2;

                if left_idx < self.nodes.len() {
                    if let Some(left_node) = self.build_tree_node(left_idx) {
                        node.set_left(left_node);
                    }
                }

                if right_idx < self.nodes.len() {
                    if let Some(right_node) = self.build_tree_node(right_idx) {
                        node.set_right(right_node);
                    }
                }
            }

            Some(node)
        } else {
            None
        }
    }
    
    /// Build a mapping from commitment hashes to their positions in the tree
    fn build_commitment_position_map(&mut self) {
        // Clear existing data
        self.commitment_positions.clear();
        self.leaf_nodes.clear();
        
        // Process all leaf nodes
        for i in 0..self.nodes.len() {
            if let Some(hash) = self.nodes[i] {
                // Check if this is a leaf node based on its position
                let node_depth = calculate_depth_from_index(i);
                
                // In ZCash, note commitments are stored in the leaf nodes
                if node_depth >= self.depth - 1 {
                    // Convert tree index to a Position type
                    let position = Position::from(i);
                    
                    // Store in our maps
                    self.commitment_positions.insert(hash, position);
                    self.leaf_nodes.push((hash, position));
                }
            }
        }
    }
    
    /// Find the position for a commitment in the tree
    pub fn find_commitment_position(&self, commitment: &u256) -> Option<Position> {
        // Check our cache first
        if let Some(position) = self.commitment_positions.get(commitment) {
            return Some(*position);
        }
        
        // If not in cache, do a linear search through the nodes
        // This is less efficient, but serves as a fallback
        for (i, node_hash) in self.nodes.iter().enumerate() {
            if let Some(hash) = node_hash {
                if hash == commitment {
                    // Convert tree index to Position
                    return Some(Position::from(i));
                }
            }
        }
        
        None
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
    
    /// Get all commitment positions in the tree as a HashMap
    pub fn commitment_positions(&self) -> &HashMap<u256, Position> {
        &self.commitment_positions
    }
    
    /// Get a list of all commitments (leaf nodes) in the tree
    pub fn get_commitments(&self) -> Vec<u256> {
        self.leaf_nodes.iter().map(|(hash, _)| *hash).collect()
    }
    
    /// Get a debug summary of the tree structure
    pub fn get_tree_summary(&self) -> String {
        let mut summary = "Orchard Note Commitment Tree Summary:\n".to_string();
        summary.push_str("  - Format version: 1\n");
        summary.push_str(&format!("  - Tree size: {}\n", self.tree_size));
        summary.push_str(&format!("  - Tree depth: {}\n", self.depth));
        summary.push_str(&format!("  - Total nodes: {}\n", self.nodes.len()));
        
        let present_nodes = self.nodes.iter().filter(|n| n.is_some()).count();
        summary.push_str(&format!("  - Present nodes: {}\n", present_nodes));
        
        summary.push_str(&format!("  - Leaf nodes (commitments): {}\n", self.leaf_nodes.len()));
        
        if let Some(root) = &self.root {
            summary.push_str(&format!("  - Root hash: {:?}\n", root.hash));
        } else {
            summary.push_str("  - Root: None\n");
        }
        
        summary
    }
}

/// Calculate the depth of a node in the tree based on its index
/// In a perfect binary tree with 0-based indexing:
/// - Root is at index 0 (depth 0)
/// - Depth 1 nodes are at indices 1-2
/// - Depth 2 nodes are at indices 3-6
/// - Depth d nodes start at index 2^d - 1
fn calculate_depth_from_index(index: usize) -> usize {
    (index + 1).next_power_of_two().trailing_zeros() as usize
}

impl Parse for OrchardNoteCommitmentTree {
    fn parse(p: &mut Parser) -> Result<Self> {
        let mut tree = Self {
            unparsed_data: p.rest(),
            root: None,
            tree_size: 0,
            nodes: Vec::new(),
            depth: 0,
            commitment_positions: HashMap::new(),
            leaf_nodes: Vec::new(),
            is_fully_parsed: false,
        };

        // Parse the tree data immediately during construction
        // We'll log errors but continue - data can be parsed later
        if let Err(err) = tree.parse_tree_data() {
            // Log the error but continue
            eprintln!("Warning: Failed to parse orchard note commitment tree: {}", err);
        }

        Ok(tree)
    }
}

impl Default for OrchardNoteCommitmentTree {
    fn default() -> Self {
        Self {
            unparsed_data: Data::new(),
            root: None,
            tree_size: 0,
            nodes: Vec::new(),
            depth: 0,
            commitment_positions: HashMap::new(),
            leaf_nodes: Vec::new(),
            is_fully_parsed: false,
        }
    }
}
