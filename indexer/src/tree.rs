//! The pool's append-only tree, kept as its frontier, so every root a log reports is checked.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Depth of the pool's commitment tree.
pub const TREE_DEPTH: usize = 32;

/// `keccak256("hisoka.darkpool.genesis")` reduced into the scalar field.
const GENESIS_DOMAIN: [u8; 32] = [
    0x0e, 0x90, 0x00, 0x19, 0x98, 0x8d, 0xa1, 0x9e, 0x38, 0x20, 0xa6, 0x71, 0x41, 0xab, 0x82, 0xff,
    0x80, 0xf4, 0x4f, 0x2f, 0x34, 0x83, 0x33, 0x60, 0xca, 0x78, 0x39, 0x45, 0x56, 0x8c, 0xc3, 0x5b,
];

/// Read a 32-byte big-endian scalar, refusing a value at or above the modulus.
pub(crate) fn canonical(bytes: &[u8; 32]) -> Option<Fr> {
    let fr = Fr::from_be_bytes_mod_order(bytes);
    (to_bytes(fr) == *bytes).then_some(fr)
}

pub(crate) fn to_bytes(value: Fr) -> [u8; 32] {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = out.len().saturating_sub(be.len());
    if let (Some(slot), Some(src)) = (out.get_mut(start..), be.get(be.len().saturating_sub(32)..)) {
        slot.copy_from_slice(src);
    }
    out
}

fn level_scalar(level: usize) -> Fr {
    Fr::from(level as u64)
}

/// The leaf the pool seeds at index 0 on `chain_id`.
///
/// # Examples
/// ```
/// use howl_indexer::genesis_leaf;
/// assert_ne!(genesis_leaf(1), genesis_leaf(31337));
/// ```
#[must_use]
pub fn genesis_leaf(chain_id: u64) -> [u8; 32] {
    let domain = Fr::from_be_bytes_mod_order(&GENESIS_DOMAIN);
    to_bytes(howl_poseidon2::hash(&[domain, Fr::from(chain_id)]))
}

/// The left node waiting for its right sibling at each level, which is all an append-only
/// tree needs to produce the next root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frontier {
    side: [Fr; TREE_DEPTH],
    leaves: u64,
    root: Fr,
}

impl Frontier {
    pub(crate) fn empty() -> Self {
        Self {
            side: [Fr::from(0u64); TREE_DEPTH],
            leaves: 0,
            root: Fr::from(0u64),
        }
    }

    /// Rebuild from stored parts. `None` when a node is not canonical or the parts do not
    /// reproduce `root`, so a damaged checkpoint cannot seed a tree that later refuses
    /// every honest leaf.
    pub(crate) fn restore(
        side: &[[u8; 32]; TREE_DEPTH],
        leaves: u64,
        root: &[u8; 32],
    ) -> Option<Self> {
        let mut nodes = [Fr::from(0u64); TREE_DEPTH];
        for (slot, bytes) in nodes.iter_mut().zip(side) {
            *slot = canonical(bytes)?;
        }
        let frontier = Self {
            side: nodes,
            leaves,
            root: canonical(root)?,
        };
        (leaves <= 1u64 << TREE_DEPTH && frontier.fold() == frontier.root).then_some(frontier)
    }

    /// The root the frontier implies: the pending left nodes, folded from the lowest set bit
    /// of the leaf count upward.
    fn fold(&self) -> Fr {
        let mut node: Option<Fr> = None;
        for (level, side) in self.side.iter().enumerate() {
            if (self.leaves >> level) & 1 == 1 {
                node = Some(match node {
                    Some(right) => howl_poseidon2::hash(&[*side, right, level_scalar(level)]),
                    None => *side,
                });
            }
        }
        node.unwrap_or_else(|| Fr::from(0u64))
    }

    pub(crate) const fn leaves(&self) -> u64 {
        self.leaves
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        to_bytes(self.root)
    }

    pub(crate) fn side(&self) -> [[u8; 32]; TREE_DEPTH] {
        let mut out = [[0u8; 32]; TREE_DEPTH];
        for (slot, node) in out.iter_mut().zip(self.side) {
            *slot = to_bytes(node);
        }
        out
    }

    /// Append a leaf and return the new root. `None` once the tree is full.
    ///
    /// The walk is the pool's: an even position parks the node and carries it up unhashed,
    /// an odd position hashes the parked left node with it and the level.
    pub(crate) fn insert(&mut self, leaf: Fr) -> Option<[u8; 32]> {
        if self.leaves >= 1u64 << TREE_DEPTH {
            return None;
        }
        let mut node = leaf;
        let mut index = self.leaves;
        for (level, side) in self.side.iter_mut().enumerate() {
            if index & 1 == 0 {
                *side = node;
                if index == 0 {
                    break;
                }
            } else {
                node = howl_poseidon2::hash(&[*side, node, level_scalar(level)]);
            }
            index >>= 1;
        }
        self.leaves += 1;
        self.root = node;
        Some(to_bytes(node))
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical, to_bytes, Frontier, GENESIS_DOMAIN, TREE_DEPTH};
    use ark_bn254::Fr;

    #[test]
    fn a_frontier_restores_only_from_parts_that_reproduce_its_root() {
        let mut tree = Frontier::empty();
        for leaf in 1..=11u64 {
            assert!(tree.insert(Fr::from(leaf)).is_some());
        }
        let (side, root) = (tree.side(), tree.root());
        assert_eq!(Frontier::restore(&side, 11, &root), Some(tree));
        assert_eq!(
            Frontier::restore(&side, 10, &root),
            None,
            "wrong leaf count"
        );
        let mut damaged = side;
        if let Some(byte) = damaged.get_mut(1).and_then(|node| node.get_mut(31)) {
            *byte ^= 1;
        }
        assert_eq!(Frontier::restore(&damaged, 11, &root), None, "damaged node");
    }

    #[test]
    fn a_scalar_at_the_modulus_is_refused() {
        // The BN254 scalar modulus itself, which reduces to zero.
        let modulus = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];
        assert_eq!(canonical(&modulus), None);
        let mut below = modulus;
        below[31] = 0;
        assert!(canonical(&below).is_some());
    }

    #[test]
    fn the_genesis_domain_is_the_reduced_keccak_of_its_label() {
        use ark_ff::PrimeField;
        use sha3::{Digest, Keccak256};
        let hash: [u8; 32] = Keccak256::digest(b"hisoka.darkpool.genesis").into();
        assert_eq!(to_bytes(Fr::from_be_bytes_mod_order(&hash)), GENESIS_DOMAIN);
    }

    #[test]
    fn an_empty_frontier_restores() {
        let empty = Frontier::empty();
        assert_eq!(
            Frontier::restore(&[[0u8; 32]; TREE_DEPTH], 0, &[0u8; 32]),
            Some(empty)
        );
    }
}
