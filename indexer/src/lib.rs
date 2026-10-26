//! Turns Howl pool logs into the ordered leaf stream a discovery server stores.
//!
//! Every tree insertion on chain is three pool logs, in this order: `RootSaved` and
//! `LeafInserted` from the tree library, then the event that says what the leaf is -
//! `GenesisSeeded` for leaf 0, `NewNote` or `NewPrivateMemo` for every note. `LeafInserted`
//! carries the position, the leaf and the new root, so `RootSaved` adds nothing here and any
//! log of a topic this crate does not decode is skipped. [`Indexer::ingest`] pairs
//! `LeafInserted` with the describing event in `(block, logIndex)` order and yields one
//! [`Leaf`] per position: the 256-byte discovery cell, the discovery tag, and the tree leaf.
//!
//! The pairing is what makes the stream complete. A leaf whose describing event this build
//! cannot read stops the indexer, and so does a root that differs from the one recomputed
//! here, so the table is never a silent subset of the tree. The note ciphertext is
//! `bytes32[7]` in the ABI: another word count changes the event signature, which leaves a
//! `LeafInserted` unpaired, and a recognised signature of another length is refused outright.
//!
//! Only blocks at least [`IndexerConfig::finality_depth`] below the head are read. A batch
//! is applied whole or not at all, and the same logs yield the same leaves however they are
//! split across calls.
//!
//! A public memo inserts no leaf, so it passes through untouched; claiming one arrives as an
//! ordinary `NewNote`.

#![deny(missing_docs)]

mod event;
mod tree;

pub use event::{
    decode, PoolEvent, RawLog, CIPHERTEXT_WORDS, TOPIC_GENESIS_SEEDED, TOPIC_LEAF_INSERTED,
    TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO,
};
pub use tree::{genesis_leaf, TREE_DEPTH};

use ark_bn254::Fr;
use howl_record::{
    encode, HowlNoteRecord, CELL_BYTES, CIPHERTEXT_KEPT_INDICES, COMMITMENT_PREFIX_BYTES,
    LAYOUT_VERSION, RECORD_KIND_INCOMING, RECORD_KIND_SELF,
};
use tree::{canonical, Frontier};

/// Why a batch of logs was refused. Nothing is applied from a refused batch.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IndexError {
    /// A recognised event signature with an unexpected shape.
    #[error("log {block}:{log_index}: {event} carries {found} {what}, expected {expected}")]
    MalformedEvent {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Event name.
        event: &'static str,
        /// `"topics"` or `"data bytes"`.
        what: &'static str,
        /// Count found.
        found: usize,
        /// Count the ABI gives.
        expected: usize,
    },
    /// An integer argument does not fit the width this build stores it in.
    #[error("log {block}:{log_index}: {event}.{field} is out of range")]
    ValueOutOfRange {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Event name.
        event: &'static str,
        /// Argument name.
        field: &'static str,
    },
    /// A field element at or above the scalar modulus. The pool's verifier refuses those,
    /// so one in a log means the log did not come from the pool this build knows.
    #[error("log {block}:{log_index}: {event}.{field} is not a canonical BN254 scalar")]
    NonCanonicalField {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Event name.
        event: &'static str,
        /// Argument name.
        field: &'static str,
    },
    /// The same log position was supplied twice with different contents.
    #[error("log {block}:{log_index} was supplied twice with different contents")]
    ConflictingLogs {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
    },
    /// A leaf arrived out of sequence: logs are missing or from another fork.
    #[error("log {block}:{log_index}: leaf {found} inserted where leaf {expected} is next")]
    LeafOutOfOrder {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Position the log names.
        found: u64,
        /// Position this indexer expects.
        expected: u64,
    },
    /// The root in the log differs from the one this indexer computes over its leaves.
    #[error(
        "log {block}:{log_index}: root after leaf {leaf_index} differs from the recomputed root"
    )]
    RootMismatch {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Position of the leaf.
        leaf_index: u64,
    },
    /// A leaf was inserted and no event this build can read says what it is.
    #[error("leaf {leaf_index} inserted at {block}:{log_index} has no describing event")]
    UnpairedLeaf {
        /// Block of the `LeafInserted` log.
        block: u64,
        /// Index of that log in its block.
        log_index: u64,
        /// Position of the leaf.
        leaf_index: u64,
    },
    /// A describing event without the insertion it should follow, or disagreeing with it.
    #[error("log {block}:{log_index}: {event} does not match the insertion before it ({reason})")]
    PairMismatch {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// Event name.
        event: &'static str,
        /// What disagreed.
        reason: &'static str,
    },
    /// Leaf 0 is not the genesis leaf of the configured chain.
    #[error(
        "log {block}:{log_index}: genesis does not match the configured deployment ({reason})"
    )]
    GenesisMismatch {
        /// Block of the log.
        block: u64,
        /// Index of the log in its block.
        log_index: u64,
        /// What disagreed.
        reason: &'static str,
    },
    /// The batch leaves a different leaf count than the pool reports at the final block.
    #[error("batch ends at {indexed} leaves and the pool reports {chain}")]
    LeafCountMismatch {
        /// Leaves this indexer would hold.
        indexed: u64,
        /// The pool's `nextLeafIndex` at the final block.
        chain: u64,
    },
    /// The tree holds its full `2^32` leaves.
    #[error("the tree is full")]
    TreeFull,
    /// A checkpoint that is not one this crate produced.
    #[error("checkpoint does not reproduce its own root")]
    BadCheckpoint,
}

/// Which pool to read, and how far behind the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexerConfig {
    /// Chain the pool is deployed on. Checked against the genesis leaf.
    pub chain_id: u64,
    /// The pool's address. Logs from any other address are ignored.
    pub pool: [u8; 20],
    /// Block the pool was deployed in, where a fresh index starts reading.
    pub deployment_block: u64,
    /// Blocks a log must sit below the head before it is read. A row is final once
    /// written, so set this to a depth the chain does not reorganise past.
    pub finality_depth: u64,
}

/// One position of the tree, in the three forms a discovery server keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// Position in the tree, and the row of the discovery table.
    pub leaf_index: u32,
    /// The tree leaf.
    pub commitment: [u8; 32],
    /// The discovery tag the note is filed under. `None` for the genesis leaf.
    pub tag: Option<[u8; 32]>,
    /// The `howl-note-v1` cell. All zero for the genesis leaf, which no decoder accepts.
    pub cell: [u8; CELL_BYTES],
}

/// Where an indexer stands. Enough to resume it and to state the tree's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Leaves indexed so far.
    pub leaf_count: u64,
    /// Highest block fully read, if any.
    pub final_block: Option<u64>,
    /// Tree root after the last leaf.
    pub root: [u8; 32],
    /// The tree's pending left nodes, one per level.
    pub frontier: [[u8; 32]; TREE_DEPTH],
}

/// What one [`Indexer::ingest`] call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// New leaves, in position order, starting where the previous batch ended.
    pub leaves: Vec<Leaf>,
    /// The indexer's position after this batch.
    pub checkpoint: Checkpoint,
    /// Pool logs above the finality line, left for a later call.
    pub held_back: usize,
}

/// Reads pool logs in order and yields the leaf stream.
#[derive(Debug, Clone)]
pub struct Indexer {
    config: IndexerConfig,
    tree: Frontier,
    final_block: Option<u64>,
}

#[derive(Clone, Copy)]
struct At {
    block: u64,
    log_index: u64,
}

struct Inserted {
    at: At,
    leaf_index: u64,
    leaf: [u8; 32],
}

impl Indexer {
    /// Start from an empty tree.
    #[must_use]
    pub fn new(config: IndexerConfig) -> Self {
        Self {
            config,
            tree: Frontier::empty(),
            final_block: None,
        }
    }

    /// Continue from a checkpoint an earlier indexer returned.
    ///
    /// # Errors
    /// [`IndexError::BadCheckpoint`] when the frontier does not reproduce the root.
    pub fn resume(config: IndexerConfig, checkpoint: &Checkpoint) -> Result<Self, IndexError> {
        let tree = Frontier::restore(
            &checkpoint.frontier,
            checkpoint.leaf_count,
            &checkpoint.root,
        )
        .ok_or(IndexError::BadCheckpoint)?;
        Ok(Self {
            config,
            tree,
            final_block: checkpoint.final_block,
        })
    }

    /// The indexer's current position.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            leaf_count: self.tree.leaves(),
            final_block: self.final_block,
            root: self.tree.root(),
            frontier: self.tree.side(),
        }
    }

    /// First block the next [`Indexer::ingest`] call needs logs from.
    #[must_use]
    pub fn next_block(&self) -> u64 {
        self.final_block
            .map_or(self.config.deployment_block, |block| {
                block.saturating_add(1)
            })
    }

    /// Read every final block up to `head - finality_depth`.
    ///
    /// `logs` must hold every pool log from [`Indexer::next_block`] to that block; order
    /// and duplicates do not matter, and logs outside the range are left alone.
    /// `chain_leaf_count` is the pool's `nextLeafIndex` read at that same block: when given,
    /// a batch that ends on any other count is refused, which catches a log source that
    /// dropped the tail of the range.
    ///
    /// # Errors
    /// See [`IndexError`]. A refused batch leaves the indexer exactly where it was.
    pub fn ingest(
        &mut self,
        head: u64,
        logs: &[RawLog],
        chain_leaf_count: Option<u64>,
    ) -> Result<Batch, IndexError> {
        let pool = self.config.pool;
        let from = self.next_block();
        let final_block = head
            .checked_sub(self.config.finality_depth)
            .filter(|block| *block >= from);
        let unread = final_block.map_or(from, |block| block.saturating_add(1));
        let held_back = logs
            .iter()
            .filter(|log| log.address == pool && log.block_number >= unread)
            .count();
        let Some(final_block) = final_block else {
            return Ok(Batch {
                leaves: Vec::new(),
                checkpoint: self.checkpoint(),
                held_back,
            });
        };

        let mut selected: Vec<&RawLog> = logs
            .iter()
            .filter(|log| log.address == pool && (from..=final_block).contains(&log.block_number))
            .collect();
        selected.sort_by_key(|log| (log.block_number, log.log_index));

        let mut tree = self.tree.clone();
        let mut leaves = Vec::new();
        let mut pending: Option<Inserted> = None;
        let mut previous: Option<&RawLog> = None;
        for log in selected {
            if let Some(seen) = previous {
                if (seen.block_number, seen.log_index) == (log.block_number, log.log_index) {
                    if seen == log {
                        continue;
                    }
                    return Err(IndexError::ConflictingLogs {
                        block: log.block_number,
                        log_index: log.log_index,
                    });
                }
            }
            previous = Some(log);
            let at = At {
                block: log.block_number,
                log_index: log.log_index,
            };
            match decode(log)? {
                None => {}
                Some(PoolEvent::LeafInserted {
                    leaf_index,
                    leaf,
                    new_root,
                }) => {
                    if let Some(orphan) = pending.take() {
                        return Err(unpaired(&orphan));
                    }
                    insert(&mut tree, at, leaf_index, &leaf, &new_root)?;
                    pending = Some(Inserted {
                        at,
                        leaf_index,
                        leaf,
                    });
                }
                Some(event) => {
                    let inserted = pending.take().ok_or(IndexError::PairMismatch {
                        block: at.block,
                        log_index: at.log_index,
                        event: event.name(),
                        reason: "no insertion precedes it",
                    })?;
                    leaves.push(self.describe(at, &inserted, &event)?);
                }
            }
        }
        if let Some(orphan) = pending {
            return Err(unpaired(&orphan));
        }
        if let Some(chain) = chain_leaf_count {
            if chain != tree.leaves() {
                return Err(IndexError::LeafCountMismatch {
                    indexed: tree.leaves(),
                    chain,
                });
            }
        }

        self.tree = tree;
        self.final_block = Some(final_block);
        Ok(Batch {
            leaves,
            checkpoint: self.checkpoint(),
            held_back,
        })
    }

    fn describe(&self, at: At, inserted: &Inserted, event: &PoolEvent) -> Result<Leaf, IndexError> {
        let name = event.name();
        let mismatch = |reason| IndexError::PairMismatch {
            block: at.block,
            log_index: at.log_index,
            event: name,
            reason,
        };
        let genesis = |reason| IndexError::GenesisMismatch {
            block: at.block,
            log_index: at.log_index,
            reason,
        };
        let leaf_index = u32::try_from(inserted.leaf_index).map_err(|_| IndexError::TreeFull)?;
        let scalar = |bytes: &[u8; 32], field| {
            canonical(bytes).ok_or(IndexError::NonCanonicalField {
                block: at.block,
                log_index: at.log_index,
                event: name,
                field,
            })
        };

        let (described_index, commitment, tag, tag_field, kind, ephemeral, cek_wrap, ciphertext) =
            match event {
                PoolEvent::LeafInserted { .. } => return Err(unpaired(inserted)),
                PoolEvent::GenesisSeeded {
                    chain_id,
                    genesis_leaf: leaf,
                } => {
                    if inserted.leaf_index != 0 {
                        return Err(genesis("it is not leaf 0"));
                    }
                    if *chain_id != self.config.chain_id {
                        return Err(genesis("another chain id"));
                    }
                    if *leaf != inserted.leaf || *leaf != genesis_leaf(self.config.chain_id) {
                        return Err(genesis("another genesis leaf"));
                    }
                    return Ok(Leaf {
                        leaf_index,
                        commitment: *leaf,
                        tag: None,
                        cell: [0u8; CELL_BYTES],
                    });
                }
                PoolEvent::NewNote {
                    leaf_index,
                    commitment,
                    ephemeral_pk_x,
                    packed_ciphertext,
                } => (
                    *leaf_index,
                    commitment,
                    ephemeral_pk_x,
                    "ephemeralPK_x",
                    RECORD_KIND_SELF,
                    Fr::from(0u64),
                    Fr::from(0u64),
                    packed_ciphertext,
                ),
                PoolEvent::NewPrivateMemo {
                    leaf_index,
                    commitment,
                    tag,
                    ephemeral_pk_x,
                    cek_wrap,
                    packed_ciphertext,
                } => (
                    *leaf_index,
                    commitment,
                    tag,
                    "tag",
                    RECORD_KIND_INCOMING,
                    scalar(ephemeral_pk_x, "ephemeralPK_x")?,
                    scalar(cek_wrap, "cekWrap")?,
                    packed_ciphertext,
                ),
            };
        if inserted.leaf_index == 0 {
            return Err(genesis("leaf 0 is a note"));
        }
        if described_index != inserted.leaf_index {
            return Err(mismatch("another leaf index"));
        }
        if *commitment != inserted.leaf {
            return Err(mismatch("another commitment"));
        }
        scalar(tag, tag_field)?;

        let mut ciphertext_kept = [Fr::from(0u64); CIPHERTEXT_KEPT_INDICES.len()];
        for (slot, index) in ciphertext_kept.iter_mut().zip(CIPHERTEXT_KEPT_INDICES) {
            let word = ciphertext
                .get(index)
                .ok_or_else(|| mismatch("ciphertext width"))?;
            *slot = scalar(word, "packedCiphertext")?;
        }
        let mut commitment_prefix = [0u8; COMMITMENT_PREFIX_BYTES];
        if let Some(head) = commitment.get(..COMMITMENT_PREFIX_BYTES) {
            commitment_prefix.copy_from_slice(head);
        }
        Ok(Leaf {
            leaf_index,
            commitment: *commitment,
            tag: Some(*tag),
            cell: encode(&HowlNoteRecord {
                layout_version: LAYOUT_VERSION,
                record_kind: kind,
                leaf_index,
                commitment_prefix,
                ephemeral_pk_x: ephemeral,
                cek_wrap,
                ciphertext_kept,
            }),
        })
    }
}

fn unpaired(orphan: &Inserted) -> IndexError {
    IndexError::UnpairedLeaf {
        block: orphan.at.block,
        log_index: orphan.at.log_index,
        leaf_index: orphan.leaf_index,
    }
}

fn insert(
    tree: &mut Frontier,
    at: At,
    leaf_index: u64,
    leaf: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<(), IndexError> {
    if leaf_index != tree.leaves() {
        return Err(IndexError::LeafOutOfOrder {
            block: at.block,
            log_index: at.log_index,
            found: leaf_index,
            expected: tree.leaves(),
        });
    }
    let scalar = canonical(leaf).ok_or(IndexError::NonCanonicalField {
        block: at.block,
        log_index: at.log_index,
        event: "LeafInserted",
        field: "leaf",
    })?;
    let root = tree.insert(scalar).ok_or(IndexError::TreeFull)?;
    if root != *new_root {
        return Err(IndexError::RootMismatch {
            block: at.block,
            log_index: at.log_index,
            leaf_index,
        });
    }
    Ok(())
}
