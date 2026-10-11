//! The four pool events that describe a tree insertion, decoded from raw logs.

use crate::IndexError;

/// `keccak256("LeafInserted(uint256,bytes32,bytes32)")`.
pub const TOPIC_LEAF_INSERTED: [u8; 32] = [
    0x2d, 0x3c, 0x13, 0xae, 0x44, 0x99, 0x47, 0xe0, 0x40, 0x70, 0xbf, 0x2a, 0xc8, 0x93, 0x27, 0xdc,
    0x1f, 0xc5, 0x6f, 0x31, 0x04, 0x21, 0x72, 0xf3, 0xc9, 0xfd, 0xce, 0xb8, 0xf5, 0x1c, 0x90, 0xe6,
];

/// `keccak256("NewNote(uint256,bytes32,uint256,bytes32[7])")`.
pub const TOPIC_NEW_NOTE: [u8; 32] = [
    0xf9, 0x08, 0xf5, 0x9e, 0x72, 0xbf, 0x09, 0x16, 0x79, 0x99, 0x00, 0x4b, 0xbf, 0xe8, 0x49, 0xfd,
    0x50, 0x79, 0x52, 0xd0, 0x65, 0x81, 0xf7, 0xe7, 0x01, 0x34, 0x58, 0x84, 0x58, 0x70, 0x08, 0x54,
];

/// `keccak256("NewPrivateMemo(uint256,bytes32,uint256,uint256,uint256,bytes32[7])")`.
pub const TOPIC_NEW_PRIVATE_MEMO: [u8; 32] = [
    0x7a, 0x20, 0x2c, 0x1f, 0x60, 0x29, 0xa8, 0xf7, 0x36, 0xab, 0x7b, 0xb5, 0xda, 0x53, 0xa4, 0x93,
    0x0c, 0x10, 0xcc, 0xb3, 0x5e, 0xff, 0xa9, 0x88, 0x1e, 0xce, 0x38, 0x9a, 0xd9, 0xbd, 0x25, 0x44,
];

/// `keccak256("GenesisSeeded(uint256,bytes32)")`.
pub const TOPIC_GENESIS_SEEDED: [u8; 32] = [
    0x70, 0x7c, 0x82, 0x9c, 0x96, 0x89, 0xeb, 0x6b, 0x77, 0x4d, 0xdf, 0x74, 0x79, 0xad, 0x4c, 0x49,
    0x45, 0x81, 0xc7, 0xb5, 0xb3, 0x62, 0x37, 0xf8, 0x07, 0x38, 0x89, 0x5c, 0x01, 0x61, 0x66, 0xd9,
];

/// Words in the on-chain note ciphertext.
pub const CIPHERTEXT_WORDS: usize = 7;

const WORD: usize = 32;

/// One EVM log, as `eth_getLogs` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLog {
    /// Block the log was emitted in.
    pub block_number: u64,
    /// Position of the log inside that block.
    pub log_index: u64,
    /// Emitting contract.
    pub address: [u8; 20],
    /// Indexed arguments, signature hash first.
    pub topics: Vec<[u8; 32]>,
    /// ABI-encoded unindexed arguments.
    pub data: Vec<u8>,
}

/// A pool event that takes part in a tree insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
    /// The tree accepted a leaf. Emitted by every insertion, immediately before the event
    /// that says what the leaf is.
    LeafInserted {
        /// Position the tree assigned.
        leaf_index: u64,
        /// The inserted leaf.
        leaf: [u8; 32],
        /// Tree root after the insertion.
        new_root: [u8; 32],
    },
    /// Leaf 0, seeded when the pool was initialised.
    GenesisSeeded {
        /// Chain the pool is deployed on.
        chain_id: u64,
        /// The genesis leaf.
        genesis_leaf: [u8; 32],
    },
    /// A note its owner files under an ephemeral key of its own.
    NewNote {
        /// Position the tree assigned.
        leaf_index: u64,
        /// The note commitment.
        commitment: [u8; 32],
        /// The discovery tag of a self note.
        ephemeral_pk_x: [u8; 32],
        /// The note ciphertext as posted.
        packed_ciphertext: [[u8; 32]; CIPHERTEXT_WORDS],
    },
    /// A note addressed to a recipient's discovery tag.
    NewPrivateMemo {
        /// Position the tree assigned.
        leaf_index: u64,
        /// The note commitment.
        commitment: [u8; 32],
        /// The recipient's discovery tag.
        tag: [u8; 32],
        /// Sender's ephemeral key.
        ephemeral_pk_x: [u8; 32],
        /// The wrapped content key.
        cek_wrap: [u8; 32],
        /// The note ciphertext as posted.
        packed_ciphertext: [[u8; 32]; CIPHERTEXT_WORDS],
    },
}

impl PoolEvent {
    /// Solidity name of the event.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::LeafInserted { .. } => "LeafInserted",
            Self::GenesisSeeded { .. } => "GenesisSeeded",
            Self::NewNote { .. } => "NewNote",
            Self::NewPrivateMemo { .. } => "NewPrivateMemo",
        }
    }
}

struct Shape<'a> {
    log: &'a RawLog,
    event: &'static str,
}

impl Shape<'_> {
    /// A recognised signature with any other shape means the ABI moved under this build, so
    /// it stops the indexer instead of yielding a cell cut at the wrong offsets.
    fn check(&self, topics: usize, data_words: usize) -> Result<(), IndexError> {
        let malformed = |what, found, expected| IndexError::MalformedEvent {
            block: self.log.block_number,
            log_index: self.log.log_index,
            event: self.event,
            what,
            found,
            expected,
        };
        if self.log.topics.len() != topics {
            return Err(malformed("topics", self.log.topics.len(), topics));
        }
        if self.log.data.len() != data_words * WORD {
            return Err(malformed(
                "data bytes",
                self.log.data.len(),
                data_words * WORD,
            ));
        }
        Ok(())
    }

    fn topic(&self, index: usize) -> [u8; 32] {
        self.log.topics.get(index).copied().unwrap_or_default()
    }

    fn word(&self, index: usize) -> [u8; 32] {
        let mut out = [0u8; WORD];
        if let Some(src) = self.log.data.get(index * WORD..(index + 1) * WORD) {
            out.copy_from_slice(src);
        }
        out
    }

    fn ciphertext(&self, first_word: usize) -> [[u8; 32]; CIPHERTEXT_WORDS] {
        let mut out = [[0u8; WORD]; CIPHERTEXT_WORDS];
        for (offset, slot) in out.iter_mut().enumerate() {
            *slot = self.word(first_word + offset);
        }
        out
    }

    fn uint64(&self, word: [u8; 32], field: &'static str) -> Result<u64, IndexError> {
        let (high, low) = word.split_at(WORD - 8);
        let mut tail = [0u8; 8];
        tail.copy_from_slice(low);
        if high.iter().any(|byte| *byte != 0) {
            return Err(IndexError::ValueOutOfRange {
                block: self.log.block_number,
                log_index: self.log.log_index,
                event: self.event,
                field,
            });
        }
        Ok(u64::from_be_bytes(tail))
    }
}

/// Decode one log. `Ok(None)` is a log with any other signature.
///
/// # Errors
/// [`IndexError::MalformedEvent`] when a recognised signature carries a different number of
/// topics or data bytes, and [`IndexError::ValueOutOfRange`] when an integer argument
/// exceeds 64 bits.
///
/// # Examples
/// ```
/// use howl_indexer::{decode, RawLog};
/// let other = RawLog {
///     block_number: 1,
///     log_index: 0,
///     address: [0u8; 20],
///     topics: vec![[0xaa; 32]],
///     data: Vec::new(),
/// };
/// assert_eq!(decode(&other), Ok(None));
/// ```
pub fn decode(log: &RawLog) -> Result<Option<PoolEvent>, IndexError> {
    let Some(signature) = log.topics.first() else {
        return Ok(None);
    };
    let shape = |event| Shape { log, event };
    let event = match *signature {
        TOPIC_LEAF_INSERTED => {
            let s = shape("LeafInserted");
            s.check(2, 2)?;
            PoolEvent::LeafInserted {
                leaf_index: s.uint64(s.topic(1), "leafIndex")?,
                leaf: s.word(0),
                new_root: s.word(1),
            }
        }
        TOPIC_GENESIS_SEEDED => {
            let s = shape("GenesisSeeded");
            s.check(2, 1)?;
            PoolEvent::GenesisSeeded {
                chain_id: s.uint64(s.topic(1), "chainId")?,
                genesis_leaf: s.word(0),
            }
        }
        TOPIC_NEW_NOTE => {
            let s = shape("NewNote");
            s.check(3, 1 + CIPHERTEXT_WORDS)?;
            PoolEvent::NewNote {
                leaf_index: s.uint64(s.topic(1), "leafIndex")?,
                commitment: s.topic(2),
                ephemeral_pk_x: s.word(0),
                packed_ciphertext: s.ciphertext(1),
            }
        }
        TOPIC_NEW_PRIVATE_MEMO => {
            let s = shape("NewPrivateMemo");
            s.check(4, 2 + CIPHERTEXT_WORDS)?;
            PoolEvent::NewPrivateMemo {
                leaf_index: s.uint64(s.topic(1), "leafIndex")?,
                commitment: s.topic(2),
                tag: s.topic(3),
                ephemeral_pk_x: s.word(0),
                cek_wrap: s.word(1),
                packed_ciphertext: s.ciphertext(2),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(event))
}
