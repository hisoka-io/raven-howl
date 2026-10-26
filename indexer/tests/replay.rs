//! Replays a chain of pool logs and compares every leaf with what Howl's own code produces.
//!
//! The logs were ABI-encoded by ethers from the compiled pool; the expected tags, cells and
//! roots come from Howl's key derivation, record encoder and tree. Nothing on the expected
//! side was computed by this crate.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use howl_indexer::{
    genesis_leaf, Batch, IndexError, Indexer, Leaf, RawLog, TOPIC_GENESIS_SEEDED,
    TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO,
};
use sha3::{Digest, Keccak256};
use support::{Fixture, Rng};

fn replay_once(fixture: &Fixture) -> Batch {
    Indexer::new(fixture.config(0))
        .ingest(fixture.head, &fixture.logs, Some(fixture.leaf_count))
        .expect("the fixture chain indexes")
}

fn is(log: &RawLog, topic: [u8; 32], pool: [u8; 20]) -> bool {
    log.address == pool && log.topics.first() == Some(&topic)
}

/// Position, in `logs`, of the `nth` pool log with `topic`.
fn find(fixture: &Fixture, topic: [u8; 32], nth: usize) -> usize {
    fixture
        .logs
        .iter()
        .enumerate()
        .filter(|(_, log)| is(log, topic, fixture.pool))
        .nth(nth)
        .expect("fixture holds enough of that event")
        .0
}

fn refused(fixture: &Fixture, logs: &[RawLog]) -> IndexError {
    Indexer::new(fixture.config(0))
        .ingest(fixture.head, logs, None)
        .expect_err("the altered chain must be refused")
}

#[test]
fn signature_hashes_are_the_keccak_of_the_abi_signatures() {
    let keccak = |text: &str| -> [u8; 32] { Keccak256::digest(text.as_bytes()).into() };
    assert_eq!(
        TOPIC_LEAF_INSERTED,
        keccak("LeafInserted(uint256,bytes32,bytes32)")
    );
    assert_eq!(
        TOPIC_GENESIS_SEEDED,
        keccak("GenesisSeeded(uint256,bytes32)")
    );
    assert_eq!(
        TOPIC_NEW_NOTE,
        keccak("NewNote(uint256,bytes32,uint256,bytes32[7])")
    );
    assert_eq!(
        TOPIC_NEW_PRIVATE_MEMO,
        keccak("NewPrivateMemo(uint256,bytes32,uint256,uint256,uint256,bytes32[7])")
    );

    // And they are the hashes the compiled pool ABI yields.
    let fixture = Fixture::load();
    for (name, topic) in [
        ("LeafInserted", TOPIC_LEAF_INSERTED),
        ("GenesisSeeded", TOPIC_GENESIS_SEEDED),
        ("NewNote", TOPIC_NEW_NOTE),
        ("NewPrivateMemo", TOPIC_NEW_PRIVATE_MEMO),
    ] {
        assert_eq!(
            support::word(fixture.topics[name].as_str().expect("topic")),
            topic,
            "{name}"
        );
    }
}

#[test]
fn the_genesis_leaf_is_howls() {
    let fixture = Fixture::load();
    assert_eq!(genesis_leaf(fixture.chain_id), fixture.leaves[0].commitment);
}

#[test]
fn the_chain_replays_to_the_table_howl_computes() {
    let fixture = Fixture::load();
    let batch = replay_once(&fixture);

    assert_eq!(batch.leaves.len(), fixture.leaves.len());
    assert_eq!(batch.leaves.len() as u64, fixture.leaf_count);
    for (position, (leaf, expected)) in batch.leaves.iter().zip(&fixture.leaves).enumerate() {
        assert_eq!(
            leaf.leaf_index as usize, position,
            "row is the tree position"
        );
        assert_eq!(leaf.leaf_index, expected.leaf_index);
        assert_eq!(leaf.commitment, expected.commitment, "leaf {position}");
        assert_eq!(leaf.tag, expected.tag, "leaf {position}");
        match &expected.cell {
            Some(cell) => assert_eq!(leaf.cell.as_slice(), cell.as_slice(), "leaf {position}"),
            None => assert!(leaf.cell.iter().all(|byte| *byte == 0), "genesis cell"),
        }
    }
    // The root commits to every leaf and its order, and the pool computed it.
    assert_eq!(batch.checkpoint.root, fixture.root);
    assert_eq!(batch.checkpoint.leaf_count, fixture.leaf_count);
    assert_eq!(batch.checkpoint.final_block, Some(fixture.head));
    assert_eq!(batch.held_back, 0);
}

#[test]
fn every_note_cell_decodes_and_the_genesis_cell_does_not() {
    let fixture = Fixture::load();
    let batch = replay_once(&fixture);
    let (genesis, notes) = batch.leaves.split_first().expect("leaves");
    assert!(howl_record::decode(&genesis.cell).is_err());
    for leaf in notes {
        let record = howl_record::decode(&leaf.cell).expect("note cell decodes");
        assert_eq!(record.leaf_index, leaf.leaf_index);
        assert_eq!(record.commitment_prefix, leaf.commitment[..16]);
    }
}

#[test]
fn a_replay_is_the_same_table_however_the_logs_are_split() {
    let fixture = Fixture::load();
    let whole = replay_once(&fixture);
    assert_eq!(replay_once(&fixture), whole, "a second replay differs");

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..24 {
        let mut logs = fixture.logs.clone();
        // Shuffled, and with a third of the logs supplied twice.
        for i in (1..logs.len()).rev() {
            logs.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let repeats: Vec<RawLog> = logs.iter().step_by(3).cloned().collect();
        logs.extend(repeats);

        let mut indexer = Indexer::new(fixture.config(0));
        let mut leaves: Vec<Leaf> = Vec::new();
        let mut head = fixture.first_block.saturating_sub(2);
        while head < fixture.head {
            head = (head + 1 + rng.below(9)).min(fixture.head);
            // Every call sees every log: the indexer takes only its own range.
            let batch = indexer.ingest(head, &logs, None).expect("split replay");
            assert_eq!(
                batch.leaves.first().map(|leaf| leaf.leaf_index as usize),
                (!batch.leaves.is_empty()).then_some(leaves.len()),
                "a batch starts where the last one ended"
            );
            leaves.extend(batch.leaves);
        }
        assert_eq!(leaves, whole.leaves, "round {round}");
        assert_eq!(indexer.checkpoint(), whole.checkpoint, "round {round}");
    }
}

/// The pool writes `RootSaved` right before every `LeafInserted`. A stream that carries it, as
/// an unfiltered read of the pool's address does, indexes to the same table.
#[test]
fn the_root_saved_log_before_every_insert_changes_nothing() {
    let fixture = Fixture::load();
    let whole = replay_once(&fixture);
    let root_saved: [u8; 32] = Keccak256::digest(b"RootSaved(bytes32)").into();
    let mut logs = Vec::new();
    for log in &fixture.logs {
        let mut log = log.clone();
        log.log_index = log.log_index * 2 + 1;
        if is(&log, TOPIC_LEAF_INSERTED, fixture.pool) {
            let mut new_root = [0u8; 32];
            new_root.copy_from_slice(&log.data[32..64]);
            logs.push(RawLog {
                log_index: log.log_index - 1,
                topics: vec![root_saved, new_root],
                data: Vec::new(),
                ..log.clone()
            });
        }
        logs.push(log);
    }
    assert!(logs.len() > fixture.logs.len(), "no RootSaved was added");
    let batch = Indexer::new(fixture.config(0))
        .ingest(fixture.head, &logs, Some(fixture.leaf_count))
        .expect("the stream with RootSaved indexes");
    assert_eq!(batch.leaves, whole.leaves);
    assert_eq!(batch.checkpoint.root, whole.checkpoint.root);
    assert_eq!(batch.checkpoint.leaf_count, whole.checkpoint.leaf_count);
}

#[test]
fn only_blocks_below_the_finality_line_are_read() {
    let fixture = Fixture::load();
    let whole = replay_once(&fixture);
    let depth = 12;

    // What sits above the line is another fork's: unreadable, and never read.
    let fork = |final_block: u64| -> Vec<RawLog> {
        fixture
            .logs
            .iter()
            .cloned()
            .map(|mut log| {
                if log.block_number > final_block {
                    log.data.iter_mut().for_each(|byte| *byte ^= 0x5a);
                }
                log
            })
            .collect()
    };

    let mut indexer = Indexer::new(fixture.config(depth));
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut held_back = 0;
    for head in (fixture.first_block..=fixture.head + depth).step_by(7) {
        let final_block = head.saturating_sub(depth);
        let batch = indexer
            .ingest(head, &fork(final_block), None)
            .expect("blocks under the line index");
        held_back += batch.held_back;
        leaves.extend(batch.leaves);

        let expected = (final_block >= fixture.first_block).then_some(final_block);
        assert_eq!(indexer.checkpoint().final_block, expected);
        let read_through = fixture
            .logs
            .iter()
            .filter(|log| {
                is(log, TOPIC_LEAF_INSERTED, fixture.pool) && log.block_number <= final_block
            })
            .count();
        assert_eq!(
            leaves.len(),
            read_through,
            "head {head}: leaves from blocks above the line"
        );
    }
    assert!(held_back > 0, "the walk never met a held-back log");

    let batch = indexer
        .ingest(fixture.head + depth, &fixture.logs, None)
        .expect("the rest");
    leaves.extend(batch.leaves);
    assert_eq!(leaves, whole.leaves);
    assert_eq!(indexer.checkpoint().root, fixture.root);
}

#[test]
fn an_indexer_resumed_from_a_checkpoint_continues_identically() {
    let fixture = Fixture::load();
    let whole = replay_once(&fixture);
    let middle = fixture.first_block + (fixture.head - fixture.first_block) / 2;

    let mut first = Indexer::new(fixture.config(0));
    let mut leaves = first
        .ingest(middle, &fixture.logs, None)
        .expect("first half")
        .leaves;
    let checkpoint = first.checkpoint();
    assert!(checkpoint.leaf_count > 1 && checkpoint.leaf_count < fixture.leaf_count);

    let mut second = Indexer::resume(fixture.config(0), &checkpoint).expect("resume");
    assert_eq!(second.next_block(), middle + 1);
    leaves.extend(
        second
            .ingest(fixture.head, &fixture.logs, Some(fixture.leaf_count))
            .expect("second half")
            .leaves,
    );
    assert_eq!(leaves, whole.leaves);
    assert_eq!(second.checkpoint(), whole.checkpoint);

    let mut damaged = checkpoint;
    damaged.leaf_count += 1;
    assert_eq!(
        Indexer::resume(fixture.config(0), &damaged).err(),
        Some(IndexError::BadCheckpoint)
    );
}

#[test]
fn a_leaf_with_no_readable_describing_event_stops_the_indexer() {
    let fixture = Fixture::load();

    // The describing event is missing.
    let mut logs = fixture.logs.clone();
    logs.remove(find(&fixture, TOPIC_NEW_NOTE, 5));
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::UnpairedLeaf { .. }
    ));

    // The ciphertext grew a word: a new signature, which this build does not read.
    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_NEW_NOTE, 5);
    logs[at].topics[0] = Keccak256::digest(b"NewNote(uint256,bytes32,uint256,bytes32[8])").into();
    logs[at].data.extend_from_slice(&[0u8; 32]);
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::UnpairedLeaf { .. }
    ));

    // The same on the last leaf of the range, where nothing follows to expose it.
    let mut logs = fixture.logs.clone();
    let last = fixture.leaf_count as usize - 1;
    let at = logs
        .iter()
        .rposition(|log| {
            is(log, TOPIC_NEW_NOTE, fixture.pool) || is(log, TOPIC_NEW_PRIVATE_MEMO, fixture.pool)
        })
        .expect("a note");
    logs.remove(at);
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::UnpairedLeaf { leaf_index, .. } if leaf_index as usize == last
    ));
}

#[test]
fn a_recognised_event_of_another_width_is_refused() {
    let fixture = Fixture::load();
    for (topic, expected) in [(TOPIC_NEW_NOTE, 256), (TOPIC_NEW_PRIVATE_MEMO, 288)] {
        for delta in [-32i64, 32] {
            let mut logs = fixture.logs.clone();
            let at = find(&fixture, topic, 2);
            let len = (logs[at].data.len() as i64 + delta) as usize;
            logs[at].data.resize(len, 0);
            assert_eq!(
                refused(&fixture, &logs),
                IndexError::MalformedEvent {
                    block: logs[at].block_number,
                    log_index: logs[at].log_index,
                    event: if topic == TOPIC_NEW_NOTE {
                        "NewNote"
                    } else {
                        "NewPrivateMemo"
                    },
                    what: "data bytes",
                    found: len,
                    expected,
                }
            );
        }
    }

    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_NEW_PRIVATE_MEMO, 0);
    logs[at].topics.pop();
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::MalformedEvent {
            what: "topics",
            found: 3,
            expected: 4,
            ..
        }
    ));
}

#[test]
fn missing_reordered_or_altered_leaves_are_refused() {
    let fixture = Fixture::load();

    // A whole insertion is missing.
    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_LEAF_INSERTED, 40);
    logs.drain(at..=at + 1);
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::LeafOutOfOrder {
            found: 41,
            expected: 40,
            ..
        }
    ));

    // The insertion is missing and its describing event is not.
    let mut logs = fixture.logs.clone();
    logs.remove(find(&fixture, TOPIC_LEAF_INSERTED, 40));
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::PairMismatch {
            reason: "no insertion precedes it",
            ..
        }
    ));

    // A leaf differs from the one the pool hashed into its root.
    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_LEAF_INSERTED, 40);
    logs[at].data[31] ^= 1;
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::RootMismatch { leaf_index: 40, .. }
    ));

    // The describing event names another commitment than the inserted leaf.
    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_NEW_NOTE, 7);
    logs[at].topics[2][31] ^= 1;
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::PairMismatch {
            reason: "another commitment",
            ..
        }
    ));

    // Two describing events trade places.
    let mut logs = fixture.logs.clone();
    let (a, b) = (
        find(&fixture, TOPIC_NEW_NOTE, 7),
        find(&fixture, TOPIC_NEW_NOTE, 8),
    );
    let (topics, data) = (logs[a].topics.clone(), logs[a].data.clone());
    logs[a].topics = logs[b].topics.clone();
    logs[a].data = logs[b].data.clone();
    logs[b].topics = topics;
    logs[b].data = data;
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::PairMismatch {
            reason: "another leaf index",
            ..
        }
    ));
}

#[test]
fn a_field_at_or_above_the_modulus_is_refused() {
    let fixture = Fixture::load();
    let modulus =
        support::word("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_NEW_PRIVATE_MEMO, 1);
    logs[at].topics[3] = modulus;
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::NonCanonicalField {
            event: "NewPrivateMemo",
            field: "tag",
            ..
        }
    ));

    // Word 1 of the ciphertext is kept; word 0 is not stored and is not read.
    let mut logs = fixture.logs.clone();
    let at = find(&fixture, TOPIC_NEW_NOTE, 1);
    logs[at].data[64..96].copy_from_slice(&modulus);
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::NonCanonicalField {
            field: "packedCiphertext",
            ..
        }
    ));
}

#[test]
fn logs_of_another_deployment_are_ignored_and_would_not_pass_as_the_pools() {
    let fixture = Fixture::load();
    let foreign = fixture
        .logs
        .iter()
        .filter(|log| log.address != fixture.pool)
        .count();
    assert!(foreign > 0, "the fixture holds no foreign logs");
    replay_once(&fixture);

    let mut logs = fixture.logs.clone();
    for log in &mut logs {
        log.address = fixture.pool;
    }
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::RootMismatch { .. }
    ));
}

#[test]
fn the_genesis_leaf_binds_the_configured_chain() {
    let fixture = Fixture::load();
    let mut config = fixture.config(0);
    config.chain_id += 1;
    assert!(matches!(
        Indexer::new(config).ingest(fixture.head, &fixture.logs, None),
        Err(IndexError::GenesisMismatch {
            reason: "another chain id",
            ..
        })
    ));

    // A pool seeded with another genesis leaf under this chain id. The insertion and the
    // seeding event agree with each other and with the root, so only the leaf's value
    // tells. Then each of the two naming a leaf the other does not.
    let foreign = genesis_leaf(fixture.chain_id + 1);
    assert_ne!(foreign, fixture.leaves[0].commitment);
    let inserted = find(&fixture, TOPIC_LEAF_INSERTED, 0);
    let seeded = find(&fixture, TOPIC_GENESIS_SEEDED, 0);
    for (in_insertion, in_seeding) in [(true, true), (false, true), (true, false)] {
        let mut logs = fixture.logs.clone();
        if in_insertion {
            logs[inserted].data = [foreign, foreign].concat();
        }
        if in_seeding {
            logs[seeded].data = foreign.to_vec();
        }
        assert!(
            matches!(
                refused(&fixture, &logs),
                IndexError::GenesisMismatch {
                    reason: "another genesis leaf",
                    ..
                }
            ),
            "insertion altered: {in_insertion}, seeding altered: {in_seeding}"
        );
    }

    // A note where the genesis leaf belongs.
    let mut logs = fixture.logs.clone();
    let genesis = find(&fixture, TOPIC_GENESIS_SEEDED, 0);
    let note = find(&fixture, TOPIC_NEW_NOTE, 0);
    logs[genesis].topics = logs[note].topics.clone();
    logs[genesis].data = logs[note].data.clone();
    assert!(matches!(
        refused(&fixture, &logs),
        IndexError::GenesisMismatch {
            reason: "leaf 0 is a note",
            ..
        }
    ));
}

#[test]
fn a_refused_batch_changes_nothing() {
    let fixture = Fixture::load();
    let whole = replay_once(&fixture);
    let middle = fixture.first_block + 40;

    let mut indexer = Indexer::new(fixture.config(0));
    let first = indexer.ingest(middle, &fixture.logs, None).expect("first");
    let before = indexer.checkpoint();

    // The log source lost the tail of the range, cut cleanly between two insertions. Only
    // the pool's own count can tell.
    let cut = fixture
        .logs
        .iter()
        .rposition(|log| is(log, TOPIC_LEAF_INSERTED, fixture.pool))
        .expect("an insertion");
    let truncated = &fixture.logs[..cut];
    let lost = indexer.ingest(fixture.head, truncated, Some(fixture.leaf_count));
    assert_eq!(
        lost,
        Err(IndexError::LeafCountMismatch {
            indexed: fixture.leaf_count - 1,
            chain: fixture.leaf_count,
        })
    );
    assert_eq!(indexer.checkpoint(), before);

    // Two different logs claim one position.
    let mut conflicting = fixture.logs.clone();
    let mut twin = conflicting[find(&fixture, TOPIC_NEW_NOTE, 60)].clone();
    twin.data[40] ^= 1;
    conflicting.push(twin);
    assert!(matches!(
        indexer.ingest(fixture.head, &conflicting, None),
        Err(IndexError::ConflictingLogs { .. })
    ));
    assert_eq!(indexer.checkpoint(), before);

    let rest = indexer
        .ingest(fixture.head, &fixture.logs, Some(fixture.leaf_count))
        .expect("the full range");
    let leaves: Vec<Leaf> = first.leaves.into_iter().chain(rest.leaves).collect();
    assert_eq!(leaves, whole.leaves);
}
