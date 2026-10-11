//! A wallet finds its notes in the published index using nothing but its view key.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../indexer/tests/support/mod.rs"]
mod support;
#[path = "../../indexer/tests/support/wallet.rs"]
mod wallet;

use howl_indexer::Indexer;
use howl_prefix_feed::{
    segment, tag_prefix, FeedError, Match, PrefixIndex, Segment, GENESIS_PREFIX, PREFIX_BYTES,
    RESUME_ALIGN_ROWS, SEGMENT_ROWS,
};
use support::{Fixture, FixtureKey, FixtureWallet, Rng};

/// The index a server publishes for the fixture chain.
fn published(fixture: &Fixture) -> Vec<u8> {
    let batch = Indexer::new(fixture.config(0))
        .ingest(fixture.head, &fixture.logs, Some(fixture.leaf_count))
        .expect("fixture indexes");
    batch
        .leaves
        .iter()
        .flat_map(|leaf| leaf.tag.as_ref().map_or(GENESIS_PREFIX, tag_prefix))
        .collect()
}

fn walk(feed: &[u8]) -> PrefixIndex {
    let mut index = PrefixIndex::new();
    loop {
        let part = segment(feed, index.resume_cursor()).expect("segment");
        index.absorb(&part).expect("absorb");
        if part.is_frontier() {
            return index;
        }
    }
}

fn candidates(wallet: &FixtureWallet) -> Vec<[u8; 32]> {
    wallet::candidate_tags(
        &wallet.sk_view,
        wallet.self_keys.len() as u64,
        wallet.incoming_keys.len() as u64,
    )
}

fn synthetic(rows: u64, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..rows * PREFIX_BYTES as u64)
        .map(|_| rng.next() as u8)
        .collect()
}

#[test]
fn the_test_wallet_derives_the_keys_howl_derives() {
    let fixture = Fixture::load();
    for expected in &fixture.wallets {
        assert_eq!(wallet::view_key(&expected.sk_root), expected.sk_view);
        let check = |keys: &[FixtureKey], derive: fn(&[u8; 32], u64) -> wallet::Key| {
            assert!(keys.len() > 20, "{}: a window of keys", expected.label);
            for key in keys {
                let derived = derive(&expected.sk_view, key.index);
                assert_eq!(derived.x, key.x, "{} key {}", expected.label, key.index);
                assert_eq!(
                    derived.even_y, key.even_y,
                    "{} key {}",
                    expected.label, key.index
                );
            }
        };
        check(&expected.self_keys, wallet::self_key);
        check(&expected.incoming_keys, wallet::incoming_key);
    }
}

#[test]
fn a_wallet_finds_every_note_it_owns_and_nothing_else() {
    let fixture = Fixture::load();
    let index = walk(&published(&fixture));
    assert_eq!(index.len(), fixture.leaf_count);

    let mut claimed = 0;
    for wallet in &fixture.wallets {
        let tags = candidates(wallet);
        let found = index.matches(&tags, 0);
        let positions: Vec<u32> = found.iter().map(|m| m.position as u32).collect();
        let mut owned = wallet.owned_leaves.clone();
        owned.sort_unstable();
        assert!(!owned.is_empty(), "{} owns notes", wallet.label);
        assert_eq!(positions, owned, "{}", wallet.label);

        // Each match names the tag the chain filed that leaf under.
        for Match {
            position,
            candidate,
        } in found
        {
            assert_eq!(
                Some(tags[candidate]),
                fixture.leaves[position as usize].tag,
                "{} leaf {position}",
                wallet.label
            );
        }
        // A reused receiving address is one tag over several notes.
        let reused = (0..tags.len())
            .map(|c| {
                index
                    .matches(&tags, 0)
                    .iter()
                    .filter(|m| m.candidate == c)
                    .count()
            })
            .max();
        assert!(
            reused > Some(1),
            "{}: no tag carries two notes",
            wallet.label
        );
        claimed += owned.len();
    }
    assert!(
        claimed < fixture.leaves.len() - 1,
        "the chain holds notes of other wallets too"
    );

    // A wallet with other keys finds nothing: the lookup can fail.
    let stranger = wallet::view_key(&[7u8; 32]);
    assert!(index
        .matches(&wallet::candidate_tags(&stranger, 60, 30), 0)
        .is_empty());
}

#[test]
fn a_later_scan_reports_only_new_positions() {
    let fixture = Fixture::load();
    let feed = published(&fixture);
    let alice = &fixture.wallets[0];
    let tags = candidates(alice);
    let all = walk(&feed).matches(&tags, 0);

    let seen = 90;
    let older = walk(&feed[..seen * PREFIX_BYTES]).matches(&tags, 0);
    let newer = walk(&feed).matches(&tags, seen as u64);
    assert!(!older.is_empty() && !newer.is_empty());
    assert_eq!([older, newer].concat(), all);
}

#[test]
fn the_genesis_row_is_never_a_match() {
    let mut index = PrefixIndex::new();
    let feed = [GENESIS_PREFIX, [0u8; PREFIX_BYTES], [9u8; PREFIX_BYTES]].concat();
    index
        .absorb(&segment(&feed, 0).expect("segment"))
        .expect("absorb");
    // A tag whose low six bytes are zero matches row 1, and never the genesis row.
    let mut tag = [0u8; 32];
    tag[0] = 0x12;
    assert_eq!(
        index.matches(&[tag], 0),
        vec![Match {
            position: 1,
            candidate: 0
        }]
    );
}

#[test]
fn the_published_rows_are_the_rows_the_fixture_expects() {
    let fixture = Fixture::load();
    // The expected rows were written by the fixture generator from Howl's serialisation
    // of each tag. They state the rule: six zero bytes, then bytes 26..32 of every tag.
    assert_eq!(fixture.leaves[0].prefix, [0u8; PREFIX_BYTES]);
    assert_eq!(fixture.leaves[0].tag, None);
    for leaf in &fixture.leaves[1..] {
        let tag = leaf.tag.expect("a note has a tag");
        assert_eq!(leaf.prefix, tag[26..32], "leaf {}", leaf.leaf_index);
    }

    let expected = fixture.prefix_feed();
    assert_eq!(expected.len(), fixture.leaves.len() * PREFIX_BYTES);
    assert_eq!(published(&fixture), expected);
    assert_eq!(GENESIS_PREFIX, fixture.leaves[0].prefix);
    for leaf in &fixture.leaves[1..] {
        assert_eq!(tag_prefix(&leaf.tag.expect("tag")), leaf.prefix);
    }
    assert_eq!(walk(&expected).as_bytes(), expected.as_slice());
}

#[test]
fn the_prefix_is_the_low_order_end_of_the_tag() {
    let fixture = Fixture::load();
    let tags: Vec<[u8; 32]> = fixture.leaves.iter().filter_map(|leaf| leaf.tag).collect();
    // The leading byte of a BN254 scalar stops at 0x30, which is why it is not published.
    assert!(tags.iter().all(|tag| tag[0] <= 0x30));
    for tag in &tags {
        assert_eq!(tag_prefix(tag), tag[26..]);
    }
    let mut prefixes: Vec<_> = fixture
        .wallets
        .iter()
        .flat_map(|w| w.self_keys.iter().chain(&w.incoming_keys))
        .map(|key| tag_prefix(&key.x))
        .collect();
    let derived = prefixes.len();
    prefixes.sort_unstable();
    prefixes.dedup();
    assert_eq!(prefixes.len(), derived, "two derived keys share a prefix");
}

#[test]
fn segments_resume_across_boundaries_and_growth() {
    let rows = 2 * SEGMENT_ROWS + 4_321;
    let feed = synthetic(rows, 0x51ed_270b_9a11_c0de);

    // A cold walk: two sealed segments and the tail.
    let first = segment(&feed, 0).expect("first");
    assert_eq!(
        (first.base, first.next, first.total()),
        (0, SEGMENT_ROWS, None)
    );
    assert!(first.is_sealed() && !first.is_frontier());
    assert_eq!(first.rows.len(), SEGMENT_ROWS as usize * PREFIX_BYTES);
    let last = segment(&feed, 2 * SEGMENT_ROWS).expect("last");
    assert!(!last.is_sealed() && last.is_frontier());
    assert_eq!(last.total(), Some(rows));
    assert_eq!(walk(&feed).as_bytes(), feed.as_slice());

    // The list grows a few rows at a time and the wallet follows from where it stopped,
    // through a reload from storage, across a segment boundary.
    let mut rng = Rng(0x00dd_ba11);
    let mut grown = (SEGMENT_ROWS - 700) as usize;
    let mut index = walk(&feed[..grown * PREFIX_BYTES]);
    while grown < rows as usize {
        grown = (grown + 1 + rng.below(900) as usize).min(rows as usize);
        let served = &feed[..grown * PREFIX_BYTES];
        index = PrefixIndex::from_bytes(index.as_bytes().to_vec()).expect("reload");
        loop {
            let cursor = index.resume_cursor();
            assert!(
                index.len() - cursor < RESUME_ALIGN_ROWS,
                "re-read is bounded"
            );
            let part = segment(served, cursor).expect("segment");
            index.absorb(&part).expect("absorb");
            if part.is_frontier() {
                break;
            }
        }
        assert_eq!(index.as_bytes(), served);
    }

    // Up to date: an empty segment, and nothing changes.
    let done = segment(&feed, rows).expect("frontier");
    assert!(done.rows.is_empty() && done.is_frontier());
    assert_eq!(index.absorb(&done), Ok(0));
}

#[test]
fn a_segment_that_never_changes_carries_nothing_that_does() {
    let rows = 2 * SEGMENT_ROWS + 77;
    let feed = synthetic(rows, 0x5ea1_ed00_b0a7);
    let upto = |rows: u64| &feed[..rows as usize * PREFIX_BYTES];

    // Cut at the moment the list ends exactly on the boundary, and again as it grows.
    let exact = upto(SEGMENT_ROWS);
    let kept = segment(exact, 0).expect("segment");
    assert!(kept.is_sealed());
    for longer in [SEGMENT_ROWS + 1, 2 * SEGMENT_ROWS, rows] {
        assert!(segment(upto(longer), 0) == Ok(kept), "{longer} rows");
    }
    // The same holds from a cursor inside the segment.
    let inner = segment(exact, RESUME_ALIGN_ROWS).expect("segment");
    assert!(segment(&feed, RESUME_ALIGN_ROWS) == Ok(inner));
    assert!(!inner.is_sealed() && !inner.is_frontier());

    // A wallet handed the copy cut at the boundary does not take it for the end.
    assert!(!kept.is_frontier());
    let mut index = PrefixIndex::new();
    loop {
        let cursor = index.resume_cursor();
        let part = if cursor == 0 {
            kept
        } else {
            segment(&feed, cursor).expect("segment")
        };
        index.absorb(&part).expect("absorb");
        if part.is_frontier() {
            break;
        }
    }
    assert!(
        index.as_bytes() == feed.as_slice(),
        "the walk stopped early"
    );

    // A list that ends on the boundary is closed by the empty segment after it.
    let end = segment(exact, SEGMENT_ROWS).expect("segment");
    assert!(end.rows.is_empty() && end.is_frontier() && !end.is_sealed());
    assert!(walk(exact).as_bytes() == exact);
}

#[test]
fn a_changed_or_inconsistent_list_is_refused_and_the_index_kept() {
    let feed = synthetic(5_000, 0xfeed);
    let mut index = walk(&feed[..3_000 * PREFIX_BYTES]);
    let held = index.clone();

    // One re-read row differs from the row held.
    let mut other = feed.clone();
    other[2_500 * PREFIX_BYTES] ^= 1;
    let cursor = index.resume_cursor();
    assert_eq!(cursor, 2_048);
    assert_eq!(
        index.absorb(&segment(&other, cursor).expect("segment")),
        Err(FeedError::Diverged { position: 2_500 })
    );

    // The server's list is shorter than the rows held.
    assert_eq!(
        segment(&feed[..2_000 * PREFIX_BYTES], 3_000).err(),
        Some(FeedError::PastFrontier {
            since: 3_000,
            total: 2_000
        })
    );

    // A segment from beyond the rows held, and segments that misstate themselves.
    assert_eq!(
        index.absorb(&segment(&feed, 4_000).expect("segment")),
        Err(FeedError::Gap {
            base: 4_000,
            held: 3_000
        })
    );
    let honest = segment(&feed, 3_000).expect("segment");
    for lying in [
        Segment {
            next: honest.next + 1,
            ..honest
        },
        Segment {
            rows: &honest.rows[..honest.rows.len() - PREFIX_BYTES],
            ..honest
        },
    ] {
        assert!(matches!(
            index.absorb(&lying),
            Err(FeedError::Inconsistent { .. })
        ));
    }
    // Rows that run past a segment boundary are not a segment the server cuts.
    let long = synthetic(SEGMENT_ROWS + 1, 0x10e6);
    assert!(matches!(
        PrefixIndex::new().absorb(&Segment {
            base: 0,
            next: SEGMENT_ROWS + 1,
            rows: &long,
        }),
        Err(FeedError::Inconsistent { .. })
    ));
    assert_eq!(
        index.absorb(&Segment {
            rows: &honest.rows[..7],
            ..honest
        }),
        Err(FeedError::Ragged { len: 7 })
    );
    assert_eq!(
        segment(&feed[..11], 0).err(),
        Some(FeedError::Ragged { len: 11 })
    );

    assert_eq!(index, held, "a refused segment changed the index");
    assert_eq!(index.absorb(&honest), Ok(2_000));
    assert_eq!(index.as_bytes(), feed.as_slice());
}
