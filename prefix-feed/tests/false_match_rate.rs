//! How often a published prefix equals a tag it does not belong to.
//!
//! A scan compares `C` candidate tags with `N` rows of `t` bytes, so it expects
//! `N * C / 2^(8t)` chance matches. The first test measures that law with the real matcher
//! at a width small enough to count; the second evaluates it at the published width.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../indexer/tests/support/mod.rs"]
mod support;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use howl_prefix_feed::{segment, PrefixIndex, PREFIX_BYTES};
use support::Rng;

fn expected(rows: f64, candidates: f64, values: f64) -> f64 {
    rows * candidates / values
}

/// Chance matches of `candidates` random tags against `rows` random rows when only the
/// last `free` bytes of a prefix vary.
fn measured(rows: usize, candidates: usize, free: usize, rng: &mut Rng) -> usize {
    let mut draw = |out: &mut [u8]| {
        let fixed = out.len() - free;
        out[..fixed].fill(0);
        out[fixed..]
            .iter_mut()
            .for_each(|byte| *byte = rng.next() as u8);
    };
    let mut feed = vec![0u8; rows * PREFIX_BYTES];
    for row in feed.as_chunks_mut::<PREFIX_BYTES>().0 {
        draw(row);
    }
    let tags: Vec<[u8; 32]> = (0..candidates)
        .map(|_| {
            let mut tag = [0u8; 32];
            draw(&mut tag);
            tag
        })
        .collect();

    let mut index = PrefixIndex::new();
    index
        .absorb(&segment(&feed, 0).expect("segment"))
        .expect("absorb");
    index.matches(&tags, 0).len()
}

#[test]
fn chance_matches_follow_rows_times_candidates_over_values() {
    let mut rng = Rng(0x00c0_ffee_1234_5678);
    // Two varying bytes: 65,536 values.
    for (rows, candidates) in [(30_000, 64), (60_000, 128), (60_000, 256)] {
        let mean = expected(rows as f64, candidates as f64, 65_536.0);
        let found = measured(rows, candidates, 2, &mut rng) as f64;
        // Poisson: five standard deviations either side.
        let slack = 5.0 * mean.sqrt();
        assert!(
            (found - mean).abs() < slack,
            "{rows} rows x {candidates} tags: {found} matches, expected {mean:.1} +- {slack:.1}"
        );
        println!(
            "measured  rows={rows} tags={candidates} values=2^16  found={found} expected={mean:.1}"
        );
    }
    // Three varying bytes: 256 times fewer.
    let found = measured(60_000, 256, 3, &mut rng);
    assert!(found < 12, "{found} matches where 0.9 are expected");
    println!("measured  rows=60000 tags=256 values=2^24  found={found} expected=0.9");
}

#[test]
fn at_six_bytes_a_million_notes_give_a_wallet_no_chance_matches() {
    let values = 2f64.powi(8 * PREFIX_BYTES as i32);
    assert_eq!(values, 281_474_976_710_656.0);

    let per_tag = expected(1e6, 1.0, values);
    assert!((per_tag - 3.5527e-9).abs() < 1e-12);
    for (rows, candidates, at_most) in [
        (1e5, 100.0, 3.6e-8),
        (1e6, 100.0, 3.6e-7),
        (1e6, 1_000.0, 3.6e-6),
        (1e7, 1_000.0, 3.6e-5),
    ] {
        let rate = expected(rows, candidates, values);
        assert!(rate < at_most && rate > at_most / 1.02, "{rate}");
        println!(
            "six bytes rows={rows:e} tags={candidates} chance matches per full scan={rate:.3e}"
        );
    }

    // The leading six bytes of a BN254 scalar stop at those of the largest scalar, so they
    // take 2^45.6 values, 5.29 times fewer.
    let largest = (-Fr::from(1u64)).into_bigint().to_bytes_be();
    let leading_values = largest[..PREFIX_BYTES]
        .iter()
        .fold(0u64, |value, byte| value << 8 | u64::from(*byte))
        + 1;
    assert_eq!(leading_values, 53_207_371_014_450);
    let leading = expected(1e6, 100.0, leading_values as f64);
    let ratio = leading / expected(1e6, 100.0, values);
    assert!((ratio - 5.290).abs() < 5e-4, "{ratio}");
    assert!((leading - 1.879e-6).abs() < 5e-10, "{leading}");
    println!("leading-byte prefix, rows=1e6 tags=100: {leading:.3e} ({ratio:.2} times more)");
}
