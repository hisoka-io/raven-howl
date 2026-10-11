//! A wallet's side of discovery, for tests: every tag it could own, from its view key alone.
//!
//! Transcribed from Howl's key derivation and pinned against keys Howl's own code produced,
//! so a test that finds notes with these tags finds them the way a real wallet would.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

const SELF_LABEL: &str = "hisoka.selfEph";
const INCOMING_LABEL: &str = "hisoka.inKey";
const VIEW_LABEL: &str = "hisoka.view";

fn dec(text: &str) -> Fr {
    text.bytes().fold(Fr::from(0u64), |acc, digit| {
        acc * Fr::from(10u64) + Fr::from(u64::from(digit - b'0'))
    })
}

pub fn scalar(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub fn bytes(value: Fr) -> [u8; 32] {
    value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("32 bytes")
}

/// Poseidon2 over `(master, H(label), nonce)`; a zero nonce is left out.
fn kdf(label: &str, master: Fr, nonce: u64) -> Fr {
    let mut padded = [0u8; 32];
    padded[32 - label.len()..].copy_from_slice(label.as_bytes());
    let purpose = howl_poseidon2::hash(&[scalar(&padded)]);
    if nonce == 0 {
        howl_poseidon2::hash(&[master, purpose])
    } else {
        howl_poseidon2::hash(&[master, purpose, Fr::from(nonce)])
    }
}

/// `scalar * Base8` on Baby Jubjub, in projective twisted Edwards coordinates.
fn public_key(secret: Fr) -> (Fr, Fr) {
    let a = Fr::from(168_700u64);
    let d = Fr::from(168_696u64);
    let base = (
        dec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        dec("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
        Fr::from(1u64),
    );
    let add = |p: (Fr, Fr, Fr), q: (Fr, Fr, Fr)| {
        let za = p.2 * q.2;
        let zb = za * za;
        let c = p.0 * q.0;
        let dd = p.1 * q.1;
        let e = d * c * dd;
        let f = zb - e;
        let g = zb + e;
        (
            za * f * ((p.0 + p.1) * (q.0 + q.1) - c - dd),
            za * g * (dd - a * c),
            f * g,
        )
    };
    let mut acc = (Fr::from(0u64), Fr::from(1u64), Fr::from(1u64));
    for bit in secret.into_bigint().to_bits_be() {
        acc = add(acc, acc);
        if bit {
            acc = add(acc, base);
        }
    }
    let inverse = ark_ff::Field::inverse(&acc.2).expect("a subgroup point is finite");
    (acc.0 * inverse, acc.1 * inverse)
}

pub struct Key {
    pub index: u64,
    pub x: [u8; 32],
    pub even_y: bool,
}

fn key(label: &str, sk_view: Fr, index: u64) -> Key {
    let (x, y) = public_key(kdf(label, sk_view, index));
    Key {
        index,
        x: bytes(x),
        even_y: y.into_bigint().is_even(),
    }
}

pub fn view_key(sk_root: &[u8; 32]) -> [u8; 32] {
    bytes(kdf(VIEW_LABEL, scalar(sk_root), 0))
}

pub fn self_key(sk_view: &[u8; 32], index: u64) -> Key {
    key(SELF_LABEL, scalar(sk_view), index)
}

pub fn incoming_key(sk_view: &[u8; 32], index: u64) -> Key {
    key(INCOMING_LABEL, scalar(sk_view), index)
}

/// The tags a wallet scans for: indices `0..self_count` of its own ephemerals and
/// `0..incoming_count` of its receiving addresses. Only an even-y key has a tag.
pub fn candidate_tags(sk_view: &[u8; 32], self_count: u64, incoming_count: u64) -> Vec<[u8; 32]> {
    let own = (0..self_count).map(|i| self_key(sk_view, i));
    let incoming = (0..incoming_count).map(|j| incoming_key(sk_view, j));
    own.chain(incoming)
        .filter(|key| key.even_y)
        .map(|key| key.x)
        .collect()
}
