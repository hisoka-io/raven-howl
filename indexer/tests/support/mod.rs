//! The chain fixture, parsed. Shared by the test suites of the crates that consume the
//! indexer, so each one starts from the same logs and the same expected answers.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use howl_indexer::{IndexerConfig, RawLog};

pub fn unhex(text: &str) -> Vec<u8> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    assert!(digits.len().is_multiple_of(2), "odd hex length: {text}");
    (0..digits.len() / 2)
        .map(|i| u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

pub fn word(text: &str) -> [u8; 32] {
    unhex(text).try_into().expect("32 bytes")
}

pub struct ExpectedLeaf {
    pub leaf_index: u32,
    pub commitment: [u8; 32],
    pub tag: Option<[u8; 32]>,
    /// The row the public tag index holds for this leaf, as the generator wrote it.
    pub prefix: [u8; 6],
    pub cell: Option<Vec<u8>>,
}

pub struct FixtureKey {
    pub index: u64,
    pub x: [u8; 32],
    pub even_y: bool,
}

pub struct FixtureWallet {
    pub label: String,
    pub sk_root: [u8; 32],
    pub sk_view: [u8; 32],
    pub self_keys: Vec<FixtureKey>,
    pub incoming_keys: Vec<FixtureKey>,
    pub owned_leaves: Vec<u32>,
}

pub struct Fixture {
    pub chain_id: u64,
    pub pool: [u8; 20],
    pub first_block: u64,
    pub head: u64,
    pub leaf_block_size: u64,
    pub leaf_count: u64,
    pub root: [u8; 32],
    pub topics: serde_json::Value,
    pub logs: Vec<RawLog>,
    pub leaves: Vec<ExpectedLeaf>,
    pub wallets: Vec<FixtureWallet>,
}

fn keys(list: &serde_json::Value) -> Vec<FixtureKey> {
    list.as_array()
        .expect("keys")
        .iter()
        .map(|key| FixtureKey {
            index: key["index"].as_u64().expect("index"),
            x: word(key["x"].as_str().expect("x")),
            even_y: key["even_y"].as_bool().expect("even_y"),
        })
        .collect()
}

impl Fixture {
    pub fn load() -> Self {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../indexer/tests/vectors/chain.json"
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture file"))
                .expect("fixture parses");

        let mut logs = Vec::new();
        for block in doc["blocks"].as_array().expect("blocks") {
            let block_number = block["number"].as_u64().expect("number");
            for log in block["logs"].as_array().expect("logs") {
                logs.push(RawLog {
                    block_number,
                    log_index: log["log_index"].as_u64().expect("log_index"),
                    address: unhex(log["address"].as_str().expect("address"))
                        .try_into()
                        .expect("20 bytes"),
                    topics: log["topics"]
                        .as_array()
                        .expect("topics")
                        .iter()
                        .map(|t| word(t.as_str().expect("topic")))
                        .collect(),
                    data: unhex(log["data"].as_str().expect("data")),
                });
            }
        }
        let leaves = doc["leaves"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(|leaf| ExpectedLeaf {
                leaf_index: u32::try_from(leaf["leaf_index"].as_u64().expect("leaf_index"))
                    .expect("u32"),
                commitment: word(leaf["commitment"].as_str().expect("commitment")),
                tag: leaf["tag"].as_str().map(word),
                prefix: unhex(leaf["prefix"].as_str().expect("prefix"))
                    .try_into()
                    .expect("6 bytes"),
                cell: leaf["cell"].as_str().map(unhex),
            })
            .collect();
        let wallets = doc["wallets"]
            .as_array()
            .expect("wallets")
            .iter()
            .map(|wallet| FixtureWallet {
                label: wallet["label"].as_str().expect("label").to_owned(),
                sk_root: word(wallet["sk_root"].as_str().expect("sk_root")),
                sk_view: word(wallet["sk_view"].as_str().expect("sk_view")),
                self_keys: keys(&wallet["self_keys"]),
                incoming_keys: keys(&wallet["incoming_keys"]),
                owned_leaves: wallet["owned_leaves"]
                    .as_array()
                    .expect("owned")
                    .iter()
                    .map(|i| u32::try_from(i.as_u64().expect("leaf")).expect("u32"))
                    .collect(),
            })
            .collect();

        Self {
            chain_id: doc["chain_id"].as_u64().expect("chain_id"),
            pool: unhex(doc["pool"].as_str().expect("pool"))
                .try_into()
                .expect("20 bytes"),
            first_block: doc["blocks"][0]["number"].as_u64().expect("first block"),
            head: doc["head"].as_u64().expect("head"),
            leaf_block_size: doc["leaf_block_size"].as_u64().expect("leaf_block_size"),
            leaf_count: doc["leaf_count"].as_u64().expect("leaf_count"),
            root: word(doc["root"].as_str().expect("root")),
            topics: doc["topics"].clone(),
            logs,
            leaves,
            wallets,
        }
    }

    /// The public tag index of the whole chain: every leaf's expected row, in leaf order.
    pub fn prefix_feed(&self) -> Vec<u8> {
        self.leaves.iter().flat_map(|leaf| leaf.prefix).collect()
    }

    pub fn config(&self, finality_depth: u64) -> IndexerConfig {
        IndexerConfig {
            chain_id: self.chain_id,
            pool: self.pool,
            deployment_block: self.first_block,
            finality_depth,
        }
    }
}

/// splitmix64. Its output bytes are uniform enough to measure a collision rate with.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}
