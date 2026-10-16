# howl

Rust crates for serving Howl note-discovery records over private information retrieval. This
repository is part of the [Raven](https://github.com/hisoka-io/raven) PIR framework, which
includes it as a git submodule at `adapters/howl`.

- `howl-poseidon2` (`poseidon2/`): Poseidon2 over the BN254 scalar field, byte-identical to
  Aztec's `poseidon2Hash`. It is not Poseidon-BN254.
- `howl-record` (`record/`): the `howl-note-v1` discovery record, 246 payload bytes inside a
  256-byte PIR cell, with a zero-padded tail that decoders refuse when non-zero.
- `howl-indexer` (`indexer/`): turns the pool's logs into the ordered leaf stream. Every tree
  insertion is paired with the event that describes it and checked against the root the pool
  reports, so the stream is the tree, leaf for leaf. It reads blocks a configured depth below
  the head.
- `howl-prefix-feed` (`prefix-feed/`): the public tag index, six bytes per leaf in tree order,
  cut into resumable segments, with the wallet-side index that finds a wallet's positions
  from the tags it derives. A full segment is the same bytes and cursors on every read.

The durable table these crates feed, `howl-store`, is built on Raven's storage crate and lives
in the Raven repository at `adapters/howl-node`, where it is tested against this repository as
a submodule.

Status: pre-release (`0.1.0-alpha.0`), not published to crates.io. Every crate is pinned by
test vectors produced by the counterpart implementations.

## Build and test

Every crate depends on crates.io alone, so a plain clone builds and tests:

```bash
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
```

Minimum Rust version: 1.89.

## Poseidon2 test vectors

`poseidon2/tests/generators/` holds the vector generators, a Python and a JavaScript reference
implementation, and the round constants they read. `SHA256SUMS` pins the other files there along
with both corpora in `poseidon2/tests/vectors/`. The provenance check verifies those hashes and
regenerates both corpora byte for byte from the JavaScript reference; it needs Node.js 20:

```bash
poseidon2/check-provenance.sh
poseidon2/check-provenance-selftest.sh
```

To regenerate against Aztec itself, install `@aztec/foundation@2.1.11`, point
`AZTEC_FOUNDATION_ROOT` at that package's root, and run `gen-kats.mjs` or `gen-perm-kats.mjs`
with Node. The generators refuse a missing or different version of the package.

## Chain fixture

`indexer/tests/vectors/chain.json` is a chain of pool logs with the answers Howl's own code
gives for it: logs ABI-encoded from the compiled pool, tags from Howl's key derivation, cells
from its record encoder, roots from its tree. The indexer and feed tests here, and the store's in Raven, all replay it.
Each leaf also carries `prefix`, the row the public tag index holds for it (`prefix_rule`
states the derivation), so an implementation in another language can check its index against
the same file.
`indexer/tests/generators/SHA256SUMS` pins the fixture and its generator.

To regenerate, point `HOWL_ROOT` at a built Howl checkout and run the generator with Node.
It names the Howl commit it expects and refuses another:

```bash
HOWL_ROOT=/path/to/howl node indexer/tests/generators/gen-chain-fixture.mjs \
  > indexer/tests/vectors/chain.json
(cd indexer/tests/generators && sha256sum -c SHA256SUMS)
```

## License

[Apache-2.0](./LICENSE)
