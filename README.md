# howl

Rust crates for serving Howl note-discovery records over private information retrieval. This
repository is part of the [Raven](https://github.com/hisoka-io/raven) PIR framework, which
includes it as a git submodule at `adapters/howl`.

- `howl-poseidon2` (`poseidon2/`): Poseidon2 over the BN254 scalar field, byte-identical to
  Aztec's `poseidon2Hash`. It is not Poseidon-BN254.
- `howl-record` (`record/`): the `howl-note-v1` discovery record, 246 payload bytes inside a
  256-byte PIR cell, with a zero-padded tail that decoders refuse when non-zero.

Status: pre-release (`0.1.0-alpha.0`), not published to crates.io. Both crates are pinned by
test vectors produced by the counterpart implementations.

## Build and test

The workspace has no path dependencies and builds on its own:

```bash
git clone https://github.com/hisoka-io/raven-howl.git
cd raven-howl
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
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

## License

[Apache-2.0](./LICENSE)
