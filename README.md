# howl

Rust crates for serving Howl note-discovery records over private information retrieval. This
repository is part of the [Raven](https://github.com/hisoka-io/raven) PIR framework, which
includes it as a git submodule at `adapters/howl`.

- `howl-poseidon2` (`poseidon2/`): Poseidon2 over the BN254 scalar field, byte-identical to
  Aztec's `poseidon2Hash`. It is not Poseidon-BN254.
- `howl-record` (`record/`): the `howl-note-v1` discovery record, 246 payload bytes inside a
  256-byte PIR cell, with a zero-padded tail that decoders refuse when non-zero.

Both are pinned by test vectors produced by the counterpart implementations. The Poseidon2
generators are committed under `poseidon2/tests/generators/`.

## Build

The workspace has no path dependencies and builds on its own:

```bash
git clone https://github.com/hisoka-io/raven-howl.git
cd raven-howl
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
```

The Poseidon2 provenance check hashes the generator packet and regenerates both vector corpora
byte for byte. It needs Node.js 20:

```bash
poseidon2/check-provenance.sh
poseidon2/check-provenance-selftest.sh
```

Minimum Rust version: 1.89.

## License

[Apache-2.0](./LICENSE)
