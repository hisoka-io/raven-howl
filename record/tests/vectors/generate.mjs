// Regenerates record.json by running Howl's own codec (packages/wallets/src/discovery/codec.ts).
//
//   HOWL_ROOT=/path/to/darkpool-v2 node record/tests/vectors/generate.mjs > record/tests/vectors/record.json
//
// HOWL_ROOT needs `pnpm install` for packages/wallets. The codec is compiled with that checkout's tsc into a
// temporary directory, so the checkout itself is never written. Inputs come from a fixed seed: the same Howl
// commit gives the same file.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const repo = process.env.HOWL_ROOT;
if (!repo) throw new Error("set HOWL_ROOT to a darkpool-v2 checkout");
const wallets = join(repo, "packages/wallets");
const out = mkdtempSync(join(tmpdir(), "howl-codec-"));
try {
  execFileSync(join(repo, "node_modules/.bin/tsc"), [
    "--outDir", out, "--rootDir", join(wallets, "src"),
    "--module", "nodenext", "--moduleResolution", "nodenext", "--target", "es2022",
    "--skipLibCheck", "--declaration", "false",
    join(wallets, "src/discovery/codec.ts"), join(wallets, "src/discovery/types.ts"),
  ], { cwd: wallets, stdio: ["ignore", "inherit", "inherit"] });
  // The compiled codec resolves @aztec/foundation through the wallets package's own dependencies.
  symlinkSync(join(wallets, "node_modules"), join(out, "node_modules"), "dir");
  const codec = await import(pathToFileURL(join(out, "discovery/codec.js")).href);
  const types = await import(pathToFileURL(join(out, "discovery/types.js")).href);
  const { Fr } = await import(pathToFileURL(join(wallets, "node_modules/@aztec/foundation/dest/fields/index.js")).href);
  process.stdout.write(JSON.stringify(build(codec, types, Fr, revision(repo)), null, 2) + "\n");
} finally {
  rmSync(out, { recursive: true, force: true });
}

function revision(dir) {
  return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"]).toString().trim();
}

function build(codec, types, Fr, rev) {
  const P = Fr.MODULUS;
  let counter = 0;
  const stream = (n) => {
    const chunks = [];
    while (Buffer.concat(chunks).length < n) {
      chunks.push(createHash("sha256").update(`howl-note-v1 vectors/${counter++}`).digest());
    }
    return Buffer.concat(chunks).subarray(0, n);
  };
  const field = () => BigInt("0x" + stream(32).toString("hex")) % P;
  const u32 = () => stream(4).readUInt32BE(0);
  const edges = [0n, 1n, 2n ** 128n, 2n ** 248n - 1n, 2n ** 253n, P - 2n, P - 1n];

  const specs = [];
  const add = (label, kind, leafIndex, prefix, eph, cek, kept) =>
    specs.push({ label, kind, leafIndex, prefix, eph, cek, kept });
  const zero = Buffer.alloc(16);
  add("incoming_minimal", types.RECORD_KIND_INCOMING, 0, zero, 0n, 0n, [0n, 0n, 0n, 0n, 0n]);
  add("self_typical", types.RECORD_KIND_SELF, 42, Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"), 0n, 0n,
    [1n, 2n, 3n, 4n, 5n]);
  add("incoming_max_leaf", types.RECORD_KIND_INCOMING, 0xffffffff,
    Buffer.from("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0", "hex"), P - 1n, P - 2n, [3n, 4n, 5n, 6n, 7n].map((k) => P - k));
  add("boundary_prefix_high_bit", types.RECORD_KIND_SELF, 65535, Buffer.alloc(16, 0x80), 1n, 1n, [1n, 1n, 1n, 1n, 1n]);
  add("self_minimal", types.RECORD_KIND_SELF, 0, zero, 0n, 0n, [0n, 0n, 0n, 0n, 0n]);
  add("incoming_all_max", types.RECORD_KIND_INCOMING, 0xffffffff, Buffer.alloc(16, 0xff), P - 1n, P - 1n,
    [P - 1n, P - 1n, P - 1n, P - 1n, P - 1n]);
  add("self_leaf_one", types.RECORD_KIND_SELF, 1, stream(16), 0n, 0n, Array.from({ length: 5 }, field));
  edges.forEach((e, i) =>
    add(`incoming_edge_${i}`, types.RECORD_KIND_INCOMING, [1, 255, 256, 65535, 65536, 0x7fffffff, 0x80000000][i],
      stream(16), e, edges[(i + 3) % edges.length], edges.map((_, j) => edges[(i + j) % edges.length]).slice(0, 5)));
  for (let i = 0; i < 24; i++) {
    const incoming = i % 2 === 0;
    add(`${incoming ? "incoming" : "self"}_random_${i}`,
      incoming ? types.RECORD_KIND_INCOMING : types.RECORD_KIND_SELF, u32(), stream(16),
      incoming ? field() : 0n, incoming ? field() : 0n, Array.from({ length: 5 }, field));
  }

  const vectors = specs.map((s) => {
    const record = {
      layoutVersion: types.HOWL_NOTE_LAYOUT_VERSION,
      recordKind: s.kind,
      leafIndex: s.leafIndex,
      commitmentPrefix: new Uint8Array(s.prefix),
      ephemeralPkX: new Fr(s.eph),
      cekWrap: new Fr(s.cek),
      ciphertextKept: s.kept.map((w) => new Fr(w)),
    };
    const cell = codec.encodeHowlNoteRecord(record);
    const back = codec.decodeHowlNoteRecord(cell);
    const same = back.leafIndex === s.leafIndex && back.recordKind === s.kind &&
      Buffer.from(back.commitmentPrefix).equals(s.prefix) &&
      back.ephemeralPkX.toBigInt() === s.eph && back.cekWrap.toBigInt() === s.cek &&
      back.ciphertextKept.every((w, i) => w.toBigInt() === s.kept[i]);
    if (!same) throw new Error(`Howl's decode does not round-trip ${s.label}`);
    return {
      label: s.label,
      layout_version: types.HOWL_NOTE_LAYOUT_VERSION,
      record_kind: s.kind,
      leaf_index: s.leafIndex,
      commitment_prefix: s.prefix.toString("hex"),
      ephemeral_pk_x: s.eph.toString(),
      cek_wrap: s.cek.toString(),
      ciphertext_kept: s.kept.map((w) => w.toString()),
      cell: Buffer.from(cell).toString("hex"),
    };
  });

  // Cells Howl's decoder refuses, each a small change of a generated cell. Both decoders must refuse them.
  const base = Buffer.from(vectors.find((v) => v.label === "self_leaf_one").cell, "hex");
  const refused = [];
  const refuse = (label, mutate) => {
    const cell = Buffer.from(base);
    mutate(cell);
    let threw = false;
    try { codec.decodeHowlNoteRecord(new Uint8Array(cell)); } catch { threw = true; }
    if (!threw) throw new Error(`Howl's decode accepted ${label}`);
    refused.push({ label, cell: cell.toString("hex") });
  };
  refuse("layout_0", (c) => { c[0] = 0; });
  refuse("layout_2", (c) => { c[0] = 2; });
  refuse("kind_2", (c) => { c[1] = 2; });
  for (let i = types.HOWL_NOTE_RECORD_BYTES; i < types.HOWL_NOTE_CELL_BYTES; i++) {
    refuse(`pad_byte_${i}`, (c) => { c[i] = 1; });
  }
  // Howl's decode keeps a field slot as raw bytes and refuses one at or above the modulus on its first numeric
  // use; Raven's decode refuses it at once. Both refuse the cell before it reaches a commitment check.
  const modulus = Buffer.from(P.toString(16).padStart(64, "0"), "hex");
  for (const [name, offset, read] of [
    ["eph", 22, (r) => r.ephemeralPkX], ["cek", 54, (r) => r.cekWrap],
    ["word_0", 86, (r) => r.ciphertextKept[0]], ["word_4", 214, (r) => r.ciphertextKept[4]],
  ]) {
    const cell = Buffer.from(base);
    modulus.copy(cell, offset);
    let threw = false;
    try { read(codec.decodeHowlNoteRecord(new Uint8Array(cell))).toBigInt(); } catch { threw = true; }
    if (!threw) throw new Error(`Howl's codec used a non-canonical ${name}`);
    refused.push({ label: `modulus_in_${name}`, cell: cell.toString("hex"), howl: "refused on first use of the field" });
  }

  return {
    source: "Howl packages/wallets/src/discovery/codec.ts, run by record/tests/vectors/generate.mjs",
    howl_revision: rev,
    record_bytes: types.HOWL_NOTE_RECORD_BYTES,
    cell_bytes: types.HOWL_NOTE_CELL_BYTES,
    commitment_prefix_bytes: types.COMMITMENT_PREFIX_BYTES,
    ciphertext_kept_indices: [...types.CIPHERTEXT_KEPT_INDICES],
    vectors,
    refused,
  };
}
