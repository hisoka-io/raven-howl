// A deterministic chain of pool logs, encoded by ethers from the compiled pool ABI, with the
// answers Howl's own code gives for it: tags from its key derivation, cells from its record
// encoder, roots from its tree. Seeded, so it regenerates byte for byte.
import { loadHowl } from "./howl-checkout.mjs";

const { commit, wallets, harness, ethers, abi } = await loadHowl();
const { Fr } = wallets;

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CHAIN_ID = 31337n;
const POOL = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const OTHER_POOL = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
const FIRST_BLOCK = 100;
const TARGET_LEAVES = 160;
const LOOKAHEAD = 20n;

const MASK = (1n << 64n) - 1n;
let state = 0x5eed0f0a11ce5eedn;
const next = () => {
  state ^= (state << 13n) & MASK;
  state ^= state >> 7n;
  state ^= (state << 17n) & MASK;
  return state;
};
const below = (n) => Number(next() % BigInt(n));
const field = () => {
  const wide = (next() << 192n) | (next() << 128n) | (next() << 64n) | next();
  return new Fr((wide % (P - 1n)) + 1n);
};
const address = () => ethers.getAddress("0x" + (next() << 96n | next()).toString(16).padStart(40, "0").slice(-40));

const word = (fr) => "0x" + fr.toBuffer().toString("hex");
// The published prefix of a tag, taken from Howl's own serialisation of the scalar.
const PREFIX_RULE = "bytes 26..32 of the 32-byte big-endian tag; six zero bytes for the genesis leaf";
const prefix = (fr) => "0x" + fr.toBuffer().subarray(26, 32).toString("hex");
const iface = new ethers.Interface(abi);

class Wallet {
  constructor(label, skRoot) {
    this.label = label;
    this.skRoot = skRoot;
    this.selfStart = 0n;
    this.selfHigh = 0n;
    this.addresses = [];
    this.incomingStart = 0n;
    this.incomingHigh = 0n;
    this.owned = [];
  }
  async init(addressCount) {
    this.skView = await wallets.deriveViewKey(this.skRoot);
    for (let k = 0; k < addressCount; k++) {
      const a = await wallets.canonicalIncomingAddress(this.skView, this.incomingStart);
      this.incomingStart = a.index + 1n;
      this.incomingHigh = a.index;
      this.addresses.push(a);
    }
  }
  async selfTag() {
    const a = await wallets.canonicalSelfTag(this.skView, this.selfStart);
    this.selfStart = a.index + 1n;
    this.selfHigh = a.index;
    return a.tag;
  }
  incomingTag() {
    return this.addresses[below(this.addresses.length)].tag;
  }
}

const alice = new Wallet("alice", new Fr(0x0a11ce0000000000000000000000000000000000000000000000000000000001n));
const bob = new Wallet("bob", new Fr(0x0b0b000000000000000000000000000000000000000000000000000000000002n));
await alice.init(3);
await bob.init(2);
const stranger = { label: "stranger", selfTag: async () => field(), incomingTag: () => field(), owned: [] };
const parties = [alice, bob, stranger, stranger];
const pick = () => parties[below(parties.length)];

const tree = await wallets.newSeededTree(CHAIN_ID);
const genesis = await wallets.genesisLeaf(CHAIN_ID);
const blocks = [];
const leaves = [];
let nextLeaf = 1;

const encode = (name, args, emitter = POOL) => {
  const { topics, data } = iface.encodeEventLog(name, args);
  return { address: emitter, topics, data };
};
const ciphertext = () => Array.from({ length: 7 }, field);

const inserted = async (leafIndex, commitment) => {
  const root = await tree.insert(commitment);
  return [
    encode("RootSaved", [word(root)]),
    encode("LeafInserted", [leafIndex, word(commitment), word(root)]),
  ];
};
const expectLeaf = (event, owner) => {
  const tag = harness.tagOf(event);
  leaves.push({
    leaf_index: event.leafIndex,
    kind: event.kind === "NEW_NOTE" ? "note" : "memo",
    commitment: word(event.commitment),
    tag: word(tag),
    prefix: prefix(tag),
    cell: Buffer.from(wallets.encodeHowlNoteRecord(harness.toRecord(event))).toString("hex"),
  });
  owner.owned.push(event.leafIndex);
};

const note = async (owner) => {
  const event = {
    kind: "NEW_NOTE",
    leafIndex: nextLeaf++,
    commitment: field(),
    ephemeralX: await owner.selfTag(),
    packedCiphertext: ciphertext(),
  };
  const logs = await inserted(event.leafIndex, event.commitment);
  logs.push(
    encode("NewNote", [
      event.leafIndex,
      word(event.commitment),
      event.ephemeralX.toBigInt(),
      event.packedCiphertext.map(word),
    ]),
  );
  expectLeaf(event, owner);
  return logs;
};
const memo = async (recipient) => {
  const event = {
    kind: "NEW_MEMO",
    leafIndex: nextLeaf++,
    commitment: field(),
    tag: recipient.incomingTag(),
    ephemeralX: field(),
    cekWrap: field(),
    packedCiphertext: ciphertext(),
  };
  const logs = await inserted(event.leafIndex, event.commitment);
  logs.push(
    encode("NewPrivateMemo", [
      event.leafIndex,
      word(event.commitment),
      event.tag.toBigInt(),
      event.ephemeralX.toBigInt(),
      event.cekWrap.toBigInt(),
      event.packedCiphertext.map(word),
    ]),
  );
  expectLeaf(event, recipient);
  return logs;
};
const spent = () => encode("NullifierSpent", [word(field())]);

// Log order inside each action follows the pool's entrypoints.
const actions = {
  deposit: async () => {
    const who = pick();
    return [encode("Deposited", [address(), address(), 1_000_000n]), ...(await note(who))];
  },
  withdraw: async () => {
    const who = pick();
    const nullifier = field();
    return [
      encode("NullifierSpent", [word(nullifier)]),
      ...(await note(who)),
      encode("Withdrawal", [word(nullifier), address(), address()]),
    ];
  },
  transfer: async () => {
    const from = pick();
    const to = pick();
    return [spent(), ...(await memo(to)), ...(await note(from))];
  },
  join: async () => {
    const who = pick();
    return [spent(), spent(), ...(await note(who))];
  },
  split: async () => {
    const who = pick();
    return [spent(), ...(await note(who)), ...(await note(who))];
  },
  kageSwap: async () => {
    const taker = pick();
    const maker = pick();
    return [
      spent(),
      spent(),
      ...(await note(taker)),
      ...(await note(taker)),
      ...(await note(maker)),
      ...(await note(maker)),
    ];
  },
  publicTransfer: async () => [
    encode("NewPublicMemo", [word(field()), address(), 5n, 0n, field().toBigInt()]),
  ],
  publicClaim: async () => {
    const who = pick();
    return [encode("PublicMemoSpent", [word(field())]), ...(await note(who))];
  },
  // The same events from another deployment: an indexer that filters on topics alone ingests them.
  otherPool: async () => [
    encode("LeafInserted", [nextLeaf, word(field()), word(field())], OTHER_POOL),
    encode("NewNote", [nextLeaf, word(field()), field().toBigInt(), ciphertext().map(word)], OTHER_POOL),
  ],
};
const names = Object.keys(actions);

const seal = (number, logs) =>
  blocks.push({ number, logs: logs.map((log, log_index) => ({ log_index, ...log })) });

seal(FIRST_BLOCK, [
  encode("Initialized", [1n]),
  encode("VerifierUpdated", [0n, address()]),
  encode("VerifierUpdated", [1n, address()]),
  encode("RootSaved", [word(tree.getRoot())]),
  encode("LeafInserted", [0n, word(genesis), word(tree.getRoot())]),
  encode("GenesisSeeded", [CHAIN_ID, word(genesis)]),
]);
leaves.push({ leaf_index: 0, kind: "genesis", commitment: word(genesis), tag: null, prefix: "0x000000000000", cell: null });

let number = FIRST_BLOCK;
for (const name of names) {
  seal(++number, await actions[name]());
}
while (nextLeaf < TARGET_LEAVES) {
  number += 1 + below(3);
  const logs = [];
  for (let tx = below(4); tx > 0; tx--) {
    logs.push(...(await actions[names[below(names.length)]]()));
  }
  seal(number, logs);
}
seal(number + 5, []);

const keys = async (derive, high) => {
  const out = [];
  for (let index = 0n; index <= high + LOOKAHEAD; index++) {
    const pub = wallets.publicKey(await derive(index));
    out.push({ index: Number(index), x: word(new Fr(pub[0])), even_y: wallets.isEvenY(pub) });
  }
  return out;
};
const describe = async (w) => ({
  label: w.label,
  sk_root: word(w.skRoot),
  sk_view: word(w.skView),
  self_keys: await keys((i) => wallets.deriveSelfEphemeral(w.skView, i), w.selfHigh),
  incoming_keys: await keys((i) => wallets.deriveIncomingKey(w.skView, i), w.incomingHigh),
  owned_leaves: w.owned,
});

const topic = (name) => iface.getEvent(name).topicHash;
console.log(
  JSON.stringify(
    {
      source: `Howl at ${commit.slice(0, 7)}: pool ABI, wallet key derivation, record encoder, tree`,
      chain_id: Number(CHAIN_ID),
      pool: POOL,
      topics: {
        LeafInserted: topic("LeafInserted"),
        NewNote: topic("NewNote"),
        NewPrivateMemo: topic("NewPrivateMemo"),
        GenesisSeeded: topic("GenesisSeeded"),
      },
      head: number + 5,
      leaf_block_size: wallets.LEAF_BLOCK_SIZE,
      prefix_rule: PREFIX_RULE,
      leaf_count: nextLeaf,
      root: word(tree.getRoot()),
      blocks,
      leaves,
      wallets: [await describe(alice), await describe(bob)],
    },
    null,
    1,
  ),
);
