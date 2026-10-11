import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_COMMIT = "dda803a3910da1adcb74f750e797e14bd033d091";
const ENV_NAME = "HOWL_ROOT";

const importFrom = (root, relative) => import(pathToFileURL(resolve(root, relative)).href);

/** Loads Howl's own wallet code, harness indexer and compiled pool ABI from a built checkout. */
export const loadHowl = async () => {
  const root = process.env[ENV_NAME]?.trim();
  if (!root) {
    throw new Error(`${ENV_NAME} must point to a built Howl checkout`);
  }

  let commit;
  try {
    commit = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch (error) {
    throw new Error(`${ENV_NAME} is not a git checkout`, { cause: error });
  }
  if (commit !== EXPECTED_COMMIT) {
    throw new Error(`${ENV_NAME} is at ${commit}; expected ${EXPECTED_COMMIT}`);
  }

  let wallets;
  let harness;
  let ethers;
  let artifact;
  try {
    [wallets, harness, ethers, artifact] = await Promise.all([
      importFrom(root, "packages/wallets/dist/index.js"),
      importFrom(root, "packages/howl-e2e/dist/index.js"),
      importFrom(root, "packages/wallets/node_modules/ethers/lib.esm/index.js"),
      readFile(
        resolve(root, "packages/evm-contracts/artifacts/contracts/DarkPool.sol/DarkPool.json"),
        "utf8",
      ).then(JSON.parse),
    ]);
  } catch (error) {
    throw new Error(`${ENV_NAME} is missing a build output the generator reads`, { cause: error });
  }

  const required = [
    "Fr",
    "deriveViewKey",
    "deriveSelfEphemeral",
    "deriveIncomingKey",
    "canonicalSelfTag",
    "canonicalIncomingAddress",
    "publicKey",
    "isEvenY",
    "newSeededTree",
    "genesisLeaf",
    "encodeHowlNoteRecord",
    "LEAF_BLOCK_SIZE",
  ];
  for (const name of required) {
    if (wallets[name] === undefined) {
      throw new Error(`${ENV_NAME} wallet build does not export ${name}`);
    }
  }
  if (typeof harness.toRecord !== "function" || typeof harness.tagOf !== "function") {
    throw new Error(`${ENV_NAME} harness build does not export toRecord and tagOf`);
  }

  return { commit, wallets, harness, ethers, abi: artifact.abi };
};
