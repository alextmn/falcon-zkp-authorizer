import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { network } from "hardhat";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_FILES_DIR = join(__dirname, "../test-files");

interface CalldataEntry {
  index: number;
  calldata: string;
}

type ParsedCalldata = [
  [string, string],
  [[string, string], [string, string]],
  [string, string],
  [string, string, string],
];

function parseCalldata(raw: string): ParsedCalldata {
  return JSON.parse("[" + raw + "]") as ParsedCalldata;
}

function toArgs(parsed: ParsedCalldata) {
  const [pA, pB, pC, pub] = parsed;
  return [
    [BigInt(pA[0]), BigInt(pA[1])] as [bigint, bigint],
    [
      [BigInt(pB[0][0]), BigInt(pB[0][1])],
      [BigInt(pB[1][0]), BigInt(pB[1][1])],
    ] as [[bigint, bigint], [bigint, bigint]],
    [BigInt(pC[0]), BigInt(pC[1])] as [bigint, bigint],
    [BigInt(pub[0]), BigInt(pub[1]), BigInt(pub[2])] as [bigint, bigint, bigint],
  ] as const;
}

function loadTestFiles(): { file: string; entries: CalldataEntry[] }[] {
  const jsonFiles = readdirSync(TEST_FILES_DIR).filter((f) =>
    f.endsWith(".json"),
  );

  return jsonFiles.map((file) => {
    const raw = readFileSync(join(TEST_FILES_DIR, file), "utf-8");
    const entries = JSON.parse(raw) as CalldataEntry[];
    return { file, entries };
  });
}

const { viem } = await network.connect();

describe("Groth16Verifier (FalconVerifier)", function () {
  const testFiles = loadTestFiles();

  for (const { file, entries } of testFiles) {
    describe(`Test file: ${file}`, function () {
      let verifier: Awaited<ReturnType<typeof viem.deployContract>>;

      before(async function () {
        verifier = await viem.deployContract("Groth16Verifier");
      });

      for (const entry of entries) {
        it(`verifyProof passes for index ${entry.index}`, async function () {
          const parsed = parseCalldata(entry.calldata);
          const args = toArgs(parsed);

          const result = await verifier.read.verifyProof(args);

          assert.equal(result, true, `Proof at index ${entry.index} should be valid`);
        });
      }
    });
  }
});
