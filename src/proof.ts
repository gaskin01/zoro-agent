import { randomBytes } from "node:crypto";
import * as snarkjs from "snarkjs";

/**
 * Local Groth16 proof generation with snarkjs.
 *
 * Circuit signal names were discovered by probing the shipped .wasm files
 * (circom_runtime `getInputSignalSize`): a name that exists returns >= 1.
 *
 * GATEKEEPER (13 inputs, 13 public signals - all inputs public except the
 * private `salt` blinding factor, plus 1 public output validity flag):
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   taskId, decision, salt
 *
 * VFY-POLICY (17 inputs, 9 public signals - the 8 game fields public,
 * `salt` + `strategyParams[8]` private, plus 1 public output flag):
 *   commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
 *   amount, circuitVersion, salt, strategyParams[8]
 *
 * ENCODINGS (assumptions - see README "Proof encodings"):
 * - 32-byte hashes (vk hashes, commitment) and 20-byte addresses are passed
 *   as BigInt; snarkjs normalizes them mod the BN128 scalar field prime.
 * - taskId like "gk_9d3" -> the trailing hex suffix as a number (0x9d3).
 * - matchId (UUID) -> dashes stripped, parsed as a 128-bit hex number.
 * - decision: APPROVE = 1, REJECT = 0.  action: HOLD = 0, FORTIFY = 1,
 *   EXTRACT = 2.  circuitVersion "v1" = 1.
 * - salt: fresh random field element per proof (blinding / uniqueness).
 */

const PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
export const VFY_POLICY_VK_HASH =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

const GATEKEEPER_WASM = new URL("../circuits/gatekeeper.wasm", import.meta.url).pathname;
const GATEKEEPER_ZKEY = new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname;
const VFY_WASM = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const VFY_ZKEY = new URL("../circuits/vfy-policy_final.zkey", import.meta.url).pathname;

export function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : "0x" + hex);
}

export function taskIdToBigInt(taskId: string): bigint {
  const m = String(taskId).match(/([0-9a-fA-F]+)$/);
  if (m) return BigInt("0x" + m[1]);
  let h = 0n;
  for (const ch of String(taskId)) h = (h * 31n + BigInt(ch.charCodeAt(0))) % PRIME;
  return h;
}

export function uuidToBigInt(uuid: string): bigint {
  return BigInt("0x" + String(uuid).replace(/-/g, ""));
}

export function randomSalt(): bigint {
  // 31 random bytes -> safely below the field prime.
  return BigInt("0x" + randomBytes(31).toString("hex")) % PRIME;
}

export interface Groth16ProofOut {
  proof: unknown;
  publicSignals: string[];
}

export interface GatekeeperProofInput {
  registeredVk: string;
  proofVk: string;
  minimum: bigint | number | string;
  publicBalance: bigint | number | string;
  expiryBlock: bigint | number | string;
  currentBlock: bigint | number | string;
  recipient: string;
  conditionRecipient: string;
  amount: bigint | number | string;
  maxTransfer: bigint | number | string;
  taskId: string;
  decision: 0 | 1;
}

export async function proveGatekeeper(input: GatekeeperProofInput): Promise<Groth16ProofOut> {
  const circuitInput = {
    registeredVkHash: hexToBigInt(input.registeredVk),
    proofVkHash: hexToBigInt(input.proofVk),
    minimum: BigInt(input.minimum),
    publicBalance: BigInt(input.publicBalance),
    expiryBlock: BigInt(input.expiryBlock),
    currentBlock: BigInt(input.currentBlock),
    recipient: hexToBigInt(input.recipient),
    conditionRecipient: hexToBigInt(input.conditionRecipient),
    amount: BigInt(input.amount),
    maxTransfer: BigInt(input.maxTransfer),
    taskId: taskIdToBigInt(input.taskId),
    decision: BigInt(input.decision),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    GATEKEEPER_WASM,
    GATEKEEPER_ZKEY,
  );
  return { proof, publicSignals: publicSignals.map(String) };
}

export interface VfyProofInput {
  commitment: string;
  matchId: string;
  turn: number | bigint;
  selfBalance: number | bigint;
  opponentBalance: number | bigint;
  action: 0 | 1 | 2;
  amount: number | bigint;
  circuitVersion?: number | bigint;
  strategyParams: bigint[];
}

export async function proveVfyPolicy(input: VfyProofInput): Promise<Groth16ProofOut> {
  if (input.strategyParams.length !== 8) {
    throw new Error(`strategyParams must have exactly 8 elements, got ${input.strategyParams.length}`);
  }
  const circuitInput = {
    commitment: hexToBigInt(input.commitment),
    matchId: uuidToBigInt(input.matchId),
    turnNumber: BigInt(input.turn),
    selfBalance: BigInt(input.selfBalance),
    opponentBalance: BigInt(input.opponentBalance),
    action: BigInt(input.action),
    amount: BigInt(input.amount),
    circuitVersion: BigInt(input.circuitVersion ?? 1),
    salt: randomSalt(),
    strategyParams: input.strategyParams.map((v) => BigInt(v)),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    VFY_WASM,
    VFY_ZKEY,
  );
  return { proof, publicSignals: publicSignals.map(String) };
}
