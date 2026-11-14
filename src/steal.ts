import { randomUUID } from "node:crypto";
import { keccak256, concat, numberToHex } from "viem";
import { actionCode, decideSteal, strategyParams, type StealState } from "./strategy.js";

/**
 * Steal the VFY - turn handler.
 *
 * The platform posts a signed turn envelope. We echo matchId + turn, declare
 * our action, and attach the policy proof. policyProof.publicInputsHash is
 * the keccak256 of ABI-packed fields in EXACTLY this order (from /build):
 *   commitment, matchId (32-byte), turn, selfBalance, opponentBalance,
 *   action code (HOLD=0, FORTIFY=1, EXTRACT=2), amount (0 for HOLD/FORTIFY),
 *   circuitVersion "v1" -> 1.
 * Each field is padded to 32 bytes big-endian. The platform independently
 * computes this hash and rejects any proof where the hashes diverge, so the
 * order and padding must match exactly.
 *
 * NEVER send action.amount for HOLD or FORTIFY - omit the field entirely;
 * the schema rejects the field even when it is 0.
 * Fresh idempotencyKey per turn - only the first submission per key is
 * accepted, never reuse one.
 */

export interface StealTurnEnvelope {
  protocolVersion?: string;
  eventId: string;
  mode?: string;
  matchId: string;
  turn: number;
  issuedAt?: string;
  deadlineAt?: string;
  state: {
    selfBalance: string | number;
    opponentBalance: string | number;
    selfFortifiedUntilTurn: number | null;
    opponentFortifiedUntilTurn: number | null;
  };
  strategyCommitment: { hash: string };
  resolverVersion?: string;
  nonce?: string;
}

export interface StealTurnResponse {
  matchId: string;
  turn: number;
  action: { type: "HOLD" } | { type: "FORTIFY" } | { type: "EXTRACT"; amount: number };
  policyProof: {
    circuitVersion: string;
    proof?: unknown;
    publicSignals?: string[];
    proofReference?: string;
    publicInputsHash: string;
  };
  agentTimestamp: string;
  idempotencyKey: string;
}

/** keccak256 of the ABI-packed public inputs, in the spec's exact order. */
export function computePublicInputsHash(
  commitment: string,
  matchId: string,
  turn: number,
  selfBalance: number,
  opponentBalance: number,
  action: "HOLD" | "FORTIFY" | "EXTRACT",
  amount: number,
  circuitVersion = 1,
): string {
  const matchIdHex = "0x" + matchId.replace(/-/g, "");
  return keccak256(
    concat([
      numberToHex(BigInt(commitment), { size: 32 }),
      numberToHex(BigInt(matchIdHex), { size: 32 }),
      numberToHex(BigInt(turn), { size: 32 }),
      numberToHex(BigInt(selfBalance), { size: 32 }),
      numberToHex(BigInt(opponentBalance), { size: 32 }),
      numberToHex(BigInt(actionCode(action)), { size: 32 }),
      numberToHex(BigInt(amount), { size: 32 }),
      numberToHex(BigInt(circuitVersion), { size: 32 }),
    ]),
  );
}

/** Pure turn decision + response shape (proof attached by the caller). */
export function buildStealResponse(
  env: StealTurnEnvelope,
  proof?: unknown,
  publicSignals?: string[],
  proofReference?: string,
): StealTurnResponse {
  const state: StealState = {
    selfBalance: Number(env.state.selfBalance),
    opponentBalance: Number(env.state.opponentBalance),
    selfFortifiedUntilTurn: env.state.selfFortifiedUntilTurn,
    opponentFortifiedUntilTurn: env.state.opponentFortifiedUntilTurn,
  };
  const decision = decideSteal(state, env.turn);
  const amount = decision.action === "EXTRACT" ? (decision.amount ?? 0) : 0;
  const publicInputsHash = computePublicInputsHash(
    env.strategyCommitment.hash,
    env.matchId,
    env.turn,
    state.selfBalance,
    state.opponentBalance,
    decision.action,
    amount,
    1,
  );

  const action =
    decision.action === "EXTRACT"
      ? { type: "EXTRACT" as const, amount: decision.amount ?? 0 }
      : decision.action === "FORTIFY"
        ? { type: "FORTIFY" as const }
        : { type: "HOLD" as const };

  const policyProof: StealTurnResponse["policyProof"] = {
    circuitVersion: "v1",
    publicInputsHash,
  };
  if (proof !== undefined) policyProof.proof = proof;
  if (publicSignals !== undefined) policyProof.publicSignals = publicSignals;
  if (proofReference) policyProof.proofReference = proofReference;

  return {
    matchId: env.matchId,
    turn: env.turn,
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
  };
}

export { strategyParams };
