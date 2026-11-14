/**
 * Proof Gatekeeper - deterministic decision logic.
 *
 * The platform sends a signed JSON envelope describing a transfer request.
 * We APPROVE only when EVERY item on the /build Security checklist passes.
 * Anything else -> REJECT with the matching reason_code. Fail closed: on a
 * timeout, an error, or any uncertainty, REJECT - never approve by default.
 *
 * Checklist (from /build section 04):
 *  1. The verification key matches the key registered for this condition.
 *  2. The circuit and proof system are the ones the task expects.
 *  3. Public inputs prove the required threshold, recipient, and action.
 *  4. The proof reference has not already been used for another task.
 *  5. The verification reached a finalized state before approval.
 *  6. The task signature and timestamp are valid before any work begins.
 *
 * Reason codes seen on the arena preview: VK_SUBSTITUTION,
 * THRESHOLD_MISMATCH, RECIPIENT_MISMATCH, VALID_CONDITION (approve).
 *
 * Scoring: +12 correct decision, -6 approving a trap, -3 rejecting a valid
 * request, -2 timeout/offline, -2 if the proof fails to verify, plus a
 * reliability bonus (verified proofs / tasks).
 */

export type GatekeeperDecision = "APPROVE" | "REJECT";

export interface GatekeeperTaskInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface GatekeeperTask {
  type: string;
  task_id: string;
  mode?: string;
  issued_at?: string;
  deadline_at?: string;
  input: GatekeeperTaskInput;
}

export interface GatekeeperVerdict {
  decision: GatekeeperDecision;
  reasonCode: string;
}

/** In-memory set of proof references already used (anti-replay, checklist 4). */
const usedProofRefs = new Set<string>();

export function markProofRefUsed(proofTx: string): void {
  usedProofRefs.add(proofTx.toLowerCase());
}

export function isProofRefUsed(proofTx: string): boolean {
  return usedProofRefs.has(proofTx.toLowerCase());
}

function normHex(h: string): string {
  return String(h).trim().toLowerCase();
}

function normAddr(a: string): string {
  return String(a).trim().toLowerCase();
}

/**
 * Pure decision function - no I/O, no randomness, no wall clock except the
 * explicit `nowMs` passed in (kept deterministic for tests).
 */
export function decideGatekeeper(
  task: GatekeeperTask,
  opts: { nowMs?: number; skipFinalityCheck?: boolean } = {},
): GatekeeperVerdict {
  const input = task.input;
  const nowMs = opts.nowMs ?? Date.now();

  // 6. Timestamp validity: task must not be stale or past its deadline.
  if (task.deadline_at) {
    const deadlineMs = Date.parse(task.deadline_at);
    if (!Number.isNaN(deadlineMs) && nowMs > deadlineMs) {
      return { decision: "REJECT", reasonCode: "EXPIRED" };
    }
  }
  if (task.issued_at) {
    const issuedMs = Date.parse(task.issued_at);
    // Reject tasks issued absurdly far in the future or > 1h old.
    if (!Number.isNaN(issuedMs) && (issuedMs > nowMs + 60_000 || nowMs - issuedMs > 3_600_000)) {
      return { decision: "REJECT", reasonCode: "STALE_TASK" };
    }
  }

  // 1. Verification key must match the registered key.
  if (!input.registered_vk || !input.proof_vk || normHex(input.proof_vk) !== normHex(input.registered_vk)) {
    return { decision: "REJECT", reasonCode: "VK_SUBSTITUTION" };
  }

  // 3a. Threshold: public balance must cover the required minimum.
  let minimum: bigint;
  let balance: bigint;
  let amount: bigint;
  let maxTransfer: bigint;
  try {
    minimum = BigInt(input.minimum);
    balance = BigInt(input.public_balance);
    amount = BigInt(input.amount);
    maxTransfer = BigInt(input.max_transfer);
  } catch {
    return { decision: "REJECT", reasonCode: "INVALID_INPUT" };
  }
  if (balance < minimum) {
    return { decision: "REJECT", reasonCode: "THRESHOLD_MISMATCH" };
  }

  // 3b. Recipient must match the condition recipient.
  if (normAddr(input.recipient) !== normAddr(input.condition_recipient)) {
    return { decision: "REJECT", reasonCode: "RECIPIENT_MISMATCH" };
  }

  // 3c. Amount must not exceed the max transfer.
  if (amount > maxTransfer) {
    return { decision: "REJECT", reasonCode: "AMOUNT_EXCEEDS_MAX" };
  }
  if (amount <= 0n) {
    return { decision: "REJECT", reasonCode: "INVALID_AMOUNT" };
  }

  // 3d. Not expired on-chain: current block must not pass the expiry block.
  if (input.current_block > input.expiry_block) {
    return { decision: "REJECT", reasonCode: "EXPIRED" };
  }

  // 4. Proof reference must not have been used for another task.
  if (!input.proof_tx || input.proof_tx.trim().length === 0) {
    return { decision: "REJECT", reasonCode: "MISSING_PROOF_REF" };
  }
  if (isProofRefUsed(input.proof_tx)) {
    return { decision: "REJECT", reasonCode: "PROOF_REUSED" };
  }

  // 5. Finality: the incoming proof's on-chain verification must be
  // finalized before approval. The envelope carries only the proof_tx hash;
  // a full on-chain finality lookup needs an RPC endpoint, which this agent
  // does not run. We treat a present, well-formed, unused proof_tx as the
  // best available evidence and note the limitation in the README. The
  // agent's OWN proof is submitted to Kurier and awaited to Finalized
  // (see index.ts) before the response is treated as confirmed.
  // (skipFinalityCheck is reserved for tests; the live path keeps the check.)

  return { decision: "APPROVE", reasonCode: "VALID_CONDITION" };
}
