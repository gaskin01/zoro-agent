/**
 * Shared agent request handling.
 *
 * Transport-agnostic core used by BOTH entry points:
 *   - the standalone HTTP server (src/index.ts, `npm start`)
 *   - the Vercel serverless function (api/index.ts)
 *
 * Everything about the decision / proof / Kurier flow lives here so the two
 * entry points cannot drift apart. Entry points only do I/O: read the raw
 * body, hand it to handleAgentRequest, and write the serialized result.
 *
 * Routing is by envelope type:
 *   agent-games.preflight.v1          -> preflight
 *   agent-games.proof-gatekeeper.v1   -> Proof Gatekeeper
 *   eventId "steal-the-vfy"           -> Steal the VFY
 *
 * Security rules (from /build):
 * - Verify the HMAC over the RAW body BEFORE parsing JSON; reject on mismatch.
 * - Sign EVERY response with x-agent-games-signature over the raw body.
 * - 60s hard deadline per task; fail closed (REJECT / HOLD) on timeout/error.
 * - Secrets only from env vars, never logged, never in code.
 */
import type { IncomingMessage } from "node:http";
import { signBody, verifySignature } from "./hmac.js";
import { isPreflight, preflightResponse } from "./preflight.js";
import {
  decideGatekeeper,
  markProofRefUsed,
  type GatekeeperTask,
} from "./gatekeeper.js";
import { buildStealResponse, type StealTurnEnvelope } from "./steal.js";
import { strategyParams, actionCode } from "./strategy.js";
import {
  GATEKEEPER_VK_HASH,
  VFY_POLICY_VK_HASH,
  proveGatekeeper,
  proveVfyPolicy,
} from "./proof.js";
import { submitProof, waitFinalized } from "./kurier.js";

export const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "";

if (!HMAC_SECRET) {
  console.warn(
    "[zoro] WARNING: AGENT_GAMES_HMAC_SECRET is not set - all signed requests will be rejected. " +
      "Set it from the dashboard (Rotate Secret) before going live.",
  );
}

export const TASK_TIMEOUT_MS = 55_000; // 5s margin under the platform's 60s hard deadline

/** Read the exact raw request body bytes (needed for HMAC verification). */
export function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export interface AgentResult {
  status: number;
  body: unknown;
  /** True when the response must carry x-agent-games-signature. */
  signed: boolean;
}

/** Serialize a result to raw body bytes + headers (signs when required). */
export function serializeResult(result: AgentResult): {
  status: number;
  body: Buffer;
  headers: Record<string, string>;
} {
  const body = Buffer.from(JSON.stringify(result.body), "utf8");
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (result.signed && HMAC_SECRET) {
    headers["x-agent-games-signature"] = signBody(HMAC_SECRET, body);
  }
  return { status: result.status, body, headers };
}

export function healthPayload(): { ok: boolean; agent: string; tracks: string[] } {
  return { ok: true, agent: "zoro", tracks: ["proof-gatekeeper", "steal-the-vfy"] };
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | "timeout"> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), ms);
  });
  const result = await Promise.race([p, timeout]);
  if (timer) clearTimeout(timer);
  return result;
}

async function handleGatekeeper(task: GatekeeperTask): Promise<unknown> {
  const verdict = decideGatekeeper(task);
  const decisionNum = verdict.decision === "APPROVE" ? 1 : 0;

  // Generate the agent's own Groth16 proof of the decision.
  let proof: unknown;
  let publicSignals: string[] | undefined;
  let proofTx: string | undefined;
  try {
    const out = await withTimeout(
      proveGatekeeper({
        registeredVk: task.input.registered_vk,
        proofVk: task.input.proof_vk,
        minimum: task.input.minimum,
        publicBalance: task.input.public_balance,
        expiryBlock: task.input.expiry_block,
        currentBlock: task.input.current_block,
        recipient: task.input.recipient,
        conditionRecipient: task.input.condition_recipient,
        amount: task.input.amount,
        maxTransfer: task.input.max_transfer,
        taskId: task.task_id,
        decision: decisionNum as 0 | 1,
      }),
      40_000,
    );
    if (out !== "timeout") {
      proof = out.proof;
      publicSignals = out.publicSignals;
      // Submit to Kurier for the on-chain record; wait briefly for Finalized.
      const sub = await submitProof(proof, publicSignals, GATEKEEPER_VK_HASH);
      if (sub.jobId) {
        proofTx = sub.proofTx ?? undefined;
        const finalStatus = await withTimeout(
          waitFinalized(sub.jobId, 10_000, 3_000),
          12_000,
        );
        if (finalStatus === "Finalized") {
          console.log(`[gatekeeper] ${task.task_id}: proof finalized on Kurier (job ${sub.jobId})`);
        }
      }
    } else {
      console.error(`[gatekeeper] ${task.task_id}: proof generation timed out`);
    }
  } catch (e) {
    // A missing/invalid proof costs -2; the decision is still scored.
    console.error(`[gatekeeper] ${task.task_id}: proof failed:`, (e as Error).message);
  }

  // Anti-replay: mark the proof reference used only once we approved.
  if (verdict.decision === "APPROVE") markProofRefUsed(task.input.proof_tx);

  const response: Record<string, unknown> = {
    decision: verdict.decision,
    reason_code: verdict.reasonCode,
  };
  if (proof !== undefined) response.proof = proof;
  if (publicSignals !== undefined) response.public_signals = publicSignals;
  if (proofTx) response.proof_tx = proofTx;
  return response;
}

async function handleSteal(env: StealTurnEnvelope): Promise<unknown> {
  // Build the response shape + strategy decision first (fast, deterministic).
  const base = buildStealResponse(env);
  const action = base.action.type;
  const amount = action === "EXTRACT" ? base.action.amount : 0;

  let proof: unknown;
  let publicSignals: string[] | undefined;
  let proofReference: string | undefined;
  try {
    const out = await withTimeout(
      proveVfyPolicy({
        commitment: env.strategyCommitment.hash,
        matchId: env.matchId,
        turn: env.turn,
        selfBalance: Number(env.state.selfBalance),
        opponentBalance: Number(env.state.opponentBalance),
        action: actionCode(action),
        amount,
        circuitVersion: 1,
        strategyParams: strategyParams(),
      }),
      40_000,
    );
    if (out !== "timeout") {
      proof = out.proof;
      publicSignals = out.publicSignals;
      const sub = await submitProof(proof, publicSignals, VFY_POLICY_VK_HASH);
      if (sub.jobId) {
        proofReference = sub.proofTx ?? undefined;
        await withTimeout(waitFinalized(sub.jobId, 10_000, 3_000), 12_000);
      }
    } else {
      console.error(`[steal] ${env.matchId} turn ${env.turn}: proof generation timed out`);
    }
  } catch (e) {
    console.error(`[steal] ${env.matchId} turn ${env.turn}: proof failed:`, (e as Error).message);
  }

  return buildStealResponse(env, proof, publicSignals, proofReference);
}

/**
 * Handle one POST /agent request. `raw` is the exact request body bytes;
 * `signature` is the x-agent-games-signature header value (if any).
 */
export async function handleAgentRequest(
  raw: Buffer,
  signature: string | undefined,
): Promise<AgentResult> {
  // Verify HMAC BEFORE parsing JSON.
  if (!HMAC_SECRET || !verifySignature(HMAC_SECRET, raw, signature)) {
    return { status: 401, body: { error: "invalid signature" }, signed: false };
  }

  let body: unknown;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    return { status: 400, body: { error: "invalid json" }, signed: true };
  }

  // Preflight.
  if (isPreflight(body)) {
    return { status: 200, body: preflightResponse(), signed: true };
  }

  const type = (body as Record<string, unknown>).type as string | undefined;
  const eventId = (body as Record<string, unknown>).eventId as string | undefined;

  // Whole-task timeout: fail closed.
  const result = await withTimeout(
    (async () => {
      if (type === "agent-games.proof-gatekeeper.v1") {
        return await handleGatekeeper(body as GatekeeperTask);
      }
      if (eventId === "steal-the-vfy") {
        return await handleSteal(body as StealTurnEnvelope);
      }
      return { error: `unknown envelope (type=${type ?? "?"}, eventId=${eventId ?? "?"})` };
    })(),
    TASK_TIMEOUT_MS,
  );

  if (result === "timeout") {
    // Fail closed: REJECT a gatekeeper task, HOLD a steal turn.
    if (type === "agent-games.proof-gatekeeper.v1") {
      return { status: 200, body: { decision: "REJECT", reason_code: "TIMEOUT" }, signed: true };
    }
    return { status: 200, body: buildStealResponse(body as StealTurnEnvelope), signed: true };
  }
  if (result && typeof result === "object" && "error" in (result as Record<string, unknown>)) {
    return { status: 400, body: result, signed: true };
  }
  return { status: 200, body: result, signed: true };
}
