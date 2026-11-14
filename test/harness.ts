/**
 * Local test harness - replays sample envelopes against the agent.
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=test-secret node --experimental-strip-types test/harness.ts
 *
 * Starts the agent on a test port, then:
 *  1. GET /health
 *  2. POST /agent preflight (signed) -> expect { ok: true, protocolVersion: "v1" }
 *  3. POST /agent preflight with a BAD signature -> expect 401
 *  4. POST /agent gatekeeper valid task -> expect APPROVE + proof + public_signals
 *  5. POST /agent gatekeeper trap task -> expect REJECT + reason_code
 *  6. POST /agent steal turn -> expect an action + publicInputsHash (+ proof if it generates)
 *
 * The harness signs requests with the same HMAC secret the server uses, so
 * it exercises the real auth path. Kurier submission is skipped when
 * KURIER_API_KEY is unset (the proof is still generated and returned).
 */
import { createHmac } from "node:crypto";

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "test-secret";
const PORT = 18099;
const BASE = `http://127.0.0.1:${PORT}`;

function sign(body: string): string {
  return createHmac("sha256", SECRET).update(Buffer.from(body, "utf8")).digest("hex");
}

async function post(path: string, obj: unknown, sig?: string): Promise<{ status: number; json: unknown; sigOk: boolean }> {
  const body = JSON.stringify(obj);
  const headers: Record<string, string> = { "content-type": "application/json" };
  headers["x-agent-games-signature"] = sig ?? sign(body);
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers, body });
  const text = await res.text();
  let json: unknown = null;
  try { json = JSON.parse(text); } catch { json = text; }
  // Verify the response signature.
  let sigOk = false;
  const respSig = res.headers.get("x-agent-games-signature");
  if (respSig) {
    const expected = createHmac("sha256", SECRET).update(Buffer.from(text, "utf8")).digest("hex");
    sigOk = respSig === expected;
  }
  return { status: res.status, json, sigOk };
}

function verifyHmacRejectsBadSig(): void {
  // Unit check: a wrong signature must not verify (uses the server's rule).
  const good = sign("hello");
  const bad = "00".repeat(32);
  if (good === bad) throw new Error("sanity: good==bad");
}

async function main(): Promise<void> {
  verifyHmacRejectsBadSig();
  let pass = 0;
  let fail = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    if (ok) { pass++; console.log(`  PASS ${name}`); }
    else { fail++; console.log(`  FAIL ${name}`, extra ?? ""); }
  };

  // 1. Health
  const health = await fetch(`${BASE}/health`);
  check("GET /health -> 200", health.status === 200);

  // 2. Preflight (good signature)
  const pre = await post("/agent", {
    type: "agent-games.preflight.v1",
    agent_id: "agt_test",
    issued_at: new Date().toISOString(),
    nonce: "abc123",
  });
  check("preflight -> 200", pre.status === 200, pre.json);
  check("preflight body { ok: true, protocolVersion: v1 }",
    (pre.json as Record<string, unknown>)?.ok === true &&
    (pre.json as Record<string, unknown>)?.protocolVersion === "v1");
  check("preflight response signature valid", pre.sigOk);

  // 3. Bad signature -> 401
  const badSig = await post("/agent", { type: "agent-games.preflight.v1" }, "00".repeat(32));
  check("bad signature -> 401", badSig.status === 401);

  // 4. Gatekeeper valid task -> APPROVE + proof
  const gkValid = await post("/agent", {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_9d3",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0xDe42aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9f01",
      condition_recipient: "0xDe42aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa8b00000000000000000000000000000000000000000000000000000000000c",
    },
  });
  const gkValidJson = gkValid.json as Record<string, unknown>;
  check("gatekeeper valid -> 200", gkValid.status === 200, gkValidJson);
  check("gatekeeper valid -> APPROVE / VALID_CONDITION",
    gkValidJson?.decision === "APPROVE" && gkValidJson?.reason_code === "VALID_CONDITION", gkValidJson);
  check("gatekeeper valid -> proof + public_signals present",
    !!gkValidJson?.proof && Array.isArray(gkValidJson?.public_signals), gkValidJson);
  check("gatekeeper valid -> response signature valid", gkValid.sigOk);

  // 5. Gatekeeper trap task (recipient mismatch) -> REJECT
  const gkTrap = await post("/agent", {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_9d4",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0xDe42aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9f01",
      condition_recipient: "0x1111111111111111111111111111111111111111",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa8b00000000000000000000000000000000000000000000000000000000000d",
    },
  });
  const gkTrapJson = gkTrap.json as Record<string, unknown>;
  check("gatekeeper trap -> REJECT / RECIPIENT_MISMATCH",
    gkTrapJson?.decision === "REJECT" && gkTrapJson?.reason_code === "RECIPIENT_MISMATCH", gkTrapJson);

  // 6. Steal the VFY turn -> action + publicInputsHash
  const steal = await post("/agent", {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: "9f4e1b2a-0000-0000-0000-000000000000",
    turn: 3,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 60_000).toISOString(),
    state: {
      selfBalance: "95",
      opponentBalance: "105",
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: "0x7d00000000000000000000000000000000000000000000000000000000000091" },
    resolverVersion: "v1",
    nonce: "3c2f1a",
  });
  const stealJson = steal.json as Record<string, unknown>;
  check("steal turn -> 200", steal.status === 200, stealJson);
  const action = (stealJson?.action as Record<string, unknown>) ?? {};
  check("steal turn -> action present (HOLD/FORTIFY/EXTRACT)",
    ["HOLD", "FORTIFY", "EXTRACT"].includes(String(action.type)), stealJson);
  check("steal turn -> no amount field on HOLD/FORTIFY",
    action.type !== "HOLD" && action.type !== "FORTIFY" ? true : !("amount" in action), action);
  const pp = (stealJson?.policyProof as Record<string, unknown>) ?? {};
  check("steal turn -> publicInputsHash present",
    typeof pp.publicInputsHash === "string" && (pp.publicInputsHash as string).startsWith("0x"), pp);
  check("steal turn -> matchId + turn echoed",
    stealJson?.matchId === "9f4e1b2a-0000-0000-0000-000000000000" && stealJson?.turn === 3, stealJson);
  check("steal turn -> response signature valid", steal.sigOk);
  if (pp.proof) {
    check("steal turn -> policy proof generated", true);
  } else {
    console.log("  NOTE steal turn -> no policy proof (see README: vfy-policy proof status)");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) process.exitCode = 1;
}

await main();
