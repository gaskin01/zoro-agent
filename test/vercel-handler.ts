/**
 * Local test for the Vercel serverless entry point (api/index.ts).
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=test-secret node --experimental-strip-types test/vercel-handler.ts
 *
 * Calls the exported Vercel handler directly with mock req/res objects
 * (no HTTP server, no deployment), using the same signed envelopes as
 * test/harness.ts:
 *
 * HOW THE HANDLER IS LOADED: this Node (v24.22.1) does not resolve the
 * repo's NodeNext `.js` import specifiers to `.ts` files under
 * --experimental-strip-types (even `npm run dev` fails the same way), so
 * the test runs against the COMPILED handler: `npm run test:vercel`
 * first compiles src + api to dist-test/ (gitignored) with
 * tsconfig.test.json, then the test imports ../dist-test/api/index.js.
 * The circuit resolver is unit-tested from SOURCE (../src/proof.ts) because
 * proof.ts has no relative imports, so it loads under strip-types directly.
 *  1. GET /health -> 200
 *  2. POST /agent preflight (signed) -> 200 { ok: true, protocolVersion: "v1" }
 *     with a valid x-agent-games-signature
 *  3. POST /agent preflight with a BAD signature -> 401
 *  4. POST /agent gatekeeper valid task -> APPROVE + proof + public_signals
 *  5. POST /agent gatekeeper trap task -> REJECT / RECIPIENT_MISMATCH
 *  6. Circuit resolution: all 4 artifacts resolve to existing files, and
 *     still resolve after process.chdir() away from the repo root (the
 *     resolver must not depend on cwd).
 *
 * Kurier submission is skipped when KURIER_API_KEY is unset (the proof is
 * still generated and returned).
 */
import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import { Readable } from "node:stream";
import handler from "../dist-test/api/index.js";
import { resolveCircuitPath } from "../src/proof.ts";

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "test-secret";

function sign(body: string): string {
  return createHmac("sha256", SECRET).update(Buffer.from(body, "utf8")).digest("hex");
}

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  done: Promise<void>;
}

function mockReq(method: string, body: string, sig?: string): unknown {
  const stream = Readable.from([Buffer.from(body, "utf8")]);
  Object.assign(stream, {
    method,
    url: method === "GET" ? "/health" : "/agent",
    headers: {
      "content-type": "application/json",
      ...(sig !== undefined ? { "x-agent-games-signature": sig } : {}),
    },
  });
  return stream;
}

function mockRes(): { res: unknown; captured: Captured } {
  let resolve!: () => void;
  const done = new Promise<void>((r) => {
    resolve = r;
  });
  const captured: Captured = { status: 0, headers: {}, body: Buffer.alloc(0), done };
  const res = {
    writeHead(status: number, headers: Record<string, string>) {
      captured.status = status;
      captured.headers = headers;
      return this;
    },
    end(data?: Buffer | string) {
      if (data !== undefined) {
        captured.body = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
      }
      resolve();
      return this;
    },
  };
  return { res, captured };
}

async function callHandler(
  method: string,
  obj?: unknown,
  sig?: string,
): Promise<{ status: number; json: unknown; sigOk: boolean; raw: string }> {
  const body = obj === undefined ? "" : JSON.stringify(obj);
  const req = mockReq(method, body, sig);
  const { res, captured } = mockRes();
  await (handler as (req: unknown, res: unknown) => Promise<void>)(req, res);
  await captured.done;
  const raw = captured.body.toString("utf8");
  let json: unknown = null;
  try {
    json = JSON.parse(raw);
  } catch {
    json = raw;
  }
  let sigOk = false;
  const respSig = captured.headers["x-agent-games-signature"];
  if (respSig) {
    const expected = createHmac("sha256", SECRET).update(Buffer.from(raw, "utf8")).digest("hex");
    sigOk = respSig === expected;
  }
  return { status: captured.status, json, sigOk, raw };
}

async function main(): Promise<void> {
  let pass = 0;
  let fail = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    if (ok) {
      pass++;
      console.log(`  PASS ${name}`);
    } else {
      fail++;
      console.log(`  FAIL ${name}`, extra ?? "");
    }
  };

  // 1. Health
  const health = await callHandler("GET");
  check("GET /health -> 200", health.status === 200, health.json);
  check(
    "GET /health body { ok: true, agent: zoro }",
    (health.json as Record<string, unknown>)?.ok === true &&
      (health.json as Record<string, unknown>)?.agent === "zoro",
    health.json,
  );

  // 2. Preflight (good signature)
  const preBody = JSON.stringify({
    type: "agent-games.preflight.v1",
    agent_id: "agt_test",
    issued_at: new Date().toISOString(),
    nonce: "abc123",
  });
  const preSigned = await callHandler("POST", JSON.parse(preBody), sign(preBody));
  check("preflight -> 200", preSigned.status === 200, preSigned.json);
  check(
    "preflight body { ok: true, protocolVersion: v1 }",
    (preSigned.json as Record<string, unknown>)?.ok === true &&
      (preSigned.json as Record<string, unknown>)?.protocolVersion === "v1",
  );
  check("preflight response signature valid", preSigned.sigOk);

  // 3. Bad signature -> 401
  const badSig = await callHandler(
    "POST",
    { type: "agent-games.preflight.v1" },
    "00".repeat(32),
  );
  check("bad signature -> 401", badSig.status === 401, badSig.json);

  // 4. Gatekeeper valid task -> APPROVE + proof
  const gkValidBody = JSON.stringify({
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
  const gkValid = await callHandler("POST", JSON.parse(gkValidBody), sign(gkValidBody));
  const gkValidJson = gkValid.json as Record<string, unknown>;
  check("gatekeeper valid -> 200", gkValid.status === 200, gkValidJson);
  check(
    "gatekeeper valid -> APPROVE / VALID_CONDITION",
    gkValidJson?.decision === "APPROVE" && gkValidJson?.reason_code === "VALID_CONDITION",
    gkValidJson,
  );
  check(
    "gatekeeper valid -> proof + public_signals present",
    !!gkValidJson?.proof && Array.isArray(gkValidJson?.public_signals),
    gkValidJson,
  );
  check("gatekeeper valid -> response signature valid", gkValid.sigOk);

  // 5. Gatekeeper trap task (recipient mismatch) -> REJECT
  const gkTrapBody = JSON.stringify({
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
  const gkTrap = await callHandler("POST", JSON.parse(gkTrapBody), sign(gkTrapBody));
  const gkTrapJson = gkTrap.json as Record<string, unknown>;
  check(
    "gatekeeper trap -> REJECT / RECIPIENT_MISMATCH",
    gkTrapJson?.decision === "REJECT" && gkTrapJson?.reason_code === "RECIPIENT_MISMATCH",
    gkTrapJson,
  );

  // 6. Circuit resolution
  const files = [
    "gatekeeper.wasm",
    "gatekeeper_final.zkey",
    "vfy-policy.wasm",
    "vfy-policy_final.zkey",
  ];
  for (const f of files) {
    const p = resolveCircuitPath(f);
    check(`circuit resolves + exists: ${f}`, existsSync(p), p);
    console.log(`    -> ${p}`);
  }
  // Fallback sanity: resolving must not depend on the working directory.
  const before = files.map((f) => resolveCircuitPath(f));
  process.chdir("/tmp");
  const after = files.map((f) => resolveCircuitPath(f));
  check(
    "circuit paths identical after chdir to /tmp (cwd-independent)",
    before.every((p, i) => p === after[i]),
    { before, after },
  );
  process.chdir(new URL("..", import.meta.url).pathname);

  console.log(`\n${pass} passed, ${fail} failed`);
  // Exit explicitly: snarkjs leaves worker threads (MessagePorts) alive
  // after proof generation, which would keep this process hanging for
  // minutes after the checks finish. The responses themselves are fast;
  // this only affects the test runner's shutdown, not the deployed function
  // (Vercel freezes the instance after the response is sent).
  process.exit(fail > 0 ? 1 : 0);
}

await main();
