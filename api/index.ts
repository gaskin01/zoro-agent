/**
 * Vercel serverless entry point for agent "zoro".
 *
 * Same agent, same behavior as the standalone server (src/index.ts) - all
 * decision / proof / Kurier logic lives in src/handler.ts; this file is only
 * the Vercel I/O wrapper (read raw body, call the handler, write the result).
 *
 * Deployed as a Hobby (free, no card) serverless function:
 *   - POST /agent  -> the agent endpoint (rewritten to /api/index in vercel.json)
 *   - GET  /health -> health check (also rewritten)
 *   - bodyParser is OFF: the HMAC must be verified over the exact raw bytes
 *     the platform signed, and Vercel's default JSON parsing would change them.
 *   - maxDuration 60 (vercel.json); the handler itself enforces a 55s
 *     internal timeout and fails closed, so it stays inside the platform's
 *     60s hard deadline.
 *   - Circuit files (circuits/*.wasm, *.zkey) are downloaded at build time
 *     by the postinstall script and bundled via vercel.json includeFiles.
 *     Their location is resolved in src/proof.ts (CIRCUITS_DIR override +
 *     fallbacks), because the bundled handler does not live next to src/.
 *
 * Caveat: Hobby functions are stateless per invocation - the in-memory
 * anti-replay set (usedProofRefs in src/gatekeeper.ts) does not persist
 * across cold starts, same as any restart of the standalone server.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  handleAgentRequest,
  healthPayload,
  readRawBody,
  serializeResult,
} from "../src/handler.js";

export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    if (req.method === "GET") {
      const { status, body, headers } = serializeResult({
        status: 200,
        body: healthPayload(),
        signed: false,
      });
      res.writeHead(status, headers);
      res.end(body);
      return;
    }
    if (req.method === "POST") {
      const raw = await readRawBody(req);
      const signature = req.headers["x-agent-games-signature"];
      const result = await handleAgentRequest(
        raw,
        Array.isArray(signature) ? signature[0] : signature,
      );
      const { status, body, headers } = serializeResult(result);
      res.writeHead(status, headers);
      res.end(body);
      return;
    }
    const { status, body, headers } = serializeResult({
      status: 404,
      body: { error: "not found" },
      signed: false,
    });
    res.writeHead(status, headers);
    res.end(body);
  } catch (e) {
    console.error("[zoro] handler error:", (e as Error).message);
    const { status, body, headers } = serializeResult({
      status: 500,
      body: { error: "internal error" },
      signed: false,
    });
    try {
      res.writeHead(status, headers);
      res.end(body);
    } catch {
      // Response already sent; nothing left to do.
    }
  }
}
