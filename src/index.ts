/**
 * Agent "zoro" - standalone HTTP server entry point (`npm start`).
 *
 * Thin I/O wrapper: all request handling lives in src/handler.ts, which is
 * shared with the Vercel serverless entry point (api/index.ts).
 *
 *   GET  / or /health  -> health payload (unsigned)
 *   POST /agent or /   -> signed agent tasks (preflight / gatekeeper / steal)
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  handleAgentRequest,
  healthPayload,
  readRawBody,
  serializeResult,
  type AgentResult,
} from "./handler.js";

const PORT = Number(process.env.PORT ?? 3000);

function sendResult(res: ServerResponse, result: AgentResult): void {
  const { status, body, headers } = serializeResult(result);
  res.writeHead(status, headers);
  res.end(body);
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/health")) {
      sendResult(res, { status: 200, body: healthPayload(), signed: false });
      return;
    }
    if (req.method === "POST" && (req.url === "/agent" || req.url === "/")) {
      const raw = await readRawBody(req as IncomingMessage);
      const result = await handleAgentRequest(
        raw,
        req.headers["x-agent-games-signature"] as string | undefined,
      );
      sendResult(res, result);
      return;
    }
    sendResult(res, { status: 404, body: { error: "not found" }, signed: false });
  } catch (e) {
    console.error("[zoro] handler error:", (e as Error).message);
    sendResult(res, { status: 500, body: { error: "internal error" }, signed: false });
  }
});

server.listen(PORT, () => {
  console.log(`[zoro] listening on port ${PORT} (POST /agent, GET /health)`);
});
