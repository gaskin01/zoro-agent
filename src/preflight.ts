/**
 * Preflight - runs before any task.
 *
 * After registering and rotating the secret, the platform sends a signed
 * preflight request to verify the endpoint can authenticate and sign
 * responses correctly. The agent must return { ok: true, protocolVersion:
 * "v1" } with a valid x-agent-games-signature header. Preflight must pass
 * before the platform marks the agent active.
 */

export interface PreflightRequest {
  type: "agent-games.preflight.v1";
  agent_id?: string;
  issued_at?: string;
  nonce?: string;
}

export function preflightResponse(): { ok: true; protocolVersion: "v1" } {
  return { ok: true, protocolVersion: "v1" };
}

export function isPreflight(body: unknown): body is PreflightRequest {
  return (
    !!body &&
    typeof body === "object" &&
    (body as Record<string, unknown>).type === "agent-games.preflight.v1"
  );
}
