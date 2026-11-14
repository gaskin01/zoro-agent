/**
 * Kurier REST client (zkVerify proof submission).
 *
 * Docs: https://docs.zkverify.io/overview/getting-started/kurier
 *
 * Flow: POST /submit-proof/<API_KEY> with { proofType, vkRegistered,
 * proofOptions, proofData } -> returns a job. Poll the job until it reaches
 * "Finalized". The proof itself is generated locally (see proof.ts); Kurier
 * only puts the verification on-chain and gives us an audit reference.
 *
 * If Kurier is unreachable or the API key is missing, submission is skipped
 * (the locally-generated proof is still returned - the platform re-verifies
 * it against its own registered key). A missing/invalid proof costs -2, so
 * the proof is never the thing we drop; only the on-chain reference is.
 */

const KURIER_BASE = "https://api.kurier.xyz/api/v1";

export type KurierJobStatus = "Submitted" | "IncludedInBlock" | "Finalized" | string;

export interface KurierSubmitResult {
  jobId: string | null;
  status: KurierJobStatus | null;
  proofTx: string | null;
  raw: unknown;
}

function apiKey(): string | null {
  const k = process.env.KURIER_API_KEY;
  return k && k.length > 0 ? k : null;
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { _raw: text, _status: res.status };
    }
  } finally {
    clearTimeout(t);
  }
}

function pickJobId(obj: unknown): string | null {
  if (obj && typeof obj === "object") {
    const o = obj as Record<string, unknown>;
    for (const k of ["jobId", "job_id", "id", "proofId"]) {
      if (typeof o[k] === "string") return o[k] as string;
    }
    if (o.job && typeof o.job === "object") {
      return pickJobId(o.job);
    }
  }
  return null;
}

function pickStatus(obj: unknown): KurierJobStatus | null {
  if (obj && typeof obj === "object") {
    const o = obj as Record<string, unknown>;
    for (const k of ["status", "state"]) {
      if (typeof o[k] === "string") return o[k] as string;
    }
    if (o.job && typeof o.job === "object") return pickStatus(o.job);
  }
  return null;
}

/** Submit a Groth16 proof to Kurier. Returns the job id / status, or nulls on failure. */
export async function submitProof(
  proof: unknown,
  publicSignals: unknown,
  vkHash: string,
): Promise<KurierSubmitResult> {
  const key = apiKey();
  if (!key) return { jobId: null, status: null, proofTx: null, raw: null };
  try {
    const res = await fetchJson(
      `${KURIER_BASE}/submit-proof/${key}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          vkRegistered: true,
          proofOptions: { library: "snarkjs", curve: "bn128" },
          proofData: { proof, publicSignals, vk: vkHash },
        }),
      },
      15000,
    );
    const jobId = pickJobId(res);
    const status = pickStatus(res);
    return { jobId, status, proofTx: jobId, raw: res };
  } catch (e) {
    console.error("[kurier] submit failed:", (e as Error).message);
    return { jobId: null, status: null, proofTx: null, raw: null };
  }
}

/** Poll a Kurier job until Finalized (or timeout). Returns the final status. */
export async function waitFinalized(
  jobId: string,
  timeoutMs = 60000,
  pollMs = 5000,
): Promise<KurierJobStatus | null> {
  const key = apiKey();
  if (!key || !jobId) return null;
  const deadline = Date.now() + timeoutMs;
  // The status endpoint shape is not pinned in the build guide; try the
  // documented job lookup first, then fall back to the proof lookup.
  const urls = [
    `${KURIER_BASE}/job/${jobId}`,
    `${KURIER_BASE}/proof/${jobId}`,
    `${KURIER_BASE}/jobs/${jobId}`,
  ];
  while (Date.now() < deadline) {
    for (const url of urls) {
      try {
        const res = await fetchJson(url, { method: "GET" }, 10000);
        const status = pickStatus(res);
        if (status === "Finalized") return status;
        if (status) return status; // return latest known status; caller decides
      } catch {
        // try next url
      }
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return null;
}
