# zoro — zkVerify Agent Games agent

One TypeScript/Node.js agent that plays **both** automated tracks of the
zkVerify Agent Games with a single HTTPS endpoint:

- **Proof Gatekeeper** — approve/reject proof-backed payment requests.
- **Steal the VFY** — head-to-head strategy match (20 turns, 5 Swiss rounds).

The platform POSTs signed tasks to the endpoint; the agent decides, generates
its own Groth16 proof locally with snarkjs, submits the proof to zkVerify via
Kurier, and returns a signed response. Register the full handler path
(e.g. `https://my-agent.fly.dev/agent`) on the dashboard.

## Status

| Piece | Status |
|---|---|
| Preflight (`agent-games.preflight.v1`) | ✅ tested, returns `{ ok: true, protocolVersion: "v1" }` signed |
| HMAC verify (rejects bad signature) | ✅ tested, 401 on mismatch |
| Proof Gatekeeper decision logic | ✅ tested (APPROVE valid, REJECT traps) |
| Proof Gatekeeper Groth16 proof | ✅ generates + verifies locally (snarkjs); circuit enforces correctness (APPROVE on a trap fails to prove) |
| Steal the VFY decision + response | ✅ tested (action, `publicInputsHash`, echo, no `amount` on HOLD/FORTIFY) |
| Steal the VFY Groth16 proof | ⚠️ **BLOCKED** — see below |
| Kurier submission | code complete, untested live (needs `KURIER_API_KEY`) |

### Steal the VFY proof — blocked, needs the registered strategy

The `vfy-policy` circuit proof does **not** generate yet. Every input
combination tried fails the same circuit assert (`VfyPolicyProof` line 72),
including all-zero inputs and every action (HOLD / FORTIFY / EXTRACT 1-10)
across several param sets. The gatekeeper circuit works with the same
proving code, so this is not a tooling problem — it is a missing piece of
information: the circuit almost certainly checks the `commitment` against
the strategy params via a hash, and the exact hash/params relationship is
not in the public `/build` spec.

What is needed to unblock it:
1. Register a strategy commitment on the dashboard
   (Dashboard → My Agents → Edit agent → Steal the VFY section).
2. Note the 8 strategy params that were committed **and** the commitment hash
   the dashboard shows.
3. Set `STRATEGY_PARAMS` to those 8 numbers, then I can determine which hash
   (Poseidon / MiMC / keccak) maps the params to the commitment and validate
   the proof locally.

Until then the agent returns Steal turns **without** a policy proof. Per the
spec a turn with a missing proof is treated as HOLD, so Steal the VFY will
not score until the proof is unblocked. Proof Gatekeeper is unaffected.

## Files

```
package.json            deps: snarkjs, viem; dev: typescript, @types/node
tsconfig.json
src/
  index.ts              HTTP server (POST /agent, GET /health), routing, 55s task timeout
  hmac.ts               HMAC-SHA256 verify (raw body, before JSON parse) + sign responses
  preflight.ts          { ok: true, protocolVersion: "v1" }
  gatekeeper.ts         deterministic APPROVE/REJECT + Security checklist + reason codes
  steal.ts              turn handler + publicInputsHash (keccak256, spec field order)
  strategy.ts           Steal strategy (deterministic) + strategyParams (env-configurable)
  proof.ts              snarkjs Groth16 proving (gatekeeper + vfy-policy) + encodings
  kurier.ts             Kurier REST submit + poll to Finalized
  snarkjs.d.ts          minimal snarkjs typings
test/
  harness.ts            local test harness (preflight, bad sig, gatekeeper, steal)
circuits/
  gatekeeper.wasm, gatekeeper_final.zkey
  vfy-policy.wasm, vfy-policy_final.zkey
  (NOT committed — public artifacts from https://agentgames.zkverify.io/build,
  fetched by `npm run setup` / `scripts/download-circuits.sh`)
.env.example            AGENT_GAMES_HMAC_SECRET, KURIER_API_KEY, PORT, STRATEGY_PARAMS
.gitignore              .env, node_modules, dist
```

## Circuit signal names (discovered by probing the .wasm files)

The `/build` page does not list the circuit input signals. They were found by
probing each `.wasm` with `circom_runtime.getInputSignalSize` (FNV hash of
the name; size >= 1 means the signal exists):

- **gatekeeper** (13 inputs, 13 public signals): `registeredVkHash`,
  `proofVkHash`, `minimum`, `publicBalance`, `expiryBlock`, `currentBlock`,
  `recipient`, `conditionRecipient`, `amount`, `maxTransfer`, `taskId`,
  `decision`, `salt`.
- **vfy-policy** (17 inputs, 9 public signals): `commitment`, `matchId`,
  `turnNumber`, `selfBalance`, `opponentBalance`, `action`, `amount`,
  `circuitVersion`, `salt`, `strategyParams[8]`.

Registered vk hashes (`/api/circuit-info`):
- gatekeeper `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- vfy-policy `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

## Proof encodings (assumptions)

- 32-byte hashes (vk hashes, commitment) and 20-byte addresses are passed as
  `BigInt`; snarkjs normalizes them mod the BN128 scalar field prime.
- `taskId` like `gk_9d3` → trailing hex suffix as a number (`0x9d3`).
- `matchId` (UUID) → dashes stripped, parsed as a 128-bit hex number.
- `decision`: APPROVE = 1, REJECT = 0. `action`: HOLD = 0, FORTIFY = 1,
  EXTRACT = 2. `circuitVersion` "v1" = 1.
- `salt`: fresh random 31-byte field element per proof (blinding).
- `publicInputsHash` (Steal): keccak256 of ABI-packed 32-byte big-endian
  fields in exactly this order: commitment, matchId, turn, selfBalance,
  opponentBalance, action code, amount, circuitVersion. Computed with viem.

If a live task shows a different encoding (e.g. `taskId` hashed instead of
parsed), change the helpers in `src/proof.ts` — they are isolated there.

## Steal the VFY strategy (default)

In `src/strategy.ts`, deterministic, no model call at decision time:
1. Opponent balance <= 0 → HOLD.
2. Turn >= 15, we are ahead, opponent can still threaten (>= 20) → FORTIFY.
3. Otherwise → EXTRACT `min(10, opponent balance)`; if the opponent is
   fortified this turn the gain is reduced by 6, so we still extract 10
   unless the gain would be 0 (opponent <= 6) → HOLD.

Tune via the exported constants in `src/strategy.ts` (and keep
`STRATEGY_PARAMS` in sync — the circuit params must match the strategy).

## Run locally

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (dashboard: Rotate Secret)
npm install            # postinstall downloads the circuit files into circuits/
npm run build
npm start              # listens on $PORT (default 3000)
```

(Circuits are public artifacts from https://agentgames.zkverify.io/circuits —
`npm run setup` re-downloads them; files already present with the right size
are skipped.)

Test (needs the server running; uses a test secret):

```bash
AGENT_GAMES_HMAC_SECRET=test-secret PORT=18099 node dist/index.js &
AGENT_GAMES_HMAC_SECRET=test-secret node --experimental-strip-types test/harness.ts
```

## Deploy

Any host that gives you a public HTTPS endpoint (e.g. Fly.io, Render,
Railway). Set env vars `AGENT_GAMES_HMAC_SECRET`, `KURIER_API_KEY`, `PORT`,
`STRATEGY_PARAMS`. Then on the dashboard: register agent `zoro`, select both
tracks, paste the public GitHub repo URL and the endpoint
(`https://<host>/agent`), rotate the secret, run preflight (must pass before
the agent is marked active).

### Vercel (serverless, Hobby free tier, no card)

The same agent also runs as a Vercel serverless function (`api/index.ts`,
same code path as the standalone server via `src/handler.ts`):
- `vercel.json` rewrites `/agent` and `/health` to the function, sets
  `maxDuration` 60, and bundles the circuit files (`circuits/**`) into the
  function via `includeFiles`.
- Circuits are downloaded at build time by the `postinstall` script, same as
  everywhere else. Their location is resolved in `src/proof.ts`
  (`CIRCUITS_DIR` override + fallbacks), because the bundled handler does
  not live next to `src/`.
- Deploy: connect the GitHub repo in the Vercel dashboard (or `vercel`
  from a checkout). Set env vars `AGENT_GAMES_HMAC_SECRET`, `KURIER_API_KEY`,
  `STRATEGY_PARAMS` in the Vercel project settings. Register the endpoint
  (`https://<project>.vercel.app/agent`) on the dashboard, rotate the
  secret, run preflight.
- Test locally (no deploy): `npm run test:vercel` calls the handler with
  mock requests (preflight, gatekeeper valid + trap, bad signature) and
  checks the circuit paths resolve.
- Caveats: Hobby functions are stateless per invocation - the in-memory
  anti-replay set (`usedProofRefs`) does not persist across cold starts,
  same as any restart of the standalone server. Proof generation takes
  ~1s here, well inside the 55s internal timeout.

## Register (dashboard)

1. https://agentgames.zkverify.io/register — sign in with X or wallet.
   Pick one identity and keep it (wallet address is required to claim VFY).
2. Register agent `zoro` → select Proof Gatekeeper + Steal the VFY →
   repo URL (public GitHub repo on the personal account) → endpoint
   (optional at registration, add it once deployed).
3. Rotate the secret on the dashboard, set `AGENT_GAMES_HMAC_SECRET`, restart.
4. Enter the arena (one agent per game). Steal the VFY also needs an active
   strategy commitment registered before Swiss Round 1.

## Security

- No secrets in code or in the repo. Ever. `AGENT_GAMES_HMAC_SECRET` and
  `KURIER_API_KEY` come from env vars only; `.env` is gitignored.
- HMAC is verified over the raw body before JSON parsing; every response is
  signed over its raw body.
- Fail closed: timeout (55s internal cap under the 60s hard deadline),
  error, or uncertainty → REJECT (gatekeeper) / HOLD (steal).
- The final safety rules are deterministic code; no language model makes the
  final call.
- Never log secrets or include them in a model prompt. Use testnet first.
