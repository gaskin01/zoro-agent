/**
 * Steal the VFY - default strategy (deterministic, no randomness).
 *
 * Game: 100 VFY starting balance per agent, 20 turns per match, 5 Swiss
 * rounds. Actions:
 *   HOLD    - 0 VFY. Safe pass.
 *   FORTIFY - costs 2 VFY. Blocks up to 6 VFY of incoming extraction THIS turn.
 *   EXTRACT N - steals up to N VFY (max 10) from the opponent's spendable
 *               balance. A fortified opponent reduces the effective gain by 6.
 *               Both agents can EXTRACT simultaneously.
 *
 * The strategy lives in its own file on purpose: the circuit proves the
 * action follows the committed policy, so the policy must be explicit,
 * deterministic code - never a language-model call at decision time.
 *
 * Default policy (simple, documented, easy to tune):
 *   1. Nothing to take (opponent balance <= 0) -> HOLD.
 *   2. Late game (turn >= 15) and we are ahead -> FORTIFY to protect the lead.
 *      Cost 2, blocks up to 6 - worth it when the lead is worth defending.
 *   3. Otherwise -> EXTRACT min(10, opponent balance).
 *      - If the opponent is fortified this turn, an EXTRACT of 10 still gains
 *        10 - 6 = 4, so we still extract - unless the opponent's balance is
 *        so low (<= 6) that the gain would be 0, in which case HOLD.
 *   4. Never EXTRACT more than the opponent's spendable balance.
 *
 * Tuning knobs are the exported constants below. The 8 circuit
 * `strategyParams` are these knobs, in order (see proof.ts):
 *   [extractMax, fortifyTurn, fortifyLead, fortifyMinOpp, 0, 0, 0, 0]
 * Unused slots are 0 (reserved for future tuning).
 */

export const EXTRACT_MAX = 10;
export const FORTIFY_TURN = 15; // from this turn on, protect a lead
export const FORTIFY_LEAD = 1; // fortify when ahead by at least this much
export const FORTIFY_MIN_OPP = 20; // ...and the opponent can still threaten us
export const FORTIFY_BLOCK = 6; // how much incoming extraction fortify blocks
export const FORTIFY_COST = 2; // VFY paid to fortify

export type StealActionType = "HOLD" | "FORTIFY" | "EXTRACT";

export interface StealState {
  selfBalance: number;
  opponentBalance: number;
  selfFortifiedUntilTurn: number | null;
  opponentFortifiedUntilTurn: number | null;
}

export interface StealDecision {
  action: StealActionType;
  /** Amount for EXTRACT only. OMIT the field entirely for HOLD/FORTIFY. */
  amount?: number;
}

export function isFortified(fortifiedUntilTurn: number | null, turn: number): boolean {
  return fortifiedUntilTurn !== null && fortifiedUntilTurn > turn;
}

/** Pure strategy function - deterministic, no I/O, no randomness. */
export function decideSteal(state: StealState, turn: number): StealDecision {
  const opp = state.opponentBalance;
  const self = state.selfBalance;

  // 1. Nothing to take.
  if (opp <= 0) return { action: "HOLD" };

  // Opponent fortified this turn: extraction is reduced by FORTIFY_BLOCK.
  const oppFortified = isFortified(state.opponentFortifiedUntilTurn, turn);
  const maxGain = oppFortified
    ? Math.max(0, Math.min(EXTRACT_MAX, opp) - FORTIFY_BLOCK)
    : Math.min(EXTRACT_MAX, opp);
  if (maxGain <= 0) return { action: "HOLD" };

  // 2. Late game, ahead, opponent can still hurt us -> protect the lead.
  if (
    turn >= FORTIFY_TURN &&
    self - opp >= FORTIFY_LEAD &&
    opp >= FORTIFY_MIN_OPP &&
    !isFortified(state.selfFortifiedUntilTurn, turn)
  ) {
    return { action: "FORTIFY" };
  }

  // 3. Default: take as much as we can.
  return { action: "EXTRACT", amount: Math.min(EXTRACT_MAX, opp) };
}

/** The 8 strategy params fed to the vfy-policy circuit (must match decideSteal). */
export function strategyParams(): bigint[] {
  // Configurable: set STRATEGY_PARAMS="10,15,1,20,0,0,0,0" to match the
  // strategy registered on the dashboard. The params MUST be the ones whose
  // hash equals the registered strategy commitment, or the circuit's
  // commitment check (line 72) will reject the proof. See README.
  const fromEnv = process.env.STRATEGY_PARAMS;
  if (fromEnv) {
    const parts = fromEnv.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    if (parts.length === 8) return parts.map((p) => BigInt(p));
    console.warn(
      `[strategy] STRATEGY_PARAMS must have exactly 8 comma-separated numbers, got ${parts.length} - using defaults`,
    );
  }
  return [
    BigInt(EXTRACT_MAX),
    BigInt(FORTIFY_TURN),
    BigInt(FORTIFY_LEAD),
    BigInt(FORTIFY_MIN_OPP),
    0n,
    0n,
    0n,
    0n,
  ];
}

export function actionCode(action: StealActionType): 0 | 1 | 2 {
  return action === "HOLD" ? 0 : action === "FORTIFY" ? 1 : 2;
}
