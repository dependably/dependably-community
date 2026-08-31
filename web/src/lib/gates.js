/**
 * Every block gate the gate service can record, in the order they read best as a set.
 *
 * Two surfaces need this vocabulary up front rather than inferred from data: the Quarantine
 * queue's gate filter (a value missing here is a gate the queue cannot be narrowed to), and
 * the dashboard's Prevention panel, which renders a pill per gate whether or not it fired —
 * an all-zero row is the reassuring answer, and it cannot be built from a payload that only
 * carries the gates that did.
 *
 * It is a DISPLAY baseline, not a contract. PackageAnalyticsRepository derives its gate
 * counts by matching the 'blocked%' event prefix precisely so a newly added gate reaches the
 * dashboard without a frontend change, so both callers union whatever the payload carries on
 * top of this list rather than filtering to it. The legacy bare 'blocked' event, which the
 * repository collapses to 'manual', arrives that way — it is an operator action rather than
 * a policy arm, so it is not part of the baseline.
 *
 * Each value needs a matching `dashboard.gates.<value>` string in every locale.
 */
export const BLOCK_GATES = Object.freeze([
  'deprecated', 'revoked', 'release_age', 'license', 'install_script',
  'provenance', 'malicious', 'kev', 'kev_ransomware', 'epss', 'vuln_score',
])

/**
 * The Prevention panel's pills: one per gate, whether or not it refused anything.
 *
 * `blockedByGate` carries only the gates that fired (PackageAnalyticsRepository groups the
 * activity rows it found), so a quiet window arrives as an empty list. Rendering that as an
 * absence answers the wrong question — the row of zeros is what says which gates are being
 * counted at all — so the baseline is filled in and the payload layered over it.
 *
 * Ordered by count so a gate that fired leads, ties broken by {@link BLOCK_GATES} order,
 * which is what an all-zero window renders in. Unknown gates keep their payload order behind
 * the baseline, so a new backend arm appears without a change here.
 *
 * @param {Array<{ gate: string, count: number }> | null | undefined} blockedByGate
 * @returns {Array<{ gate: string, count: number }>} never empty
 */
export function buildPreventionCells(blockedByGate) {
  const rows = Array.isArray(blockedByGate) ? blockedByGate : []
  const counts = new Map(rows.map(r => [r.gate, r.count]))
  const extra = rows.map(r => r.gate).filter(g => g && !BLOCK_GATES.includes(g))
  return [...BLOCK_GATES, ...new Set(extra)]
    .map((gate, i) => ({ gate, count: counts.get(gate) ?? 0, i }))
    .sort((a, b) => b.count - a.count || a.i - b.i)
    .map(({ gate, count }) => ({ gate, count }))
}
