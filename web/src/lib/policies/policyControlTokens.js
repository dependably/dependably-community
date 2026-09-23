// Canonical list of BlockGateService reason tokens PolicyControls.svelte renders a row for,
// grouped in render order. Exported as plain data — rather than left inline in
// PolicyControls.svelte's script — so the component and policyControls.parity.test.js share one
// source of truth: the parity test asserts every token here has
// policies.controls.<token>.{name,what} in every locale, and a token added to (or
// renamed in) the component's own row list is a token added to (or renamed in) this export too,
// so the parity check can never silently drift from what actually renders.
//
// 'provenance' itself is deliberately not in any group's `tokens` list: its rows come from
// policy.controls.provenance's own per-ecosystem keys at render time (one BlockGateService
// reason token backs six rows), not from a fixed token array — but the token still needs its own
// locale entry, so it is listed separately in POLICY_CONTROL_TOKENS below.
export const POLICY_CONTROL_GROUPS = [
  {
    key: 'vulnerability',
    tokens: [
      'malicious', 'malicious_live', 'kev', 'kev_ransomware', 'ssvc_exploitation',
      'vuln_score', 'epss', 'epss_percentile',
    ],
  },
  {
    key: 'lifecycle',
    tokens: ['deprecated', 'revoked', 'release_age', 'install_script'],
  },
  {
    key: 'access',
    tokens: ['license'],
  },
]

export const POLICY_CONTROL_TOKENS = [
  ...POLICY_CONTROL_GROUPS.flatMap(g => g.tokens),
  'provenance',
]
