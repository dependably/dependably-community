// Pure helpers for the Vulnerabilities detail panel's Remediation section — kept out of
// Vulnerabilities.svelte so the derivation logic (which skills apply, what the install
// one-liner and prompt look like) is unit-testable without rendering a component.

/**
 * Ordered, de-duplicated list of applicable skill ids: the flagship dependency-upgrade skill
 * first (only when the advisory has a fixed version), then one entry per distinct class-skill
 * id carried by the CWE entries — in the order the entries appear, duplicates dropped.
 * @param {object|null|undefined} remediation OsvDetail.remediation — `{ upgradeSkillId, entries: [{ skillId }] }`.
 * @returns {string[]}
 */
export function remediationSkillIds(remediation) {
  if (!remediation) return []
  const ids = []
  if (remediation.upgradeSkillId) ids.push(remediation.upgradeSkillId)
  for (const e of remediation.entries ?? []) {
    if (e.skillId && !ids.includes(e.skillId)) ids.push(e.skillId)
  }
  return ids
}

/**
 * First `fixed` version found anywhere in the advisory's affected ranges — best-effort,
 * informational text for the agent prompt, not a precise per-ecosystem resolution.
 * @param {Array<object>|null|undefined} affected OsvDetail.affected — `[{ ranges: [{ events: [{ fixed }] }] }]`.
 * @returns {string|null}
 */
export function firstFixedVersion(affected) {
  for (const af of affected ?? []) {
    for (const rng of af.ranges ?? []) {
      for (const ev of rng.events ?? []) {
        if (ev.fixed) return ev.fixed
      }
    }
  }
  return null
}

/**
 * The fixed version to show: the server-resolved one when present (the fix for the range
 * containing the installed version, under the ecosystem's native ordering), else the
 * best-effort first `fixed` event.
 * @param {object|null|undefined} remediation OsvDetail.remediation — `{ fixedVersion }`.
 * @param {Array<object>|null|undefined} affected OsvDetail.affected.
 * @returns {string|null}
 */
export function resolvedFixedVersion(remediation, affected) {
  return remediation?.fixedVersion ?? firstFixedVersion(affected)
}

/**
 * The AI assistants the remediation section can target. The skill markdown itself is
 * assistant-neutral; only the install location and the invocation wording differ:
 * Claude Code loads skills from `~/.claude/skills/<id>/SKILL.md`, OpenAI Codex reads custom
 * prompts from `~/.codex/prompts/<id>.md` (invoked as `/<id>`), and GitHub Copilot reads
 * repo-level prompt files from `.github/prompts/<id>.prompt.md` (also invoked as `/<id>`).
 * Labels are product names — not translated.
 */
export const ASSISTANTS = [
  { id: 'claude', label: 'Claude Code' },
  { id: 'codex', label: 'OpenAI Codex' },
  { id: 'copilot', label: 'GitHub Copilot' },
]

/** Copyable one-liner that fetches a curated skill from this instance into the assistant's skill/prompt location. */
export function skillInstallCommand(skillId, origin, assistant = 'claude') {
  const url = `${origin}/api/v1/remediation/skills/${skillId}`
  switch (assistant) {
    case 'codex':
      return `mkdir -p ~/.codex/prompts && curl -fsSL ${url} -o ~/.codex/prompts/${skillId}.md`
    case 'copilot':
      return `mkdir -p .github/prompts && curl -fsSL ${url} -o .github/prompts/${skillId}.prompt.md`
    default:
      return `mkdir -p ~/.claude/skills/${skillId} && curl -fsSL ${url} -o ~/.claude/skills/${skillId}/SKILL.md`
  }
}

/** Copyable prompt pre-filled with the advisory id, purl, installed version, and fixed version. */
export function skillPrompt(skillId, osvId, purl, installedVersion, fixedVersion, assistant = 'claude') {
  // Claude discovers installed skills by name; Codex and Copilot invoke prompt files as /<id>.
  const skillRef = assistant === 'claude' ? `the ${skillId} skill` : `the /${skillId} prompt`
  let prompt = `Use ${skillRef} to remediate ${osvId ?? 'this advisory'} in ${purl ?? 'this package'} (installed version ${installedVersion ?? 'unknown'}`
  prompt += fixedVersion ? `, fixed in ${fixedVersion}).` : ').'
  return prompt
}
