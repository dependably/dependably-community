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

/** Copyable one-liner that fetches a curated skill from this instance into `~/.claude/skills/`. */
export function skillInstallCommand(skillId, origin) {
  return `mkdir -p ~/.claude/skills/${skillId} && curl -fsSL ${origin}/api/v1/remediation/skills/${skillId} -o ~/.claude/skills/${skillId}/SKILL.md`
}

/** Copyable prompt pre-filled with the advisory id, purl, installed version, and fixed version. */
export function skillPrompt(skillId, osvId, purl, installedVersion, fixedVersion) {
  let prompt = `Use the ${skillId} Claude skill to remediate ${osvId ?? 'this advisory'} in ${purl ?? 'this package'} (installed version ${installedVersion ?? 'unknown'}`
  prompt += fixedVersion ? `, fixed in ${fixedVersion}).` : ').'
  return prompt
}
