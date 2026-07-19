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

/**
 * The pre-filled task statement that closes a remediation brief — a standalone sentence usable
 * on its own (e.g. as a prompt) that names the curated skill only when one is mapped, and states
 * an unresolved fixed version explicitly rather than dropping it.
 * @param {string|null|undefined} osvId
 * @param {string|null|undefined} purl
 * @param {string|null|undefined} installedVersion
 * @param {string|null|undefined} fixedVersion
 * @param {string[]} skillIds Ordered list from {@link remediationSkillIds}; may be empty.
 * @returns {string}
 */
export function remediationTaskStatement(osvId, purl, installedVersion, fixedVersion, skillIds) {
  let statement = `Remediate ${osvId ?? 'this advisory'} in ${purl ?? 'this package'} (installed version ${installedVersion ?? 'unknown'}`
  statement += fixedVersion
    ? `, fixed in ${fixedVersion}).`
    : ', fixed version unknown — check the advisory\'s affected/fixed ranges before upgrading).'
  if (skillIds?.length) {
    statement += ` Use the ${skillIds[0]} skill if it is available.`
  }
  return statement
}

/**
 * Self-contained markdown remediation brief for the Vulnerabilities detail panel's "Copy
 * remediation brief" action — pasteable into any AI assistant or a ticket. Works even when the
 * advisory carries no CWE data and no mapped curated skill: every section either renders what it
 * has or states explicitly that the value is unknown, never silently dropping it (this project's
 * hard rule that security UI surfaces uncertainty rather than fabricating or omitting it).
 * @param {object} params
 * @param {string|null|undefined} params.osvId
 * @param {string|null|undefined} params.summary
 * @param {string|null|undefined} params.purl
 * @param {string|null|undefined} params.installedVersion
 * @param {string|null|undefined} params.fixedVersion Pre-resolved via {@link resolvedFixedVersion}.
 * @param {object|null|undefined} params.remediation OsvDetail.remediation — `{ entries: [{ cweId, cweUrl, owaspId, owaspTitle, owaspUrl }] }`.
 * @returns {string} Markdown.
 */
/** The `- [CWE](url) — [OWASP title](url)` line for one weakness-classification entry. */
function formatCweEntryLine(e) {
  const cwePart = e.cweUrl ? `[${e.cweId}](${e.cweUrl})` : e.cweId
  return `- ${cwePart}${formatOwaspPart(e)}`
}

/** The ` — [OWASP-id Title](url)` suffix for one entry, or '' when the entry carries no OWASP id. */
function formatOwaspPart(e) {
  if (!e.owaspId) return ''
  const titleSuffix = e.owaspTitle ? ` ${e.owaspTitle}` : ''
  return ` — [${e.owaspId}${titleSuffix}](${e.owaspUrl})`
}

/** Weakness-classification section body lines: one per CWE entry, or an explicit "none" line. */
function buildWeaknessLines(entries) {
  return entries.length
    ? entries.map(formatCweEntryLine)
    : ['_No CWE/OWASP classification available for this advisory._']
}

/** Curated-skill section (heading + summary line), or [] when no skill is mapped. */
function buildSkillLines(skillIds) {
  if (!skillIds.length) return []
  const skillList = skillIds.map(id => `\`${id}\``).join(', ')
  const summary = skillIds.length === 1
    ? `A curated remediation skill is available for this advisory class: \`${skillIds[0]}\`.`
    : `Curated remediation skills are available for this advisory: ${skillList}.`
  return ['', '## Curated skill', summary]
}

export function remediationBrief({ osvId, summary, purl, installedVersion, fixedVersion, remediation }) {
  const skillIds = remediationSkillIds(remediation)
  const entries = (remediation?.entries ?? []).filter(e => e.cweId)

  const lines = [
    `# Remediation brief: ${osvId ?? 'Unknown advisory'}`,
    '',
    summary || '_No summary available for this advisory._',
    '',
    '## Affected',
    `- Package: \`${purl ?? 'unknown package'}\``,
    `- Installed version: \`${installedVersion ?? 'unknown'}\``,
    fixedVersion
      ? `- Fixed version: \`${fixedVersion}\``
      : '- Fixed version: **unknown** — no fixed version could be resolved from the advisory.',
    '',
    '## Weakness classification',
    ...buildWeaknessLines(entries),
    ...buildSkillLines(skillIds),
    '',
    '## Task',
    remediationTaskStatement(osvId, purl, installedVersion, fixedVersion, skillIds),
  ]

  return lines.join('\n')
}
