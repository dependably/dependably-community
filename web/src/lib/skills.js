// Shared helpers for every surface that offers a curated skill: the Vulnerabilities detail
// panel's remediation block, the Setup wizard's configure-with-an-assistant alternative, and
// the Setup page's skills tab. Kept out of the components so the derivation logic — which
// assistant installs a skill where, and which skill covers a given Setup cell — is
// unit-testable without rendering anything.

/**
 * The AI assistants a skill can be installed into. The skill markdown itself is
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

/**
 * One developer uses one assistant, not one per advisory or per package manager, so the
 * choice is remembered per browser and shared across every surface that offers a skill.
 */
export const ASSISTANT_STORAGE_KEY = 'remediationAssistant'

/**
 * The stored assistant id, or 'claude' when nothing valid is stored.
 * @param {any} [storage] Storage backend; injectable so the behaviour is testable.
 * @returns {string}
 */
export function readStoredAssistant(storage = globalThis.localStorage) {
  let stored = ''
  try {
    stored = storage?.getItem(ASSISTANT_STORAGE_KEY) ?? ''
  } catch {
    // A browser with site data blocked throws on access; the default is a fine answer.
    stored = ''
  }
  return ASSISTANTS.some(a => a.id === stored) ? stored : 'claude'
}

/**
 * Remembers the chosen assistant, tolerating a storage backend that refuses to write.
 * @param {string} id
 * @param {any} [storage] Storage backend; injectable so the behaviour is testable.
 */
export function storeAssistant(id, storage = globalThis.localStorage) {
  try {
    storage?.setItem(ASSISTANT_STORAGE_KEY, id)
  } catch {
    // Nothing depends on persistence succeeding — the choice still applies to this view.
  }
}

/** Copyable one-liner that fetches a curated skill from this instance into the assistant's skill/prompt location. */
export function skillInstallCommand(skillId, origin, assistant = 'claude') {
  const url = `${origin}/api/v1/skills/${skillId}`
  switch (assistant) {
    case 'codex':
      return `mkdir -p ~/.codex/prompts && curl -fsSL ${url} -o ~/.codex/prompts/${skillId}.md`
    case 'copilot':
      return `mkdir -p .github/prompts && curl -fsSL ${url} -o .github/prompts/${skillId}.prompt.md`
    default:
      return `mkdir -p ~/.claude/skills/${skillId} && curl -fsSL ${url} -o ~/.claude/skills/${skillId}/SKILL.md`
  }
}

/**
 * One command that installs every skill in `skillIds` into the assistant's location — the bulk
 * form of {@link skillInstallCommand}, for a reader who does not want to run nine of them.
 * A loop over the ids rather than a bundle download, because this lands each file where the
 * assistant already looks; the zip is the answer to a different question (taking the corpus
 * somewhere else).
 * @param {string[]} skillIds
 * @param {string} origin
 * @param {string} [assistant]
 * @returns {string}
 */
export function skillInstallAllCommand(skillIds, origin, assistant = 'claude') {
  const ids = (skillIds ?? []).join(' ')
  const base = `${origin}/api/v1/skills`
  switch (assistant) {
    case 'codex':
      return `mkdir -p ~/.codex/prompts && for s in ${ids}; do curl -fsSL ${base}/$s -o ~/.codex/prompts/$s.md; done`
    case 'copilot':
      return `mkdir -p .github/prompts && for s in ${ids}; do curl -fsSL ${base}/$s -o .github/prompts/$s.prompt.md; done`
    default:
      return `for s in ${ids}; do mkdir -p ~/.claude/skills/$s && curl -fsSL ${base}/$s -o ~/.claude/skills/$s/SKILL.md; done`
  }
}

/**
 * URL of the zip bundling a whole family (or the whole corpus when `family` is omitted). Used
 * as an `<a download>` href, so the browser saves it without the page holding the bytes.
 * @param {string} [family] `config` or `remediation`.
 * @returns {string}
 */
export function skillsBundleUrl(family) {
  return family ? `/api/v1/skills/bundle?family=${encodeURIComponent(family)}` : '/api/v1/skills/bundle'
}

/** How a given assistant is asked to run a skill: Claude discovers it by name, the others invoke a prompt file. */
export function skillReference(skillId, assistant = 'claude') {
  return assistant === 'claude' ? `the ${skillId} skill` : `the /${skillId} prompt`
}

/**
 * The client-config skill covering one Setup cell, looked up in the index the instance
 * actually served rather than reconstructed from a local naming rule. A cell with no skill
 * returns null, and the caller renders nothing — the page must never advertise an install
 * command for a skill this binary cannot hand back.
 * @param {Array<object>|null|undefined} index The `/api/v1/skills` payload.
 * @param {string|null|undefined} ecosystem Ecosystem key from the `ECOSYSTEMS` vocabulary.
 * @param {string|null|undefined} scope `project` or `global`.
 * @returns {object|null} The index entry, or null.
 */
export function findConfigSkill(index, ecosystem, scope) {
  if (!index || !ecosystem || !scope) return null
  return index.find(s => s.family === 'config' && s.ecosystem === ecosystem && s.scope === scope) ?? null
}

/** The remediation family of a skills index, in served order. */
export function remediationSkills(index) {
  return (index ?? []).filter(s => s.family === 'remediation')
}

/**
 * Copyable prompt that points an assistant at a client-config skill for this instance. The
 * wording follows the skill's own scope: a project skill writes a file into the repository,
 * a global one changes the machine, and telling the assistant the wrong one invites it to
 * edit the wrong file.
 * @param {string} skillId
 * @param {string} origin This instance's base URL.
 * @param {string} [assistant]
 * @param {string} [scope] `project` or `global`.
 * @returns {string}
 */
export function configSkillPrompt(skillId, origin, assistant = 'claude', scope = 'project') {
  const target = scope === 'global'
    ? 'configure this machine to resolve packages from'
    : 'configure this project to resolve packages from'
  return `Use ${skillReference(skillId, assistant)} to ${target} ${origin}.`
}
