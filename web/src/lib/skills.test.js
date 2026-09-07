import { describe, it, expect, beforeEach } from 'vitest'
import {
  ASSISTANTS,
  ASSISTANT_STORAGE_KEY,
  configSkillPrompt,
  findConfigSkill,
  readStoredAssistant,
  remediationSkills,
  skillInstallAllCommand,
  skillInstallCommand,
  skillReference,
  skillsBundleUrl,
  storeAssistant,
} from './skills.js'

/** A stand-in for the `/api/v1/skills` payload, shaped exactly as the controller serves it. */
const INDEX = [
  { id: 'npm-configure-project', name: 'npm-configure-project', description: 'npm, one repo', family: 'config', ecosystem: 'npm', scope: 'project' },
  { id: 'npm-configure-global', name: 'npm-configure-global', description: 'npm, machine', family: 'config', ecosystem: 'npm', scope: 'global' },
  { id: 'docker-configure-global', name: 'docker-configure-global', description: 'OCI login', family: 'config', ecosystem: 'oci', scope: 'global' },
  { id: 'go-configure-project', name: 'go-configure-project', description: 'Go, one repo', family: 'config', ecosystem: 'golang', scope: 'project' },
  { id: 'fix-xss', name: 'fix-xss', description: 'Remediate XSS', family: 'remediation', ecosystem: null, scope: null },
]

describe('findConfigSkill', () => {
  it('finds the skill covering a cell', () => {
    expect(findConfigSkill(INDEX, 'npm', 'project').id).toBe('npm-configure-project')
    expect(findConfigSkill(INDEX, 'npm', 'global').id).toBe('npm-configure-global')
  })

  // The ids do not follow the ecosystem key: oci is served by docker-*, golang by go-*.
  // Looking the cell up in the served index is what keeps that from being a naming rule the
  // frontend has to know — and get wrong.
  it('resolves cells whose skill id does not match the ecosystem key', () => {
    expect(findConfigSkill(INDEX, 'oci', 'global').id).toBe('docker-configure-global')
    expect(findConfigSkill(INDEX, 'golang', 'project').id).toBe('go-configure-project')
  })

  it('returns null for a cell no skill covers', () => {
    expect(findConfigSkill(INDEX, 'oci', 'project')).toBeNull()
    expect(findConfigSkill(INDEX, 'terraform', 'project')).toBeNull()
    expect(findConfigSkill(INDEX, 'not-an-ecosystem', 'global')).toBeNull()
  })

  // The whole point of looking the skill up rather than deriving it: an index that never
  // arrived must advertise nothing, not a command that would 404.
  it('returns null when the index is absent or the coordinates are incomplete', () => {
    expect(findConfigSkill(null, 'npm', 'project')).toBeNull()
    expect(findConfigSkill(undefined, 'npm', 'project')).toBeNull()
    expect(findConfigSkill(INDEX, '', 'project')).toBeNull()
    expect(findConfigSkill(INDEX, 'npm', '')).toBeNull()
  })

  // A remediation entry carries null coordinates, so a lookup must never fall through to one
  // — the Setup shortcut would then offer a vulnerability-fix skill as a client config.
  it('never returns a remediation skill', () => {
    expect(findConfigSkill(INDEX, null, null)).toBeNull()
    const everyPair = INDEX.map(s => [s.ecosystem, s.scope])
    for (const [eco, sc] of everyPair) {
      const hit = findConfigSkill(INDEX, eco, sc)
      expect(hit === null || hit.family === 'config').toBe(true)
    }
  })
})

describe('remediationSkills', () => {
  it('keeps only the remediation family, in served order', () => {
    expect(remediationSkills(INDEX).map(s => s.id)).toEqual(['fix-xss'])
  })

  it('tolerates an absent index', () => {
    expect(remediationSkills(null)).toEqual([])
    expect(remediationSkills(undefined)).toEqual([])
  })
})

describe('skillInstallCommand', () => {
  it('targets the unified skills route, so one command shape serves both families', () => {
    expect(skillInstallCommand('npm-configure-project', 'https://repo.example.com')).toBe(
      'mkdir -p ~/.claude/skills/npm-configure-project && curl -fsSL https://repo.example.com/api/v1/skills/npm-configure-project -o ~/.claude/skills/npm-configure-project/SKILL.md',
    )
    expect(skillInstallCommand('fix-xss', 'https://repo.example.com')).toContain(
      '/api/v1/skills/fix-xss',
    )
  })

  it('writes to each assistant own location', () => {
    expect(skillInstallCommand('fix-xss', 'https://r.example', 'codex')).toBe(
      'mkdir -p ~/.codex/prompts && curl -fsSL https://r.example/api/v1/skills/fix-xss -o ~/.codex/prompts/fix-xss.md',
    )
    expect(skillInstallCommand('fix-xss', 'https://r.example', 'copilot')).toBe(
      'mkdir -p .github/prompts && curl -fsSL https://r.example/api/v1/skills/fix-xss -o .github/prompts/fix-xss.prompt.md',
    )
  })

  it('falls back to the Claude layout for an unknown assistant', () => {
    expect(skillInstallCommand('fix-xss', 'https://r.example', 'nope')).toContain('~/.claude/skills/')
  })
})

describe('skillInstallAllCommand', () => {
  const IDS = ['fix-xss', 'fix-ssrf']

  it('installs every id into the assistant location, in one command', () => {
    expect(skillInstallAllCommand(IDS, 'https://r.example', 'claude')).toBe(
      'for s in fix-xss fix-ssrf; do mkdir -p ~/.claude/skills/$s && curl -fsSL https://r.example/api/v1/skills/$s -o ~/.claude/skills/$s/SKILL.md; done',
    )
  })

  // The per-skill and install-all commands must write to the same place for the same
  // assistant, or a reader who used one and then the other ends up with two half-populated
  // locations and an assistant that finds neither reliably.
  it.each(['claude', 'codex', 'copilot'])('agrees with the single-skill command for %s', (assistant) => {
    const all = skillInstallAllCommand(['fix-xss'], 'https://r.example', assistant)
    const one = skillInstallCommand('fix-xss', 'https://r.example', assistant)
    const dir = one.match(/-o (\S+)\/[^/]+$/)?.[1].replace('fix-xss', '$s')
    expect(dir).toBeTruthy()
    expect(all).toContain(dir)
  })

  it('tolerates an empty or absent id list', () => {
    expect(skillInstallAllCommand([], 'https://r.example')).toContain('for s in ;')
    expect(() => skillInstallAllCommand(/** @type {any} */ (null), 'https://r.example')).not.toThrow()
  })
})

describe('skillsBundleUrl', () => {
  it('narrows to a family when asked, and to the whole corpus when not', () => {
    expect(skillsBundleUrl('remediation')).toBe('/api/v1/skills/bundle?family=remediation')
    expect(skillsBundleUrl()).toBe('/api/v1/skills/bundle')
  })
})

describe('skillReference', () => {
  it('names a skill for Claude and a prompt file for the others', () => {
    expect(skillReference('fix-xss', 'claude')).toBe('the fix-xss skill')
    expect(skillReference('fix-xss', 'codex')).toBe('the /fix-xss prompt')
    expect(skillReference('fix-xss', 'copilot')).toBe('the /fix-xss prompt')
  })
})

describe('configSkillPrompt', () => {
  it('names the skill and this instance', () => {
    expect(configSkillPrompt('npm-configure-project', 'https://repo.example.com', 'claude', 'project')).toBe(
      'Use the npm-configure-project skill to configure this project to resolve packages from https://repo.example.com.',
    )
    expect(configSkillPrompt('npm-configure-project', 'https://repo.example.com', 'codex', 'project')).toContain(
      'the /npm-configure-project prompt',
    )
  })

  // A project skill writes a file into the repository and a global one changes the machine.
  // Naming the wrong target invites the assistant to edit the wrong file.
  it('follows the skill scope', () => {
    expect(configSkillPrompt('npm-configure-global', 'https://r.example', 'claude', 'global')).toContain(
      'configure this machine',
    )
    expect(configSkillPrompt('npm-configure-project', 'https://r.example', 'claude', 'project')).toContain(
      'configure this project',
    )
  })
})

describe('assistant persistence', () => {
  /**
   * A minimal Storage stand-in; `throws` models a browser with site data blocked.
   * @param {{initial?: string|null, throws?: boolean}} [opts]
   * @returns {any}
   */
  function fakeStorage({ initial = null, throws = false } = {}) {
    /** @type {string|null} */
    let value = initial
    return {
      getItem: () => { if (throws) throw new Error('blocked'); return value },
      setItem: (_k, v) => { if (throws) throw new Error('blocked'); value = v },
      read: () => value,
    }
  }

  let storage
  beforeEach(() => { storage = fakeStorage() })

  it('round-trips a valid assistant id', () => {
    storeAssistant('codex', storage)
    expect(storage.read()).toBe('codex')
    expect(readStoredAssistant(storage)).toBe('codex')
  })

  it('defaults to claude when nothing is stored', () => {
    expect(readStoredAssistant(storage)).toBe('claude')
  })

  // A value left by an older build, or edited by hand, must not select a nonexistent
  // assistant and render an install command for a location that does not exist.
  it('defaults to claude when the stored value is not a known assistant', () => {
    expect(readStoredAssistant(fakeStorage({ initial: 'gemini' }))).toBe('claude')
    expect(readStoredAssistant(fakeStorage({ initial: '' }))).toBe('claude')
  })

  it('survives a storage backend that throws on read and on write', () => {
    const blocked = fakeStorage({ throws: true })
    expect(readStoredAssistant(blocked)).toBe('claude')
    expect(() => storeAssistant('codex', blocked)).not.toThrow()
  })

  it('shares one key with the Vulnerabilities panel', () => {
    expect(ASSISTANT_STORAGE_KEY).toBe('remediationAssistant')
    expect(ASSISTANTS.map(a => a.id)).toEqual(['claude', 'codex', 'copilot'])
  })
})
