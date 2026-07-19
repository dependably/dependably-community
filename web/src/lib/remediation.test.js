import { describe, it, expect } from 'vitest'
import vulnerabilitiesSource from '../pages/Vulnerabilities.svelte?raw'
import {
  remediationSkillIds,
  firstFixedVersion,
  resolvedFixedVersion,
  skillInstallCommand,
  skillPrompt,
  remediationBrief,
  remediationTaskStatement,
} from './remediation.js'

describe('remediationSkillIds', () => {
  it('returns an empty array for null/undefined remediation', () => {
    expect(remediationSkillIds(null)).toEqual([])
    expect(remediationSkillIds(undefined)).toEqual([])
  })

  it('returns an empty array when there is no upgrade skill and no entry skills', () => {
    expect(remediationSkillIds({ cweIds: [], entries: [], upgradeSkillId: null })).toEqual([])
  })

  it('puts the upgrade skill first when set', () => {
    const remediation = {
      cweIds: ['CWE-79'],
      entries: [{ cweId: 'CWE-79', skillId: 'fix-xss' }],
      upgradeSkillId: 'fix-vulnerable-dependency',
    }
    expect(remediationSkillIds(remediation)).toEqual(['fix-vulnerable-dependency', 'fix-xss'])
  })

  it('returns only entry skill ids when there is no upgrade skill (no fixed version)', () => {
    const remediation = {
      cweIds: ['CWE-79'],
      entries: [{ cweId: 'CWE-79', skillId: 'fix-xss' }],
      upgradeSkillId: null,
    }
    expect(remediationSkillIds(remediation)).toEqual(['fix-xss'])
  })

  it('de-duplicates repeated entry skill ids, preserving first-seen order', () => {
    const remediation = {
      cweIds: ['CWE-79', 'CWE-80'],
      entries: [
        { cweId: 'CWE-79', skillId: 'fix-xss' },
        { cweId: 'CWE-80', skillId: 'fix-xss' },
        { cweId: 'CWE-89', skillId: 'fix-injection' },
      ],
      upgradeSkillId: null,
    }
    expect(remediationSkillIds(remediation)).toEqual(['fix-xss', 'fix-injection'])
  })

  it('skips entries with a null skillId (unmapped CWE)', () => {
    const remediation = {
      cweIds: ['CWE-1'],
      entries: [{ cweId: 'CWE-1', skillId: null }],
      upgradeSkillId: null,
    }
    expect(remediationSkillIds(remediation)).toEqual([])
  })
})

describe('firstFixedVersion', () => {
  it('returns null for null/undefined/empty affected', () => {
    expect(firstFixedVersion(null)).toBeNull()
    expect(firstFixedVersion(undefined)).toBeNull()
    expect(firstFixedVersion([])).toBeNull()
  })

  it('finds the fixed version nested in ranges/events', () => {
    const affected = [
      { ranges: [{ events: [{ introduced: '0' }, { fixed: '1.2.4' }] }] },
    ]
    expect(firstFixedVersion(affected)).toBe('1.2.4')
  })

  it('returns null when no event carries a fixed version', () => {
    const affected = [
      { ranges: [{ events: [{ introduced: '0' }, { lastAffected: '1.0.0' }] }] },
    ]
    expect(firstFixedVersion(affected)).toBeNull()
  })

  it('returns the first fixed version across multiple affected entries', () => {
    const affected = [
      { ranges: [{ events: [{ introduced: '0' }] }] },
      { ranges: [{ events: [{ fixed: '2.0.0' }] }] },
      { ranges: [{ events: [{ fixed: '3.0.0' }] }] },
    ]
    expect(firstFixedVersion(affected)).toBe('2.0.0')
  })

  it('tolerates missing ranges/events at any level', () => {
    expect(firstFixedVersion([{}])).toBeNull()
    expect(firstFixedVersion([{ ranges: [{}] }])).toBeNull()
  })
})

describe('resolvedFixedVersion', () => {
  const affected = [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '1.8.1' }] }] }]

  it('prefers the server-resolved fixedVersion over the first fixed event', () => {
    expect(resolvedFixedVersion({ fixedVersion: '2.3.4' }, affected)).toBe('2.3.4')
  })

  it('falls back to the first fixed event when the server resolved nothing', () => {
    expect(resolvedFixedVersion({ fixedVersion: null }, affected)).toBe('1.8.1')
    expect(resolvedFixedVersion(null, affected)).toBe('1.8.1')
  })

  it('returns null when neither source has a fix', () => {
    expect(resolvedFixedVersion(null, null)).toBeNull()
  })
})

describe('skillInstallCommand', () => {
  it('builds a mkdir + curl one-liner scoped to the skill id and instance origin', () => {
    const cmd = skillInstallCommand('fix-xss', 'https://repo.example.com')
    expect(cmd).toBe(
      'mkdir -p ~/.claude/skills/fix-xss && curl -fsSL https://repo.example.com/api/v1/remediation/skills/fix-xss -o ~/.claude/skills/fix-xss/SKILL.md',
    )
  })

  // Pins the value the Copy button actually places on the clipboard. The Vulnerabilities.svelte
  // Copy button and the displayed command text must call skillInstallCommand with the same
  // arguments (skillId, window.location.origin) so the copied string matches what's shown —
  // this test invokes it exactly the way that call site does. Regression coverage for a bug
  // where the Copy button omitted the origin argument, silently copying a command with the
  // literal string "undefined" in place of the instance origin.
  it('matches the origin-carrying call the Copy button makes, with no "undefined" origin', () => {
    const cmd = skillInstallCommand('fix-xss', window.location.origin)
    expect(cmd).toContain(window.location.origin)
    expect(cmd).not.toContain('undefined')
    expect(cmd).toBe(
      `mkdir -p ~/.claude/skills/fix-xss && curl -fsSL ${window.location.origin}/api/v1/remediation/skills/fix-xss -o ~/.claude/skills/fix-xss/SKILL.md`,
    )
  })

  it('produces a command containing the literal "undefined" when the origin argument is omitted', () => {
    // Documents why the Copy button call site must always pass an explicit origin: omitting the
    // second argument (as the pre-fix Copy button handler did) silently copies a broken command
    // rather than throwing.
    const cmd = skillInstallCommand('fix-xss')
    expect(cmd).toContain('undefined')
  })

  it('targets ~/.codex/prompts/<id>.md for Codex', () => {
    expect(skillInstallCommand('fix-xss', 'https://repo.example.com', 'codex')).toBe(
      'mkdir -p ~/.codex/prompts && curl -fsSL https://repo.example.com/api/v1/remediation/skills/fix-xss -o ~/.codex/prompts/fix-xss.md',
    )
  })

  it('targets the repo-level .github/prompts/<id>.prompt.md for Copilot', () => {
    expect(skillInstallCommand('fix-xss', 'https://repo.example.com', 'copilot')).toBe(
      'mkdir -p .github/prompts && curl -fsSL https://repo.example.com/api/v1/remediation/skills/fix-xss -o .github/prompts/fix-xss.prompt.md',
    )
  })

  it('defaults to the Claude skill location for an unknown or omitted assistant', () => {
    expect(skillInstallCommand('fix-xss', 'https://repo.example.com', 'claude'))
      .toBe(skillInstallCommand('fix-xss', 'https://repo.example.com'))
  })
})

describe('Vulnerabilities.svelte install-command Copy button', () => {
  // The install-command Copy button's on:click handler isn't unit-testable directly (it reads
  // window.location inside a Svelte component), so this pins the actual call site source
  // instead: the button must invoke skillInstallCommand with the same (skillId, origin)
  // arguments as the displayed command text just above it, so the copied string always matches
  // what's shown. Fails on the pre-fix handler, which called skillInstallCommand(skillId) with
  // no origin argument — copying "undefined" into the clipboard instead of the instance origin.
  it('displays the install command with an explicit origin argument', () => {
    expect(vulnerabilitiesSource).toMatch(
      /copy-block-text">\{skillInstallCommand\(skillId,\s*window\.location\.origin,\s*assistant\)\}/,
    )
  })

  it('copies the install command with the same explicit origin argument as the displayed text', () => {
    expect(vulnerabilitiesSource).toMatch(
      /copyRemediation\(installKey,\s*skillInstallCommand\(skillId,\s*window\.location\.origin,\s*assistant\)\)/,
    )
  })
})

describe('skillPrompt', () => {
  it('includes the osvId, purl, installed version, and fixed version when all are known', () => {
    const prompt = skillPrompt('fix-xss', 'GHSA-xxxx', 'pkg:npm/vuln-pkg@1.0.0', '1.0.0', '1.2.4')
    expect(prompt).toContain('fix-xss')
    expect(prompt).toContain('GHSA-xxxx')
    expect(prompt).toContain('pkg:npm/vuln-pkg@1.0.0')
    expect(prompt).toContain('installed version 1.0.0')
    expect(prompt).toContain('fixed in 1.2.4')
  })

  it('degrades gracefully when the fixed version is unknown', () => {
    const prompt = skillPrompt('fix-injection', 'GHSA-yyyy', 'pkg:pypi/vuln-pkg@2.0.0', '2.0.0', null)
    expect(prompt).not.toContain('fixed in')
    expect(prompt).toContain('installed version 2.0.0')
  })

  it('falls back to generic phrasing when osvId/purl/version are missing', () => {
    const prompt = skillPrompt('fix-ssrf', undefined, undefined, undefined, undefined)
    expect(prompt).toContain('this advisory')
    expect(prompt).toContain('this package')
    expect(prompt).toContain('installed version unknown')
  })

  it('references the skill by name for Claude and as a /<id> prompt for Codex and Copilot', () => {
    expect(skillPrompt('fix-xss', 'GHSA-x', 'pkg:npm/p@1', '1', '2')).toContain('the fix-xss skill')
    expect(skillPrompt('fix-xss', 'GHSA-x', 'pkg:npm/p@1', '1', '2', 'codex')).toContain('the /fix-xss prompt')
    expect(skillPrompt('fix-xss', 'GHSA-x', 'pkg:npm/p@1', '1', '2', 'copilot')).toContain('the /fix-xss prompt')
  })
})

describe('remediationTaskStatement', () => {
  it('names the highest-priority skill when one is mapped', () => {
    const s = remediationTaskStatement('GHSA-x', 'pkg:npm/p@1', '1.0.0', '1.2.4', ['fix-vulnerable-dependency', 'fix-xss'])
    expect(s).toContain('fixed in 1.2.4')
    expect(s).toContain('Use the fix-vulnerable-dependency skill if it is available.')
  })

  it('omits the skill sentence entirely when no skill is mapped', () => {
    const s = remediationTaskStatement('GHSA-x', 'pkg:npm/p@1', '1.0.0', '1.2.4', [])
    expect(s).not.toContain('skill')
  })

  it('states the fixed version is unknown rather than omitting it', () => {
    const s = remediationTaskStatement('GHSA-x', 'pkg:npm/p@1', '1.0.0', null, [])
    expect(s).toContain('fixed version unknown')
    expect(s).not.toContain('fixed in')
  })
})

describe('remediationBrief', () => {
  const baseRemediation = {
    cweIds: ['CWE-79'],
    entries: [{
      cweId: 'CWE-79',
      cweUrl: 'https://cwe.mitre.org/data/definitions/79.html',
      owaspId: 'A05:2025',
      owaspTitle: 'Injection',
      owaspUrl: 'https://owasp.org/Top10/2025/A05_2025-Injection/',
      skillId: 'fix-xss',
    }],
    upgradeSkillId: 'fix-vulnerable-dependency',
    fixedVersion: '1.2.4',
  }

  it('renders the advisory id, summary, affected purl/versions, CWE+OWASP links, skill reference, and a task statement when a skill is mapped', () => {
    const brief = remediationBrief({
      osvId: 'GHSA-xxxx',
      summary: 'Reflected XSS in the template renderer.',
      purl: 'pkg:npm/vuln-pkg@1.0.0',
      installedVersion: '1.0.0',
      fixedVersion: '1.2.4',
      remediation: baseRemediation,
    })

    expect(brief).toContain('# Remediation brief: GHSA-xxxx')
    expect(brief).toContain('Reflected XSS in the template renderer.')
    expect(brief).toContain('pkg:npm/vuln-pkg@1.0.0')
    expect(brief).toContain('Installed version: `1.0.0`')
    expect(brief).toContain('Fixed version: `1.2.4`')
    expect(brief).toContain('[CWE-79](https://cwe.mitre.org/data/definitions/79.html)')
    expect(brief).toContain('[A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)')
    expect(brief).toContain('## Curated skill')
    expect(brief).toContain('fix-vulnerable-dependency')
    expect(brief).toContain('## Task')
    expect(brief).toContain('Use the fix-vulnerable-dependency skill if it is available.')
  })

  it('omits the Curated skill section gracefully when no skill is mapped', () => {
    const remediation = {
      cweIds: ['CWE-1'],
      entries: [{ cweId: 'CWE-1', cweUrl: 'https://cwe.mitre.org/data/definitions/1.html', owaspId: null, owaspTitle: null, owaspUrl: null, skillId: null }],
      upgradeSkillId: null, // no fixed version, so the flagship upgrade skill does not apply either
      fixedVersion: null,
    }
    const brief = remediationBrief({
      osvId: 'GHSA-yyyy',
      summary: 'Some advisory with an unmapped CWE.',
      purl: 'pkg:pypi/vuln-pkg@2.0.0',
      installedVersion: '2.0.0',
      fixedVersion: null,
      remediation,
    })

    expect(brief).not.toContain('## Curated skill')
    expect(brief).not.toContain('skill if it is available')
    // The unmapped CWE itself still renders — only the skill/OWASP mapping is missing.
    expect(brief).toContain('CWE-1')
  })

  it('states the fixed version is unknown explicitly rather than omitting the line', () => {
    const brief = remediationBrief({
      osvId: 'GHSA-zzzz',
      summary: 'An advisory with no resolvable fix.',
      purl: 'pkg:maven/org.example/vuln-lib@3.0.0',
      installedVersion: '3.0.0',
      fixedVersion: null,
      remediation: { cweIds: [], entries: [], upgradeSkillId: null, fixedVersion: null },
    })

    expect(brief).toContain('Fixed version: **unknown**')
    expect(brief).not.toContain('Fixed version: `')
  })

  it('states no CWE/OWASP classification is available rather than rendering an empty section', () => {
    const brief = remediationBrief({
      osvId: 'GHSA-wwww',
      summary: 'An advisory whose OSV entry carries no cwe_ids.',
      purl: 'pkg:npm/vuln-pkg@4.0.0',
      installedVersion: '4.0.0',
      fixedVersion: '4.0.1',
      remediation: { cweIds: [], entries: [], upgradeSkillId: 'fix-vulnerable-dependency', fixedVersion: '4.0.1' },
    })

    expect(brief).toContain('## Weakness classification')
    expect(brief).toContain('_No CWE/OWASP classification available for this advisory._')
    // The flagship upgrade skill still applies (a fixed version exists) even with zero CWEs.
    expect(brief).toContain('## Curated skill')
    expect(brief).toContain('fix-vulnerable-dependency')
  })

  it('degrades gracefully when remediation, summary, purl, and versions are all missing', () => {
    const brief = remediationBrief({ osvId: null, summary: null, purl: null, installedVersion: null, fixedVersion: null, remediation: null })

    expect(brief).toContain('# Remediation brief: Unknown advisory')
    expect(brief).toContain('_No summary available for this advisory._')
    expect(brief).toContain('unknown package')
    expect(brief).toContain('Fixed version: **unknown**')
    expect(brief).toContain('_No CWE/OWASP classification available for this advisory._')
    expect(brief).not.toContain('## Curated skill')
  })
})

describe('Vulnerabilities.svelte "Copy remediation brief" action', () => {
  // Pins the call site so the button always builds the brief from the resolved fixedVersion
  // (shared with the per-skill prompt above it) rather than recomputing or dropping it, and
  // copies under a distinct per-row/per-advisory state key so its "Copied!" flash never lands on
  // the wrong button.
  it('renders a copy-brief button wired to remediationBrief and a distinct copy-state key', () => {
    expect(vulnerabilitiesSource).toMatch(/briefKey\s*=\s*`\$\{r\.purl\}::\$\{r\.osvId\}::brief`/)
    expect(vulnerabilitiesSource).toMatch(/copyRemediation\(briefKey,\s*remediationBrief\(\{/)
    expect(vulnerabilitiesSource).toContain("vulnerabilities.detail.remediation.copyBrief")
  })
})
