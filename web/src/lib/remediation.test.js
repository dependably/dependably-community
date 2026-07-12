import { describe, it, expect } from 'vitest'
import vulnerabilitiesSource from '../pages/Vulnerabilities.svelte?raw'
import { remediationSkillIds, firstFixedVersion, skillInstallCommand, skillPrompt } from './remediation.js'

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
})

describe('Vulnerabilities.svelte install-command Copy button', () => {
  // The install-command Copy button's on:click handler isn't unit-testable directly (it reads
  // window.location inside a Svelte component), so this pins the actual call site source
  // instead: the button must invoke skillInstallCommand with the same (skillId, origin)
  // arguments as the displayed command text just above it, so the copied string always matches
  // what's shown. Fails on the pre-fix handler, which called skillInstallCommand(skillId) with
  // no origin argument — copying "undefined" into the clipboard instead of the instance origin.
  it('displays the install command with an explicit origin argument', () => {
    expect(vulnerabilitiesSource).toMatch(/copy-block-text">\{skillInstallCommand\(skillId,\s*window\.location\.origin\)\}/)
  })

  it('copies the install command with the same explicit origin argument as the displayed text', () => {
    expect(vulnerabilitiesSource).toMatch(
      /copyRemediation\(installKey,\s*skillInstallCommand\(skillId,\s*window\.location\.origin\)\)/,
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
})
