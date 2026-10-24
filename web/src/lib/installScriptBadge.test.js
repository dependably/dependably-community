import { describe, it, expect } from 'vitest'
import { installScriptBadge } from './installScriptBadge.js'

describe('installScriptBadge', () => {
  it('keeps the generic install-script badge for a real lifecycle script', () => {
    expect(installScriptBadge('postinstall')).toEqual({
      labelKey: 'versionDetail.badges.installScript',
      helpKey: 'versionDetail.badges.installScriptHelp',
    })
    expect(installScriptBadge(null).labelKey).toBe('versionDetail.badges.installScript')
    expect(installScriptBadge(undefined).labelKey).toBe('versionDetail.badges.installScript')
  })

  it('gives an ambiguous manifest its own label and help', () => {
    expect(installScriptBadge('npm:ambiguous-manifest')).toEqual({
      labelKey: 'versionDetail.badges.manifestIssue',
      helpKey: 'versionDetail.badges.manifestAmbiguousHelp',
    })
  })

  it('gives an unscannable manifest its own label and help', () => {
    expect(installScriptBadge('npm:unscannable-manifest')).toEqual({
      labelKey: 'versionDetail.badges.manifestIssue',
      helpKey: 'versionDetail.badges.manifestUnscannableHelp',
    })
  })
})
