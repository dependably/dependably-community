// Install-script kinds the npm manifest checks record when a stored or uploaded tarball cannot be
// read as a single package. They share the install-script flag with a real lifecycle script, so the
// badge tells them apart: a malformed archive is not a `postinstall`.
const MANIFEST_KINDS = new Set(['npm:ambiguous-manifest', 'npm:unscannable-manifest'])

export function installScriptBadge(kind) {
  if (MANIFEST_KINDS.has(kind)) {
    return {
      labelKey: 'versionDetail.badges.manifestIssue',
      helpKey: kind === 'npm:ambiguous-manifest'
        ? 'versionDetail.badges.manifestAmbiguousHelp'
        : 'versionDetail.badges.manifestUnscannableHelp',
    }
  }
  return {
    labelKey: 'versionDetail.badges.installScript',
    helpKey: 'versionDetail.badges.installScriptHelp',
  }
}
