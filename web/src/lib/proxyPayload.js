/**
 * Builds the PUT /api/v1/proxy-settings body from the editable proxy-settings state.
 *
 * Converts the value+unit age pair back to canonical hours (empty or non-positive = null, policy
 * off) and normalises the EPSS fields (empty = null). `oci_scan_enforcement` is owned by the
 * Gates tab: it is sent only when `includeOciScan` is set and the value differs from
 * `storedOciScan`, so a save from another tab never re-submits a posture the server may refuse
 * (a stored warn/block while image scanning is off) and never touches a field it does not edit.
 *
 * @param {object} ps  proxy-settings state (snake_case, as loaded plus the age value/unit pair)
 * @param {{ includeOciScan?: boolean, storedOciScan?: string }} [opts]
 */
export function buildProxyPayload(ps, { includeOciScan = false, storedOciScan } = {}) {
  const raw = String(ps.min_release_age_value ?? '').trim()
  const num = raw === '' ? null : Math.floor(Number(raw))
  let minReleaseAgeHours = null
  if (num !== null && !isNaN(num) && num > 0) {
    minReleaseAgeHours = ps.min_release_age_unit === 'days' ? num * 24 : num
  }
  const epssRaw = String(ps.max_epss_tolerance ?? '').trim()
  const maxEpssTolerance = epssRaw === '' || isNaN(Number(epssRaw)) ? null : Number(epssRaw)
  // The percentile ceiling normalises the same way and for the same reason: an empty field is
  // an explicit "policy off", which the API carries as a present-and-null value rather than an
  // omitted one, so clearing it is distinguishable from not touching it.
  const pctRaw = String(ps.max_epss_percentile_tolerance ?? '').trim()
  const maxEpssPercentileTolerance = pctRaw === '' || isNaN(Number(pctRaw)) ? null : Number(pctRaw)
  const payload = {
    proxyPassthroughEnabled: ps.proxy_passthrough_enabled,
    maxOsvScoreTolerance:    Number(ps.max_osv_score_tolerance),
    minReleaseAgeHours,
    blockDeprecated:         ps.block_deprecated,
    blockRevoked:            ps.block_revoked,
    blockMalicious:          ps.block_malicious,
    blockMaliciousLive:      ps.block_malicious_live,
    blockKev:                ps.block_kev,
    maxEpssTolerance,
    blockKevRansomware:      ps.block_kev_ransomware,
    blockSsvcExploitation:   ps.block_ssvc_exploitation,
    maxEpssPercentileTolerance,
    blockInstallScripts:     ps.block_install_scripts,
    verifyNpmSignatures:     ps.verify_npm_signatures,
    verifyNuGetSignatures:   ps.verify_nuget_signatures,
    verifyPyPiAttestations:  ps.verify_pypi_attestations,
    verifyRpmSignatures:     ps.verify_rpm_signatures,
    verifyMavenSignatures:   ps.verify_maven_signatures,
  }
  if (includeOciScan && ps.oci_scan_enforcement !== storedOciScan) {
    payload.ociScanEnforcement = ps.oci_scan_enforcement
  }
  return payload
}
