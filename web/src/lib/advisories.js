// Pure helpers for advisory identifiers shown in the Vulnerabilities detail panel.

// Canonical reference pages per advisory-id prefix. CVE ids link to NVD; the rest are
// OSV-namespace ids whose home databases publish stable per-id pages.
const ALIAS_URL_BY_PREFIX = [
  { prefix: 'GHSA-', url: id => `https://github.com/advisories/${id}` },
  { prefix: 'CVE-', url: id => `https://nvd.nist.gov/vuln/detail/${id}` },
  { prefix: 'RUSTSEC-', url: id => `https://rustsec.org/advisories/${id}.html` },
  { prefix: 'GO-', url: id => `https://pkg.go.dev/vuln/${id}` },
  { prefix: 'PYSEC-', url: id => `https://osv.dev/vulnerability/${id}` },
]

/**
 * Canonical reference URL for an advisory alias, or null when the prefix has no known
 * home database (the caller renders a plain chip instead of a link).
 * @param {string|null|undefined} alias e.g. "GHSA-xxxx-xxxx-xxxx", "CVE-2024-12345".
 * @returns {string|null}
 */
export function aliasUrl(alias) {
  if (!alias) return null
  const match = ALIAS_URL_BY_PREFIX.find(entry => alias.startsWith(entry.prefix))
  return match ? match.url(alias) : null
}
