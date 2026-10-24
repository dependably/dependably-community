import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { get } from 'svelte/store'
import { user, route, pendingRoute } from './store.js'
import { api, systemApi, ApiError } from './api.js'

/** @type {import('vitest').Mock} */
let fetchMock

function ok(body = { ok: true }) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: { get: () => null },
    json: async () => body,
    text: async () => 'plain',
    blob: async () => new Blob(['x']),
  }
}

/** @param {number} status
 *  @param {any} body
 *  @param {{ statusText?: string, retryAfter?: string | null, jsonThrows?: boolean }} [opts] */
function failing(status, body, { statusText = 'Reason', retryAfter = null, jsonThrows = false } = {}) {
  return {
    ok: false,
    status,
    statusText,
    headers: { get: (h) => (h === 'Retry-After' ? retryAfter : null) },
    json: jsonThrows ? async () => { throw new SyntaxError('bad json') } : async () => body,
    text: async () => '',
  }
}

beforeEach(() => {
  user.set({ userId: 'u1', email: 'a@b' })
  route.set({ page: 'packages', params: {} })
  pendingRoute.set(null)
  fetchMock = vi.fn().mockResolvedValue(ok())
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const P = '/api/v1'

// [label, invoke, method, path-below-/api/v1, body]
/** @type {Array<[string, () => Promise<any>, string, string, any?]>} */
const jsonEndpoints = [
  ['getBootstrap', () => api.getBootstrap(), 'GET', '/bootstrap'],
  ['getLicenses', () => api.getLicenses(), 'GET', '/licenses'],
  ['logout', () => api.logout(), 'POST', '/auth/logout'],
  ['forgotPassword', () => api.forgotPassword('a@b.c'), 'POST', '/auth/forgot-password', { email: 'a@b.c' }],
  ['resetPassword', () => api.resetPassword('tok', 'pw'), 'POST', '/auth/reset-password', { token: 'tok', newPassword: 'pw' }],
  ['me', () => api.me(), 'GET', '/auth/me'],
  ['changePassword', () => api.changePassword('old', 'new'), 'POST', '/users/me/password', { currentPassword: 'old', newPassword: 'new' }],
  ['updateLanguage', () => api.updateLanguage('fr'), 'POST', '/users/me/language', { language: 'fr' }],
  ['updateTimezone', () => api.updateTimezone('America/Toronto'), 'POST', '/users/me/timezone', { timezone: 'America/Toronto' }],
  ['updateTimezone null', () => api.updateTimezone(null), 'POST', '/users/me/timezone', { timezone: null }],
  ['mfaStatus', () => api.mfaStatus(), 'GET', '/mfa/status'],
  ['mfaSetupBegin', () => api.mfaSetupBegin(), 'POST', '/mfa/setup/begin'],
  ['mfaSetupVerify', () => api.mfaSetupVerify('123456'), 'POST', '/mfa/setup/verify', { code: '123456' }],
  ['mfaDisable', () => api.mfaDisable('pw', '123456'), 'POST', '/mfa/disable', { currentPassword: 'pw', code: '123456' }],
  ['mfaRegenerateRecoveryCodes', () => api.mfaRegenerateRecoveryCodes('123456'), 'POST', '/mfa/recovery-codes/regenerate', { code: '123456' }],
  ['getAuthMethods', () => api.getAuthMethods(), 'GET', '/auth/methods'],
  ['getAuthConfig', () => api.getAuthConfig(), 'GET', '/auth-config'],
  ['putAuthConfig', () => api.putAuthConfig({ a: 1 }), 'PUT', '/auth-config', { a: 1 }],
  ['uploadSamlMetadata', () => api.uploadSamlMetadata('<xml/>'), 'POST', '/auth-config/metadata', { metadataXml: '<xml/>' }],
  ['deleteAuthConfig', () => api.deleteAuthConfig(), 'DELETE', '/auth-config'],
  ['getInstanceSettings', () => api.getInstanceSettings(), 'GET', '/instance/settings'],
  ['updateInstanceSettings', () => api.updateInstanceSettings({ a: 1 }), 'PUT', '/instance/settings', { a: 1 }],
  ['getMetricsAccess', () => api.getMetricsAccess(), 'GET', '/instance/metrics-access'],
  ['updateMetricsAccess', () => api.updateMetricsAccess({ a: 1 }), 'PUT', '/instance/metrics-access', { a: 1 }],
  ['getInstanceEmailConfig', () => api.getInstanceEmailConfig(), 'GET', '/instance/email-config'],
  ['updateInstanceEmailConfig', () => api.updateInstanceEmailConfig({ a: 1 }), 'PUT', '/instance/email-config', { a: 1 }],
  ['testInstanceEmail', () => api.testInstanceEmail(), 'POST', '/instance/email-config/test'],
  ['getInstanceEmailHealth', () => api.getInstanceEmailHealth(), 'GET', '/instance/email-health'],
  ['getInstanceVulnTrackerConfig', () => api.getInstanceVulnTrackerConfig(), 'GET', '/instance/vuln-tracker-config'],
  ['updateInstanceVulnTrackerConfig', () => api.updateInstanceVulnTrackerConfig({ a: 1 }), 'PUT', '/instance/vuln-tracker-config', { a: 1 }],
  ['testInstanceVulnTrackerConfig', () => api.testInstanceVulnTrackerConfig(), 'POST', '/instance/vuln-tracker-config/test'],
  ['getInstanceVulnTrackerHealth', () => api.getInstanceVulnTrackerHealth(), 'GET', '/instance/vuln-tracker-health'],
  ['getOrgSettings', () => api.getOrgSettings(), 'GET', '/settings'],
  ['getRetention', () => api.getRetention(), 'GET', '/retention'],
  ['updateRetention', () => api.updateRetention({ keepVersions: 3 }), 'PUT', '/retention', { keepVersions: 3 }],
  ['getProxySettings', () => api.getProxySettings(), 'GET', '/proxy-settings'],
  ['updateProxySettings', () => api.updateProxySettings({ a: 1 }), 'PUT', '/proxy-settings', { a: 1 }],
  ['updateRpmUpstreamMode', () => api.updateRpmUpstreamMode('merged'), 'PUT', '/rpm-upstream-mode', { mode: 'merged' }],
  ['search default limit', () => api.search('left pad'), 'GET', '/search?q=left+pad&limit=8'],
  ['search explicit limit', () => api.search('x', 3), 'GET', '/search?q=x&limit=3'],
  ['lookupPackage with version', () => api.lookupPackage('npm', '@s/p', '1.0.0'), 'GET', '/lookup?ecosystem=npm&name=%40s%2Fp&version=1.0.0'],
  ['lookupPackage omits version', () => api.lookupPackage('npm', 'p'), 'GET', '/lookup?ecosystem=npm&name=p'],
  ['listPackages defaults', () => api.listPackages(), 'GET', '/packages?limit=50&page=1'],
  ['listPackages override', () => api.listPackages({ page: 3, q: 'a' }), 'GET', '/packages?limit=50&page=3&q=a'],
  ['getPackage escapes slash', () => api.getPackage('npm', '@s/p'), 'GET', '/packages/npm/@s%2Fp'],
  ['getOciScan no options', () => api.getOciScan('lib/img', 'sha256:abc'), 'GET', '/packages/oci/lib%2Fimg/sha256:abc/scan'],
  ['getOciScan options', () => api.getOciScan('img', 'sha256:abc', { platform: 'linux/amd64', affectedOnly: false, offset: 0, limit: 25 }), 'GET', '/packages/oci/img/sha256:abc/scan?platform=linux%2Famd64&affectedOnly=false&offset=0&limit=25'],
  ['deleteVersion', () => api.deleteVersion('npm', '@s/p', '1.0.0'), 'DELETE', '/packages/npm/@s%2Fp/1.0.0'],
  ['listProjects defaults', () => api.listProjects(), 'GET', '/projects?limit=50&offset=0'],
  ['listProjects override', () => api.listProjects({ offset: 50 }), 'GET', '/projects?limit=50&offset=50'],
  ['getProject', () => api.getProject('a b'), 'GET', '/projects/a%20b'],
  ['listProjectCollections', () => api.listProjectCollections(), 'GET', '/projects/collections'],
  ['createProject', () => api.createProject({ name: 'n' }), 'POST', '/projects', { name: 'n' }],
  ['updateProject', () => api.updateProject('p/1', { parentId: null }), 'PATCH', '/projects/p%2F1', { parentId: null }],
  ['deleteProject', () => api.deleteProject('p1'), 'DELETE', '/projects/p1'],
  ['deleteProjectVersion', () => api.deleteProjectVersion('p1', 'v 1'), 'DELETE', '/projects/p1/versions/v%201'],
  ['promoteLatest', () => api.promoteLatest('p1', 'v1'), 'POST', '/projects/p1/versions/v1/promote-latest'],
  ['setProjectVersionActive', () => api.setProjectVersionActive('p1', 'v1', false), 'PATCH', '/projects/p1/versions/v1', { isActive: false }],
  ['getActivity defaults', () => api.getActivity(), 'GET', '/activity?limit=50&page=1'],
  ['getActivity params', () => api.getActivity({ page: 2, actor: 'x' }), 'GET', '/activity?limit=50&page=2&actor=x'],
  ['listClaims none', () => api.listClaims(), 'GET', '/admin/claims'],
  ['listClaims filter', () => api.listClaims({ state: 'held' }), 'GET', '/admin/claims?state=held'],
  ['getClaim', () => api.getClaim('npm', '@s/p'), 'GET', '/admin/claims/npm/%40s%2Fp'],
  ['createClaim', () => api.createClaim({ a: 1 }), 'POST', '/admin/claims', { a: 1 }],
  ['transitionClaim', () => api.transitionClaim('npm', 'p', { to: 'held' }), 'PATCH', '/admin/claims/npm/p', { to: 'held' }],
  ['releaseClaim no reason', () => api.releaseClaim('npm', 'p'), 'DELETE', '/admin/claims/npm/p'],
  ['releaseClaim reason', () => api.releaseClaim('npm', 'p', 'a b&c'), 'DELETE', '/admin/claims/npm/p?reason=a%20b%26c'],
  ['getAudit defaults', () => api.getAudit(), 'GET', '/audit?limit=50&page=1'],
  ['getAudit params', () => api.getAudit({ action: 'x' }), 'GET', '/audit?limit=50&page=1&action=x'],
  ['getAllowlist', () => api.getAllowlist(), 'GET', '/allowlist'],
  ['addAllowlist', () => api.addAllowlist('pkg:npm/*'), 'POST', '/allowlist', { purlPattern: 'pkg:npm/*' }],
  ['deleteAllowlist', () => api.deleteAllowlist(7), 'DELETE', '/allowlist/7'],
  ['getBlocklist', () => api.getBlocklist(), 'GET', '/blocklist'],
  ['addBlocklist', () => api.addBlocklist('pkg:npm/evil'), 'POST', '/blocklist', { pattern: 'pkg:npm/evil' }],
  ['deleteBlocklist', () => api.deleteBlocklist(7), 'DELETE', '/blocklist/7'],
  ['getReservedNamespaces', () => api.getReservedNamespaces(), 'GET', '/reserved-namespaces'],
  ['addReservedNamespace', () => api.addReservedNamespace('npm', '@corp/*'), 'POST', '/reserved-namespaces', { ecosystem: 'npm', pattern: '@corp/*' }],
  ['deleteReservedNamespace', () => api.deleteReservedNamespace(7), 'DELETE', '/reserved-namespaces/7'],
  ['getInstallScriptAllowlist', () => api.getInstallScriptAllowlist(), 'GET', '/install-script-allowlist'],
  ['addInstallScriptAllowlist pattern', () => api.addInstallScriptAllowlist('npm', 'p', '1.*'), 'POST', '/install-script-allowlist', { ecosystem: 'npm', name: 'p', versionPattern: '1.*' }],
  ['addInstallScriptAllowlist empty pattern is null', () => api.addInstallScriptAllowlist('npm', 'p', ''), 'POST', '/install-script-allowlist', { ecosystem: 'npm', name: 'p', versionPattern: null }],
  ['deleteInstallScriptAllowlist', () => api.deleteInstallScriptAllowlist(7), 'DELETE', '/install-script-allowlist/7'],
  ['getQuarantine defaults', () => api.getQuarantine(), 'GET', '/quarantine?limit=50&offset=0'],
  ['getQuarantine params', () => api.getQuarantine({ offset: 50 }), 'GET', '/quarantine?limit=50&offset=50'],
  ['decideQuarantine', () => api.decideQuarantine(4, 'release', 'ok'), 'POST', '/quarantine/4/decide', { decision: 'release', note: 'ok' }],
  ['getUpstreamRegistries', () => api.getUpstreamRegistries(), 'GET', '/upstream-registries'],
  ['addUpstreamRegistry minimal', () => api.addUpstreamRegistry(/** @type {any} */ ({ ecosystem: 'npm', url: 'https://u', name: 'n', authType: 'anonymous' })), 'POST', '/upstream-registries', { ecosystem: 'npm', url: 'https://u', name: 'n' }],
  ['addUpstreamRegistry full', () => api.addUpstreamRegistry(/** @type {any} */ ({ ecosystem: 'npm', url: 'https://u', name: 'n', authType: 'basic', username: 'u', secret: 's', protocol: 'v3', publicKeyPem: 'PEM' })), 'POST', '/upstream-registries', { ecosystem: 'npm', url: 'https://u', name: 'n', authType: 'basic', username: 'u', secret: 's', protocol: 'v3', publicKeyPem: 'PEM' }],
  ['addOciUpstreamRegistry', () => api.addOciUpstreamRegistry(/** @type {any} */ ({ name: '', url: 'https://r', authType: 'token', prefixes: ['lib/'] })), 'POST', '/upstream-registries', { ecosystem: 'oci', url: 'https://r', name: null, authType: 'token', username: null, secret: null, tokenEndpoint: null, prefixes: ['lib/'] }],
  ['addOciUpstreamRegistry full', () => api.addOciUpstreamRegistry(/** @type {any} */ ({ name: 'n', url: 'https://r', authType: 'basic', username: 'u', secret: 's', tokenEndpoint: 'https://t', prefixes: [] })), 'POST', '/upstream-registries', { ecosystem: 'oci', url: 'https://r', name: 'n', authType: 'basic', username: 'u', secret: 's', tokenEndpoint: 'https://t', prefixes: [] }],
  ['deleteUpstreamRegistry', () => api.deleteUpstreamRegistry(3), 'DELETE', '/upstream-registries/3'],
  ['reorderUpstreamRegistries', () => api.reorderUpstreamRegistries('npm', [2, 1]), 'PUT', '/upstream-registries/npm/order', { ids: [2, 1] }],
  ['setUpstreamSymbolServer', () => api.setUpstreamSymbolServer(3, 'https://sym'), 'PUT', '/upstream-registries/3/symbol-server', { symbolServerUrl: 'https://sym' }],
  ['getHexSigningKey', () => api.getHexSigningKey(), 'GET', '/hex/signing-key'],
  ['rotateHexSigningKey', () => api.rotateHexSigningKey(), 'POST', '/hex/signing-key/rotate'],
  ['getSbomSigningKey', () => api.getSbomSigningKey(), 'GET', '/sbom-signing-key'],
  ['rotateSbomSigningKey', () => api.rotateSbomSigningKey(), 'POST', '/sbom-signing-key/rotate'],
  ['getSbomSigningKeys', () => api.getSbomSigningKeys(), 'GET', '/sbom-signing-keys'],
  ['getTrustAnchors', () => api.getTrustAnchors(), 'GET', '/trust-anchors'],
  ['addTrustAnchor', () => api.addTrustAnchor(/** @type {any} */ ({ ecosystem: 'rpm', anchorKind: 'gpg', material: 'M' })), 'POST', '/trust-anchors', { ecosystem: 'rpm', anchorKind: 'gpg', material: 'M', label: null, keyId: null }],
  ['addTrustAnchor labelled', () => api.addTrustAnchor(/** @type {any} */ ({ ecosystem: 'rpm', anchorKind: 'gpg', material: 'M', label: 'L', keyId: 'K' })), 'POST', '/trust-anchors', { ecosystem: 'rpm', anchorKind: 'gpg', material: 'M', label: 'L', keyId: 'K' }],
  ['deleteTrustAnchor', () => api.deleteTrustAnchor(5), 'DELETE', '/trust-anchors/5'],
  ['listTokens', () => api.listTokens(), 'GET', '/tokens'],
  ['createToken', () => api.createToken(['read:packages'], '2030-01-01', 'd'), 'POST', '/tokens', { capabilities: ['read:packages'], expiresAt: '2030-01-01', description: 'd' }],
  ['deleteToken', () => api.deleteToken(5), 'DELETE', '/tokens/5'],
  ['listServiceTokens', () => api.listServiceTokens(), 'GET', '/service-tokens'],
  ['createServiceToken', () => api.createServiceToken('ci', ['read:packages'], null, 'd'), 'POST', '/service-tokens', { name: 'ci', capabilities: ['read:packages'], expiresAt: null, description: 'd' }],
  ['deleteServiceToken', () => api.deleteServiceToken(5), 'DELETE', '/service-tokens/5'],
  ['listWebhooks', () => api.listWebhooks(), 'GET', '/webhooks'],
  ['addWebhook', () => api.addWebhook('https://h', ['a'], 's', 'd'), 'POST', '/webhooks', { url: 'https://h', eventTypes: ['a'], secret: 's', description: 'd' }],
  ['updateWebhook', () => api.updateWebhook(9, 'https://h', ['a'], true, 's', 'd'), 'PUT', '/webhooks/9', { url: 'https://h', eventTypes: ['a'], enabled: true, secret: 's', description: 'd' }],
  ['deleteWebhook', () => api.deleteWebhook(9), 'DELETE', '/webhooks/9'],
  ['testWebhook', () => api.testWebhook(9), 'POST', '/webhooks/9/test'],
  ['listAlerts defaults', () => api.listAlerts(), 'GET', '/alerts?limit=50&offset=0'],
  ['listAlerts state', () => api.listAlerts('open', 10, 20), 'GET', '/alerts?state=open&limit=10&offset=20'],
  ['getAlertsSummary', () => api.getAlertsSummary(), 'GET', '/alerts/summary'],
  ['dismissAlert', () => api.dismissAlert(2), 'POST', '/alerts/2/dismiss'],
  ['dismissAllAlerts', () => api.dismissAllAlerts(), 'POST', '/alerts/dismiss-all'],
  ['getAlertSettings', () => api.getAlertSettings(), 'GET', '/alert-settings'],
  ['updateAlertSettings', () => api.updateAlertSettings({ a: 1 }), 'PUT', '/alert-settings', { a: 1 }],
  ['updateAlertEmail', () => api.updateAlertEmail(true, 'a@b'), 'PUT', '/alert-settings/email', { emailEnabled: true, emailRecipients: 'a@b' }],
  ['updateAlertSlack', () => api.updateAlertSlack(true, 'https://s'), 'PUT', '/alert-settings/slack', { slackEnabled: true, slackWebhookUrl: 'https://s' }],
  ['testAlertSlack', () => api.testAlertSlack(), 'POST', '/alert-settings/slack/test'],
  ['testAlertEmail', () => api.testAlertEmail(), 'POST', '/alert-settings/email/test'],
  ['listInvites', () => api.listInvites(), 'GET', '/invites'],
  ['createInvite default role', () => api.createInvite('a@b'), 'POST', '/invites', { email: 'a@b', role: 'member' }],
  ['createInvite admin', () => api.createInvite('a@b', 'admin'), 'POST', '/invites', { email: 'a@b', role: 'admin' }],
  ['deleteInvite', () => api.deleteInvite(2), 'DELETE', '/invites/2'],
  ['listUsers', () => api.listUsers(), 'GET', '/users'],
  ['removeUser', () => api.removeUser('u1'), 'DELETE', '/users/u1'],
  ['updateUserRole', () => api.updateUserRole('u1', 'admin'), 'PATCH', '/users/u1/role', { role: 'admin' }],
  ['getSetup', () => api.getSetup('npm'), 'GET', '/setup/npm'],
  ['getPolicies', () => api.getPolicies(), 'GET', '/policies'],
  ['getLicensePolicy', () => api.getLicensePolicy(), 'GET', '/license-policy'],
  ['setLicenseMode', () => api.setLicenseMode('block'), 'PUT', '/license-policy/mode', { mode: 'block' }],
  ['addLicenseAllow defaults', () => api.addLicenseAllow('MIT'), 'POST', '/license-policy/allowlist', { licenseSpdx: 'MIT', disposition: 'allowed', note: null }],
  ['addLicenseAllow explicit', () => api.addLicenseAllow('MIT', 'review', /** @type {any} */ ('n')), 'POST', '/license-policy/allowlist', { licenseSpdx: 'MIT', disposition: 'review', note: 'n' }],
  ['updateLicenseAllow', () => api.updateLicenseAllow('GPL-2.0+', { note: 'n' }), 'PATCH', '/license-policy/allowlist/GPL-2.0%2B', { note: 'n' }],
  ['removeLicenseAllow', () => api.removeLicenseAllow('GPL-2.0+'), 'DELETE', '/license-policy/allowlist/GPL-2.0%2B'],
  ['addLicenseBlock default note', () => api.addLicenseBlock('AGPL-3.0'), 'POST', '/license-policy/blocklist', { licenseSpdx: 'AGPL-3.0', note: null }],
  ['addLicenseBlock note', () => api.addLicenseBlock('AGPL-3.0', /** @type {any} */ ('n')), 'POST', '/license-policy/blocklist', { licenseSpdx: 'AGPL-3.0', note: 'n' }],
  ['updateLicenseBlock', () => api.updateLicenseBlock('AGPL-3.0', { note: 'n' }), 'PATCH', '/license-policy/blocklist/AGPL-3.0', { note: 'n' }],
  ['removeLicenseBlock', () => api.removeLicenseBlock('AGPL-3.0'), 'DELETE', '/license-policy/blocklist/AGPL-3.0'],
  ['searchSpdx defaults', () => api.searchSpdx(), 'GET', '/spdx-licenses?q=&includeDeprecated=false&limit=50'],
  ['searchSpdx explicit', () => api.searchSpdx('mit', true, 5), 'GET', '/spdx-licenses?q=mit&includeDeprecated=true&limit=5'],
  ['getSpdx', () => api.getSpdx('GPL-2.0+'), 'GET', '/spdx-licenses/GPL-2.0%2B'],
  ['getSpdxText', () => api.getSpdxText('MIT'), 'GET', '/spdx-licenses/MIT/text'],
  ['getLicenseReview default', () => api.getLicenseReview(), 'GET', '/license-policy/review?includeDeprecated=false'],
  ['getLicenseReview deprecated', () => api.getLicenseReview(true), 'GET', '/license-policy/review?includeDeprecated=true'],
  ['getVulnReport defaults', () => api.getVulnReport(), 'GET', '/vuln-report?limit=50&page=1'],
  ['getVulnReport params', () => api.getVulnReport({ page: 2, severity: 'high' }), 'GET', '/vuln-report?limit=50&page=2&severity=high'],
  ['getVulnDetail bare', () => api.getVulnDetail('GHSA-1'), 'GET', '/vulnerabilities/GHSA-1'],
  ['getVulnDetail version', () => api.getVulnDetail('GHSA-1', '1.0.0'), 'GET', '/vulnerabilities/GHSA-1?version=1.0.0'],
  ['getVulnDetail version+package', () => api.getVulnDetail('GHSA-1', '1.0.0', 'npm', 'p'), 'GET', '/vulnerabilities/GHSA-1?version=1.0.0&ecosystem=npm&name=p'],
  ['getVulnDetail ecosystem without name ignored', () => api.getVulnDetail('GHSA-1', undefined, 'npm'), 'GET', '/vulnerabilities/GHSA-1'],
  ['getBlastRadiusByPackage', () => api.getBlastRadiusByPackage('npm', 'p'), 'GET', '/blast-radius/package?ecosystem=npm&name=p&limit=50&page=1'],
  ['getBlastRadiusByPackage page', () => api.getBlastRadiusByPackage('npm', 'p', { page: 4 }), 'GET', '/blast-radius/package?ecosystem=npm&name=p&limit=50&page=4'],
  ['getBlastRadiusByAdvisory', () => api.getBlastRadiusByAdvisory('GHSA-1'), 'GET', '/blast-radius/advisory?osvId=GHSA-1&limit=50&page=1'],
  ['getBlastRadiusCounts', () => api.getBlastRadiusCounts('package', ['a b', 'c']), 'GET', '/blast-radius/counts?kind=package&key=a%20b&key=c'],
  ['rescanVersion', () => api.rescanVersion('npm', '@s/p', '1.0.0'), 'POST', '/packages/npm/@s%2Fp/1.0.0/rescan'],
  ['blockVersion', () => api.blockVersion('npm', 'p', '1.0.0'), 'POST', '/packages/npm/p/1.0.0/block'],
  ['unblockVersion', () => api.unblockVersion('npm', 'p', '1.0.0'), 'POST', '/packages/npm/p/1.0.0/unblock'],
  ['setPackageVersionOverwrite', () => api.setPackageVersionOverwrite('npm', '@s/p', 'allow'), 'PATCH', '/packages/npm/@s%2Fp/version-overwrite', { override: 'allow' }],
  ['getRemediationSkills', () => api.getRemediationSkills(), 'GET', '/remediation/skills'],
  ['getSkills', () => api.getSkills(), 'GET', '/skills'],
  ['getOperationalRisk', () => api.getOperationalRisk({ page: 2 }), 'GET', '/risk/operational?limit=50&page=2'],
  ['getLicenseRisk', () => api.getLicenseRisk(), 'GET', '/risk/license?limit=50&page=1'],
  ['getStats', () => api.getStats(), 'GET', '/stats'],
  ['listBanners', () => api.listBanners(), 'GET', '/banners'],
  ['createBanner', () => api.createBanner({ m: 1 }), 'POST', '/banners', { m: 1 }],
  ['updateBanner', () => api.updateBanner(3, { m: 1 }), 'PUT', '/banners/3', { m: 1 }],
  ['deleteBanner', () => api.deleteBanner(3), 'DELETE', '/banners/3'],
  ['getActiveBanners', () => api.getActiveBanners(), 'GET', '/banners/active'],
  ['dismissBanner', () => api.dismissBanner(3), 'POST', '/banners/3/dismiss'],
  ['getProjectVersionAnalysis', () => api.getProjectVersionAnalysis('p', 'v', { q: 'x' }), 'GET', '/projects/p/versions/v/analysis?q=x'],
  ['putProjectVersionAnalysis', () => api.putProjectVersionAnalysis('p', 'v', { s: 1 }), 'PUT', '/projects/p/versions/v/analysis', { s: 1 }],
  ['listProjectVersionDocuments', () => api.listProjectVersionDocuments('p', 'v'), 'GET', '/projects/p/versions/v/documents'],
  ['getSbomConformance', () => api.getSbomConformance('p', 'v'), 'GET', '/projects/p/versions/v/documents/sbom/conformance'],
  ['rescanProjectVersion', () => api.rescanProjectVersion('p', 'v'), 'POST', '/projects/p/versions/v/rescan'],
]

/** @type {Array<[string, () => Promise<any>, string, string, any?]>} */
const systemEndpoints = [
  ['getDashboard', () => systemApi.getDashboard(), 'GET', '/system/dashboard'],
  ['listTenants defaults', () => systemApi.listTenants(), 'GET', '/system/tenants?page=1&limit=50'],
  ['listTenants paged', () => systemApi.listTenants(2, 10), 'GET', '/system/tenants?page=2&limit=10'],
  ['createTenant', () => systemApi.createTenant('acme', 'o@a.c'), 'POST', '/system/tenants', { slug: 'acme', ownerEmail: 'o@a.c' }],
  ['softDeleteTenant', () => systemApi.softDeleteTenant('acme'), 'DELETE', '/system/tenants/acme'],
  ['restoreTenant', () => systemApi.restoreTenant('acme'), 'PATCH', '/system/tenants/acme/restore'],
  ['setTenantStorageQuota', () => systemApi.setTenantStorageQuota('acme', 1024), 'PATCH', '/system/tenants/acme/storage-quota', { quotaBytes: 1024 }],
  ['setTenantStatus', () => systemApi.setTenantStatus('acme', 'suspended'), 'PATCH', '/system/tenants/acme/status', { status: 'suspended' }],
  ['getFleetUsage defaults', () => systemApi.getFleetUsage(), 'GET', '/system/usage?page=1&pageSize=50'],
  ['getFleetUsage full', () => systemApi.getFleetUsage({ from: '2026-01-01', to: '2026-02-01', sort: 'name', dir: 'desc', page: 2, pageSize: 10 }), 'GET', '/system/usage?page=2&pageSize=10&from=2026-01-01&to=2026-02-01&sort=name&dir=desc'],
  ['getTenantUsage bare', () => systemApi.getTenantUsage('a b'), 'GET', '/system/tenants/a%20b/usage'],
  ['getTenantUsage full', () => systemApi.getTenantUsage('acme', { from: 'f', to: 't', granularity: 'hour' }), 'GET', '/system/tenants/acme/usage?from=f&to=t&granularity=hour'],
  ['lookupUsers defaults', () => systemApi.lookupUsers(), 'GET', '/system/users?limit=50'],
  ['lookupUsers full', () => systemApi.lookupUsers({ email: 'a@b', tenantSlug: 'acme', limit: 5 }), 'GET', '/system/users?email=a%40b&tenantSlug=acme&limit=5'],
  ['listAudit defaults', () => systemApi.listAudit(), 'GET', '/system/audit?page=1&limit=50'],
  ['listAudit full', () => systemApi.listAudit({ page: 2, limit: 5, search: 's', action: 'a', sortBy: 'ts', sortDir: 'asc' }), 'GET', '/system/audit?page=2&limit=5&search=s&action=a&sortBy=ts&sortDir=asc'],
  ['listSystemAuditActions', () => systemApi.listSystemAuditActions(), 'GET', '/system/audit/actions'],
  ['listBackgroundJobs defaults', () => systemApi.listBackgroundJobs(), 'GET', '/system/background-jobs?page=1&limit=50'],
  ['listBackgroundJobs full', () => systemApi.listBackgroundJobs({ page: 2, limit: 5, search: 's', jobName: 'j', outcome: 'ok', sortBy: 'ts', sortDir: 'asc' }), 'GET', '/system/background-jobs?page=2&limit=5&search=s&jobName=j&outcome=ok&sortBy=ts&sortDir=asc'],
  ['getBackgroundJobFacets', () => systemApi.getBackgroundJobFacets(), 'GET', '/system/background-jobs/facets'],
  ['getSettings', () => systemApi.getSettings(), 'GET', '/system/settings'],
  ['updateSettings', () => systemApi.updateSettings({ a: 1 }), 'PUT', '/system/settings', { a: 1 }],
  ['sys getMetricsAccess', () => systemApi.getMetricsAccess(), 'GET', '/system/metrics-access'],
  ['sys updateMetricsAccess', () => systemApi.updateMetricsAccess({ a: 1 }), 'PUT', '/system/metrics-access', { a: 1 }],
  ['getEmailConfig', () => systemApi.getEmailConfig(), 'GET', '/system/email-config'],
  ['updateEmailConfig', () => systemApi.updateEmailConfig({ a: 1 }), 'PUT', '/system/email-config', { a: 1 }],
  ['testEmailConfig', () => systemApi.testEmailConfig(), 'POST', '/system/email-config/test'],
  ['getEmailHealth', () => systemApi.getEmailHealth(), 'GET', '/system/email-health'],
  ['getVulnTrackerConfig', () => systemApi.getVulnTrackerConfig(), 'GET', '/system/vuln-tracker-config'],
  ['updateVulnTrackerConfig', () => systemApi.updateVulnTrackerConfig({ a: 1 }), 'PUT', '/system/vuln-tracker-config', { a: 1 }],
  ['testVulnTrackerConfig', () => systemApi.testVulnTrackerConfig(), 'POST', '/system/vuln-tracker-config/test'],
  ['getVulnTrackerHealth', () => systemApi.getVulnTrackerHealth(), 'GET', '/system/vuln-tracker-health'],
  ['setAccountStatus', () => systemApi.setAccountStatus('a@b', 'acme', 'locked'), 'PATCH', '/system/users/account-status', { email: 'a@b', tenantSlug: 'acme', accountStatus: 'locked' }],
  ['issuePasswordReset', () => systemApi.issuePasswordReset('a@b', 'acme'), 'POST', '/system/users/password-reset', { email: 'a@b', tenantSlug: 'acme' }],
  ['getHealth', () => systemApi.getHealth(), 'GET', '/system/health'],
  ['listSuspectTrustAnchors', () => systemApi.listSuspectTrustAnchors(), 'GET', '/system/trust-anchors/suspect'],
  ['sys me', () => systemApi.me(), 'GET', '/system/me'],
  ['sys changePassword', () => systemApi.changePassword('o', 'n'), 'POST', '/system/me/password', { currentPassword: 'o', newPassword: 'n' }],
  ['sys updateLanguage', () => systemApi.updateLanguage('fr'), 'POST', '/system/me/language', { language: 'fr' }],
  ['sys updateTimezone', () => systemApi.updateTimezone('UTC'), 'POST', '/system/me/timezone', { timezone: 'UTC' }],
  ['sys mfaStatus', () => systemApi.mfaStatus(), 'GET', '/system/mfa/status'],
  ['sys mfaSetupBegin', () => systemApi.mfaSetupBegin(), 'POST', '/system/mfa/setup/begin'],
  ['sys mfaSetupVerify', () => systemApi.mfaSetupVerify('1'), 'POST', '/system/mfa/setup/verify', { code: '1' }],
  ['sys mfaDisable', () => systemApi.mfaDisable('pw', '1'), 'POST', '/system/mfa/disable', { currentPassword: 'pw', code: '1' }],
  ['sys mfaRegenerateRecoveryCodes', () => systemApi.mfaRegenerateRecoveryCodes('1'), 'POST', '/system/mfa/recovery-codes/regenerate', { code: '1' }],
  ['listAdmins', () => systemApi.listAdmins(), 'GET', '/system/admins'],
  ['createAdmin', () => systemApi.createAdmin('a@b'), 'POST', '/system/admins', { email: 'a@b' }],
  ['getAdmin', () => systemApi.getAdmin('a/b'), 'GET', '/system/admins/a%2Fb'],
  ['setAdminAccountStatus', () => systemApi.setAdminAccountStatus('a1', 'locked'), 'PATCH', '/system/admins/a1/account-status', { accountStatus: 'locked' }],
  ['resetAdminPassword', () => systemApi.resetAdminPassword('a1'), 'POST', '/system/admins/a1/password-reset'],
  ['deleteAdmin', () => systemApi.deleteAdmin('a1'), 'DELETE', '/system/admins/a1'],
  ['listSystemTokens', () => systemApi.listSystemTokens(), 'GET', '/system/tokens'],
  ['createSystemToken', () => systemApi.createSystemToken('n', null, 'd'), 'POST', '/system/tokens', { name: 'n', expiresAt: null, description: 'd' }],
  ['deleteSystemToken', () => systemApi.deleteSystemToken('t/1'), 'DELETE', '/system/tokens/t%2F1'],
  ['listSystemBanners', () => systemApi.listSystemBanners(), 'GET', '/system/banners'],
  ['createSystemBanner', () => systemApi.createSystemBanner({ m: 1 }), 'POST', '/system/banners', { m: 1 }],
  ['updateSystemBanner', () => systemApi.updateSystemBanner(3, { m: 1 }), 'PUT', '/system/banners/3', { m: 1 }],
  ['deleteSystemBanner', () => systemApi.deleteSystemBanner(3), 'DELETE', '/system/banners/3'],
  ['getSlackConfig', () => systemApi.getSlackConfig(), 'GET', '/system/slack-config'],
  ['updateSlackConfig', () => systemApi.updateSlackConfig({ a: 1 }), 'PUT', '/system/slack-config', { a: 1 }],
  ['testSlackConfig', () => systemApi.testSlackConfig(), 'POST', '/system/slack-config/test'],
]

describe('JSON endpoint request shape', () => {
  it.each([...jsonEndpoints, ...systemEndpoints])('%s', async (_label, invoke, method, path, body) => {
    const result = await invoke()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe(P + path)
    expect(opts.method).toBe(method)
    expect(opts.credentials).toBe('include')
    expect(opts.headers).toEqual({ 'Content-Type': 'application/json' })
    if (body === undefined) {
      expect(opts.body).toBeUndefined()
    } else {
      expect(JSON.parse(opts.body)).toEqual(body)
    }
    expect(result).toEqual({ ok: true })
  })
})

describe('updateOrgSettings', () => {
  it('sends exactly the whitelisted fields and drops unknown ones', async () => {
    const fields = {
      anonymousPull: true,
      allowlistMode: false,
      maxUploadBytes: 1,
      maxUploadBytesPyPi: 2,
      maxUploadBytesNpm: 3,
      maxUploadBytesNuGet: 4,
      maxUploadBytesMaven: 5,
      maxUploadBytesRpm: 6,
      maxUploadBytesOci: 7,
      defaultLanguage: 'fr',
      defaultTimezone: 'UTC',
      allowVersionOverwrite: true,
      versionOverwritePolicy: 'p',
      airGapped: false,
      requireMfa: true,
    }
    await api.updateOrgSettings({ ...fields, sneaky: 'dropped' })

    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe(`${P}/settings`)
    expect(opts.method).toBe('PUT')
    expect(JSON.parse(opts.body)).toEqual(fields)
  })
})

describe('login endpoints', () => {
  it('login posts credentials', async () => {
    await api.login('a@b', 'pw')
    expect(fetchMock.mock.calls[0][0]).toBe(`${P}/auth/login`)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ email: 'a@b', password: 'pw' })
  })

  it('loginTotp posts the code and remember flag', async () => {
    await api.loginTotp('123456', true)
    expect(fetchMock.mock.calls[0][0]).toBe(`${P}/auth/login/totp`)
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ code: '123456', rememberDevice: true })
  })
})

describe('req response handling', () => {
  it('returns null for 204 without reading the body', async () => {
    const json = vi.fn()
    fetchMock.mockResolvedValueOnce({ ok: true, status: 204, headers: { get: () => null }, json })
    expect(await api.logout()).toBeNull()
    expect(json).not.toHaveBeenCalled()
  })

  it('returns null for an empty 200 body (json parse failure)', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => { throw new SyntaxError('empty') },
    })
    expect(await api.getStats()).toBeNull()
  })

  it('prefers problem detail, then title, then statusText for the message', async () => {
    fetchMock.mockResolvedValueOnce(failing(400, { detail: 'D', title: 'T' }))
    await expect(api.getStats()).rejects.toMatchObject({ message: 'D', status: 400 })
    fetchMock.mockResolvedValueOnce(failing(400, { title: 'T' }))
    await expect(api.getStats()).rejects.toMatchObject({ message: 'T' })
    fetchMock.mockResolvedValueOnce(failing(502, null, { statusText: 'Bad Gateway', jsonThrows: true }))
    await expect(api.getStats()).rejects.toMatchObject({ message: 'Bad Gateway', status: 502, body: null })
  })

  it('throws an ApiError carrying status, Retry-After and the parsed body', async () => {
    const body = { title: 'Too many', extra: 1 }
    fetchMock.mockResolvedValueOnce(failing(429, body, { retryAfter: '30' }))
    const err = await api.getStats().catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.name).toBe('ApiError')
    expect(err.status).toBe(429)
    expect(err.retryAfter).toBe('30')
    expect(err.body).toBe(body)
  })

  it('ApiError defaults retryAfter to null and body to undefined', () => {
    const err = new ApiError('m', { status: 500 })
    expect(err.retryAfter).toBeNull()
    expect(err.body).toBeUndefined()
    expect(err.message).toBe('m')
  })

  it('does not touch session state on non-401 failures', async () => {
    fetchMock.mockResolvedValueOnce(failing(403, { title: 'no' }))
    await expect(api.getStats()).rejects.toMatchObject({ status: 403 })
    expect(get(user)).not.toBeNull()
    expect(get(route).page).toBe('packages')
  })
})

describe('401 handling', () => {
  afterEach(() => {
    window.history.pushState({}, '', '/')
  })

  it('clears the user, remembers the page and routes to login', async () => {
    route.set({ page: 'packages', params: { q: 'x' } })
    fetchMock.mockResolvedValueOnce(failing(401, { title: 'Unauthorized' }))

    await expect(api.getStats()).rejects.toMatchObject({ status: 401 })

    expect(get(user)).toBeNull()
    expect(get(pendingRoute)).toEqual({ page: 'packages', params: { q: 'x' } })
    expect(get(route).page).toBe('login')
  })

  it('routes /system/ paths to system-login', async () => {
    fetchMock.mockResolvedValueOnce(failing(401, null, { jsonThrows: true }))
    await expect(systemApi.getDashboard()).rejects.toMatchObject({ status: 401 })
    expect(get(route).page).toBe('system-login')
  })

  it.each(['login', 'system-login', 'join'])('does not stash %s as the pending route', async (page) => {
    route.set({ page, params: {} })
    fetchMock.mockResolvedValueOnce(failing(401, null))
    await expect(api.getStats()).rejects.toMatchObject({ status: 401 })
    expect(get(pendingRoute)).toBeNull()
  })

  it.each([
    ['/auth/login', () => api.login('a', 'b')],
    ['/auth/login/totp', () => api.loginTotp('1', false)],
    ['/mfa/disable', () => api.mfaDisable('p', '1')],
    ['/system/mfa/disable', () => systemApi.mfaDisable('p', '1')],
  ])('leaves the session alone for %s', async (_p, invoke) => {
    fetchMock.mockResolvedValueOnce(failing(401, { title: 'bad creds' }))
    await expect(invoke()).rejects.toMatchObject({ status: 401, message: 'bad creds' })
    expect(get(user)).not.toBeNull()
    expect(get(route).page).toBe('packages')
  })

  it.each(['/join', '/reset'])('leaves the session alone while on %s', async (path) => {
    window.history.pushState({}, '', path)
    fetchMock.mockResolvedValueOnce(failing(401, null))
    await expect(api.me()).rejects.toMatchObject({ status: 401 })
    expect(get(user)).not.toBeNull()
    expect(get(route).page).toBe('packages')
  })
})

describe('reqText', () => {
  it('returns the response text and encodes the skill id', async () => {
    fetchMock.mockResolvedValueOnce({ ...ok(), text: async () => '# skill' })
    expect(await api.getSkillMarkdown('a/b')).toBe('# skill')
    expect(fetchMock).toHaveBeenCalledWith(`${P}/skills/a%2Fb`, { credentials: 'include' })
  })

  it('throws ApiError with statusText and Retry-After on failure', async () => {
    fetchMock.mockResolvedValueOnce(failing(404, null, { statusText: 'Not Found', retryAfter: '5' }))
    const err = await api.getSkillMarkdown('x').catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 404, message: 'Not Found', retryAfter: '5' })
  })

  it('treats a 401 as an expired session', async () => {
    fetchMock.mockResolvedValueOnce(failing(401, null, { statusText: 'Unauthorized' }))
    await expect(api.getSkillMarkdown('x')).rejects.toMatchObject({ status: 401 })
    expect(get(user)).toBeNull()
    expect(get(route).page).toBe('login')
  })
})

describe('putRawDocument', () => {
  it('sends the raw body verbatim with the query string built from defined params only', async () => {
    const raw = '{ "b":1,  "a":2 }'
    await api.uploadSbomDocument('proj', '1.0', { autoCreate: true, isLatest: false, parentId: undefined }, raw)
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe(`${P}/sbom?projectName=proj&projectVersion=1.0&autoCreate=true&isLatest=false`)
    expect(opts.method).toBe('PUT')
    expect(opts.body).toBe(raw)
    expect(opts.credentials).toBe('include')
  })

  it('vex and sarif carry parentId and hit their own routes', async () => {
    await api.uploadVexDocument('p', '1', 'par', 'v')
    await api.uploadSarifDocument('p', '1', null, 's')
    expect(fetchMock.mock.calls[0][0]).toBe(`${P}/vex?projectName=p&projectVersion=1&parentId=par`)
    expect(fetchMock.mock.calls[1][0]).toBe(`${P}/sarif?projectName=p&projectVersion=1`)
  })

  it('throws ApiError on failure and redirects on 401', async () => {
    fetchMock.mockResolvedValueOnce(failing(422, { detail: 'invalid doc' }, { retryAfter: '9' }))
    await expect(api.uploadVexDocument('p', '1', null, 'x')).rejects.toMatchObject({
      status: 422, message: 'invalid doc', retryAfter: '9', body: { detail: 'invalid doc' },
    })

    fetchMock.mockResolvedValueOnce(failing(401, null, { jsonThrows: true, statusText: 'Unauthorized' }))
    await expect(api.uploadSarifDocument('p', '1', null, 'x')).rejects.toMatchObject({ status: 401, message: 'Unauthorized' })
    expect(get(route).page).toBe('login')
  })
})

describe('upload', () => {
  it('posts every file as multipart without a JSON content type', async () => {
    const a = new File(['a'], 'a.whl')
    const b = new File(['b'], 'b.tgz')
    const result = await api.upload([a, b])
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe(`${P}/admin/upload`)
    expect(opts.method).toBe('POST')
    expect(opts.headers).toBeUndefined()
    expect(opts.body.getAll('files').map((f) => f.name)).toEqual(['a.whl', 'b.tgz'])
    expect(result).toEqual({ ok: true })
  })

  it('maps failures to ApiError with detail, title, then statusText', async () => {
    fetchMock.mockResolvedValueOnce(failing(413, { detail: 'too big' }))
    await expect(api.upload([])).rejects.toMatchObject({ status: 413, message: 'too big' })
    fetchMock.mockResolvedValueOnce(failing(400, { title: 'bad' }))
    await expect(api.upload([])).rejects.toMatchObject({ message: 'bad' })
    fetchMock.mockResolvedValueOnce(failing(500, null, { statusText: 'Boom', jsonThrows: true }))
    await expect(api.upload([])).rejects.toMatchObject({ message: 'Boom', body: null })
  })
})

describe('downloads', () => {
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  function blobOk(disposition) {
    return {
      ok: true,
      status: 200,
      headers: { get: (h) => (h === 'Content-Disposition' ? disposition : null) },
      blob: async () => new Blob(['d']),
    }
  }

  function captureAnchors() {
    const anchors = []
    const orig = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = orig(tag)
      if (tag === 'a') anchors.push(el)
      return el
    })
    return anchors
  }

  it('downloadVersion passes the file selector and falls back to name-version', async () => {
    const anchors = captureAnchors()
    fetchMock.mockResolvedValueOnce(blobOk(null))
    await api.downloadVersion('npm', '@s/p', '1.0.0')
    expect(fetchMock.mock.calls[0][0]).toBe(`${P}/packages/npm/@s%2Fp/1.0.0/download`)
    expect(fetchMock.mock.calls[0][1]).toEqual({ credentials: 'include' })
    expect(anchors[0].download).toBe('sp-1.0.0')

    fetchMock.mockResolvedValueOnce(blobOk(null))
    await api.downloadVersion('maven', 'g:a', '1', 'a-1.jar')
    expect(fetchMock.mock.calls[1][0]).toBe(`${P}/packages/maven/g:a/1/download?file=a-1.jar`)
    expect(anchors[1].download).toBe('a-1.jar')
  })

  it('strips path characters from the server-provided filename', async () => {
    const anchors = captureAnchors()
    fetchMock.mockResolvedValueOnce(blobOk('attachment; filename="../../etc/pa ss.csv"'))
    await api.downloadProjectDocument('d/1', 'fallback.json')
    expect(fetchMock.mock.calls[0][0]).toBe(`${P}/sbom-documents/d%2F1/original`)
    expect(anchors[0].download).toBe('etcpass.csv')
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:x')
  })

  it('falls back to "download" when the sanitized name is empty', async () => {
    const anchors = captureAnchors()
    fetchMock.mockResolvedValueOnce(blobOk('attachment; filename="..."'))
    await api.downloadProjectDocument('d', 'f.json')
    expect(anchors[0].download).toBe('download')
  })

  it('export helpers route to the right endpoints with their options', async () => {
    fetchMock.mockResolvedValue(blobOk(null))
    await api.exportCollectionSbom('c 1', { format: 'json' }, 'c.json')
    await api.exportProjectVersionSbom('p', 'v', { specVersion: '1.6' }, 'p.json')
    await api.exportProjectVersionVex('p', 'v', '1.6', 'p-vex.json')
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([
      `${P}/projects/c%201/export/sbom?format=json`,
      `${P}/projects/p/versions/v/export/sbom?specVersion=1.6`,
      `${P}/projects/p/versions/v/export/vex?specVersion=1.6`,
    ])
  })

  it('exportActivity, exportAudit and exportFleetUsage request CSV exports', async () => {
    fetchMock.mockResolvedValue(blobOk(null))
    await api.exportActivity({ q: 'a' })
    await api.exportAudit({ q: 'b' })
    await systemApi.exportFleetUsage({ from: 'f' })
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([
      `${P}/activity?q=a&format=csv`,
      `${P}/audit?q=b&format=csv`,
      `${P}/system/usage.csv?from=f`,
    ])
  })

  it('throws ApiError (detail, title, statusText) when the download fails', async () => {
    fetchMock.mockResolvedValueOnce(failing(403, { detail: 'nope' }, { retryAfter: '2' }))
    await expect(api.downloadProjectDocument('d', 'f')).rejects.toMatchObject({ status: 403, message: 'nope', retryAfter: '2' })
    fetchMock.mockResolvedValueOnce(failing(403, { title: 'T' }))
    await expect(api.downloadProjectDocument('d', 'f')).rejects.toMatchObject({ message: 'T' })
    fetchMock.mockResolvedValueOnce(failing(500, null, { statusText: 'Boom', jsonThrows: true }))
    await expect(api.downloadProjectDocument('d', 'f')).rejects.toMatchObject({ message: 'Boom', body: null })
    expect(URL.createObjectURL).not.toHaveBeenCalled()
  })
})
