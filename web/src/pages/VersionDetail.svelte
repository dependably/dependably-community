<script>
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import VersionTable from '../lib/VersionTable.svelte'
  import { route, navigate, user } from '../lib/store.js'
  import { copyToClipboard } from '../lib/clipboard.js'

  $: params = $route.params
  let pkg = null, versions = [], loading = true, error = ''
  // Claim badge: surface the resolved claim state on the package header. null = no
  // claim row (implicit unclaimed in connected mode, implicit local_only in air-gap).
  let claim = null
  let scanningId = null, scanError = ''
  let vulnsByPurl = new SvelteMap()
  let versionTable

  $: if (params.ecosystem && params.name) load()

  async function load() {
    loading = true
    versionTable?.reset()
    try {
      const data = await api.getPackage(params.ecosystem, params.name)
      pkg = data.package
      versions = data.versions
      // Resolve claim state (admin-only API; ignore on permission failures).
      try {
        claim = await api.getClaim(params.ecosystem, params.name)
      } catch { claim = null }
      // Fetch vulns for this package (supplemental — ignore errors)
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  function buildVulnMap(items) {
    const map = new SvelteMap()
    for (const r of items) {
      if (!map.has(r.purl)) map.set(r.purl, [])
      if (r.osvId) map.get(r.purl).push({ osvId: r.osvId, severity: r.severity, summary: r.summary, cvssScore: r.cvssScore })
    }
    return map
  }

  async function deleteVersion(ver) {
    if (!confirm($t('versionDetail.deleteTitle', { values: { version: ver.version } }))) return
    await api.deleteVersion(params.ecosystem, params.name, ver.version)
    versions = versions.filter(v => v.id !== ver.id)
  }

  async function downloadVersion(ver) {
    try {
      await api.downloadVersion(params.ecosystem, params.name, ver.version)
    } catch (e) { error = e.message }
  }

  async function rescan(ver) {
    scanningId = ver.id; scanError = ''
    try {
      const res = await api.rescanVersion(params.ecosystem, params.name, ver.version)
      versions = versions.map(v => v.id === ver.id ? { ...v, vulnCheckedAt: res.vuln_checked_at } : v)
      // Refresh vuln data after rescan
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
      await load()
    } catch (e) {
      scanError = e.message
    } finally {
      scanningId = null
    }
  }

  async function blockVersion(ver) {
    try {
      await api.blockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  async function unblockVersion(ver) {
    try {
      await api.unblockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  function scanCooldownRemaining(ver) {
    if (!ver.vulnCheckedAt) return 0
    const elapsed = Date.now() - new Date(ver.vulnCheckedAt).getTime()
    return Math.max(0, 3600000 - elapsed)
  }

  function copy(text) {
    copyToClipboard(text)
  }

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
</script>

<div class="page">
  <div class="page-header">
    <div>
      <button on:click={() => {
        // history.state.idx === 0 means we're at the seated initial entry; history.back()
        // would leave the SPA. Anything > 0 means we pushed our way here, so back is safe.
        if ((window.history.state?.idx ?? 0) > 0) window.history.back()
        else navigate('packages', {}, { replace: true })
      }} class="mb-2">{$t('common.actions.back')}</button>
      {#if pkg}
        <h1 class="page-title">
          <span class="badge {pkg.ecosystem}">{pkg.ecosystem}</span>
          {pkg.name}
          {#if claim && (claim.state === 'local_only' || claim.state === 'mixed')}
            <span
              class="claim-badge claim-{claim.state}"
              title={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}
              aria-label={claim.state}>
              {#if claim.state === 'local_only'}
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-lock"/></svg>
              {:else}
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-exchange"/></svg>
              {/if}
              {$t(`claims.states.${claim.state}`)}
            </span>
          {/if}
        </h1>
      {/if}
    </div>
  </div>

  <ErrorBanner message={error} />
  {#if scanError}<div class="error-msg">{scanError}</div>{/if}
  {#if !loading && versions.length === 0}
    <p class="text-muted">{$t('versionDetail.empty')}</p>
  {:else}
    <VersionTable
      bind:this={versionTable}
      {pkg}
      {versions}
      {vulnsByPurl}
      {isAdmin}
      {scanningId}
      {loading}
      {scanCooldownRemaining}
      {copy}
      on:download={(e) => downloadVersion(e.detail)}
      on:rescan={(e) => rescan(e.detail)}
      on:block={(e) => blockVersion(e.detail)}
      on:unblock={(e) => unblockVersion(e.detail)}
      on:delete={(e) => deleteVersion(e.detail)}
    />
  {/if}
</div>

<style>
  /* Claim badge: surfaces the resolved claim state on the package header. Visual
     hierarchy matches Claims.svelte's state-badge so the two views feel consistent. */
  .claim-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    margin-left: 8px;
    vertical-align: middle;
  }
  .claim-local_only { background: var(--success-bg);  color: var(--success); border: 1px solid var(--success-border); }
  .claim-mixed      { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }
</style>
