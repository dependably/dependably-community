<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { submitForm, extractErrorMessage } from '../lib/form.js'
  import { user, bootstrapInfo } from '../lib/store.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { formatDateShort } from '../lib/format.js'
  import Claims from './Claims.svelte'
  import SpdxPicker from '../lib/SpdxPicker.svelte'
  import SettingsAuth from '../lib/settings/SettingsAuth.svelte'
  import SettingsGeneral from '../lib/settings/SettingsGeneral.svelte'
  import SettingsUpload from '../lib/settings/SettingsUpload.svelte'
  import SettingsRetention from '../lib/settings/SettingsRetention.svelte'
  import SettingsProxy from '../lib/settings/SettingsProxy.svelte'
  import SettingsServiceTokens from '../lib/settings/SettingsServiceTokens.svelte'
  import SettingsInstance from '../lib/settings/SettingsInstance.svelte'
  import SettingsMetrics from '../lib/settings/SettingsMetrics.svelte'

  let tab = 'general'
  let settings = null, retention = null, instanceMax = null, proxySettings = null
  let loading = true, saving = false, error = '', success = ''

  // Allowlist state
  let allowlistEntries = [], allowlistLoaded = false
  let showAddAllowlist = false, newAlPattern = '', addingAl = false

  // Blocklist state
  let blocklistEntries = [], blocklistLoaded = false
  let showAddBlocklist = false, newBlPattern = '', addingBl = false

  // Reserved-namespace state (dependency-confusion guard)
  let reservedEntries = [], reservedLoaded = false
  let showAddReserved = false, newRsvdEcosystem = 'npm', newRsvdPattern = '', addingRsvd = false

  // Install-script allowlist state
  let installScriptAllowlistEntries = [], installScriptAllowlistLoaded = false
  let showAddInstallScriptAllowlist = false
  let newIsaEcosystem = 'npm', newIsaName = '', newIsaVersionPattern = '', addingIsa = false

  // License policy state. Single fetch returns mode + both lists.
  let licensePolicyLoaded = false
  let licenseMode = 'off'
  let licenseAllowEntries = [], licenseBlockEntries = []
  let showAddLicenseAllow = false, newLicenseAllowSpdx = ''
  let showAddLicenseBlock = false, newLicenseBlockSpdx = ''
  let savingLicenseMode = false
  // Review queue: SPDX IDs seen during ingestion not yet on either list.
  let licenseReviewEntries = [], licenseReviewLoaded = false
  let licenseReviewIncludeDeprecated = false
  // Per-row pending flag so the operator-facing buttons disable while their POST is in flight.
  let licenseReviewBusy = {}
  // Reactive helper: identifiers already on either list — fed to SpdxPicker.exclude to grey
  // them out without changing behaviour (still selectable; the server returns 409 if dup).
  $: licensePolicyIdentifiers = [
    ...licenseAllowEntries.map(e => e.licenseSpdx),
    ...licenseBlockEntries.map(e => e.licenseSpdx),
  ]
  $: licenseAllowlistEmpty = licenseAllowEntries.length === 0

  onMount(async () => {
    try {
      const [s, r, inst, ps] = await Promise.all([
        api.getOrgSettings(),
        api.getRetention(),
        api.getInstanceSettings().catch(() => ({})),
        api.getProxySettings(),
      ])
      settings = { ...s }
      retention = { ...r }
      instanceMax = inst.MAX_UPLOAD_BYTES ? parseInt(inst.MAX_UPLOAD_BYTES) : null
      // Hours is the canonical wire format; the UI splits it into a value + unit (Hours/Days)
      // so 48 lands as "2 Days" and 36 stays as "36 Hours". A null/0 wire value shows as
      // an explicit "0" — the form treats 0 (and empty) as "policy off, allow all" on save.
      const ageHours = ps.min_release_age_hours
      const ageUnit = ageHours !== null && ageHours !== undefined && ageHours > 0 && ageHours % 24 === 0 ? 'days' : 'hours'
      const ageValue = ageHours === null || ageHours === undefined || ageHours === 0
        ? '0'
        : String(ageUnit === 'days' ? ageHours / 24 : ageHours)
      proxySettings = {
        ...ps,
        max_osv_score_tolerance: Number(ps.max_osv_score_tolerance ?? 10).toFixed(1),
        min_release_age_value: ageValue,
        min_release_age_unit: ageUnit,
      }
    } catch (e) { error = extractErrorMessage(e) }
    finally { loading = false }
  })

  async function switchTab(key) {
    tab = key
    error = ''; success = ''
    if (key === 'proxy') {
      if (!allowlistLoaded) loadAllowlist()
      if (!blocklistLoaded) loadBlocklist()
      if (!reservedLoaded) loadReserved()
      if (!installScriptAllowlistLoaded) loadInstallScriptAllowlist()
    }
    if (key === 'licenses' && !licensePolicyLoaded) await loadLicensePolicy()
    if (key === 'banners') loadBanners()
  }

  // ── License policy handlers ────────────────────────────────────────────────
  async function loadLicensePolicy() {
    try {
      const p = await api.getLicensePolicy()
      licenseMode = p.mode ?? 'off'
      licenseAllowEntries = p.allowlist ?? []
      licenseBlockEntries = p.blocklist ?? []
      licensePolicyLoaded = true
      await loadLicenseReview()
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function loadLicenseReview() {
    try {
      licenseReviewEntries = await api.getLicenseReview(licenseReviewIncludeDeprecated)
      licenseReviewLoaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function toggleReviewIncludeDeprecated() {
    licenseReviewIncludeDeprecated = !licenseReviewIncludeDeprecated
    await loadLicenseReview()
  }

  async function saveLicenseMode(mode) {
    const prev = licenseMode
    licenseMode = mode  // optimistic
    savingLicenseMode = true; error = ''; success = ''
    try {
      await api.setLicenseMode(mode)
      success = $t('settings.saved')
    } catch (e) {
      error = extractErrorMessage(e)
      licenseMode = prev
    } finally { savingLicenseMode = false }
  }

  async function addLicenseAllow(spdxArg) {
    const spdx = (spdxArg ?? newLicenseAllowSpdx ?? '').trim()
    if (!spdx) return
    error = ''
    try {
      const entry = await api.addLicenseAllow(spdx)
      licenseAllowEntries = [...licenseAllowEntries, entry]
      // Drop from the review queue if present — the next refresh would also drop it, but
      // updating optimistically prevents the row from flickering back briefly.
      licenseReviewEntries = licenseReviewEntries.filter(e => e.licenseSpdx !== spdx)
      showAddLicenseAllow = false; newLicenseAllowSpdx = ''
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function removeLicenseAllow(spdx) {
    if (!confirm($t('settings.licenses.removeConfirm'))) return
    try {
      await api.removeLicenseAllow(spdx)
      licenseAllowEntries = licenseAllowEntries.filter(e => e.licenseSpdx !== spdx)
      // A removed license may now reappear under review — refresh in the background.
      loadLicenseReview()
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function addLicenseBlock(spdxArg) {
    const spdx = (spdxArg ?? newLicenseBlockSpdx ?? '').trim()
    if (!spdx) return
    error = ''
    try {
      const entry = await api.addLicenseBlock(spdx)
      licenseBlockEntries = [...licenseBlockEntries, entry]
      licenseReviewEntries = licenseReviewEntries.filter(e => e.licenseSpdx !== spdx)
      showAddLicenseBlock = false; newLicenseBlockSpdx = ''
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function removeLicenseBlock(spdx) {
    if (!confirm($t('settings.licenses.removeConfirm'))) return
    try {
      await api.removeLicenseBlock(spdx)
      licenseBlockEntries = licenseBlockEntries.filter(e => e.licenseSpdx !== spdx)
      loadLicenseReview()
    } catch (e) { error = extractErrorMessage(e) }
  }

  // Review-queue actions: the underlying POST is the same as the add-modal flow; the per-row
  // busy map keeps the UI from double-firing while the network is in flight.
  async function approveReview(spdx) {
    licenseReviewBusy = { ...licenseReviewBusy, [spdx]: 'allow' }
    try { await addLicenseAllow(spdx) }
    finally { licenseReviewBusy = { ...licenseReviewBusy, [spdx]: undefined } }
  }
  async function blockReview(spdx) {
    licenseReviewBusy = { ...licenseReviewBusy, [spdx]: 'block' }
    try { await addLicenseBlock(spdx) }
    finally { licenseReviewBusy = { ...licenseReviewBusy, [spdx]: undefined } }
  }

  async function saveSettings() {
    success = ''
    await submitForm(() => api.updateOrgSettings(settings), {
      setSaving: v => saving = v,
      setError:  v => error  = v,
      onSuccess: () => { success = $t('settings.saved') },
    })
  }

  // Proxy save: persists the proxy form *and* the allowlistMode gate together. The mode
  // toggle lives in the same tab now but the value still rides on the /settings
  // payload, so we fire both endpoints in parallel.
  async function saveProxySettings() {
    success = ''
    // Convert the value+unit pair back to canonical hours. Empty value = null (policy off);
    // a positive value in days multiplies to hours. Math.floor guards against the user
    // pasting decimals into a numeric input on browsers that don't enforce the pattern.
    const raw = String(proxySettings.min_release_age_value ?? '').trim()
    const num = raw === '' ? null : Math.floor(Number(raw))
    const minReleaseAgeHours = num === null || isNaN(num) || num <= 0
      ? null
      : (proxySettings.min_release_age_unit === 'days' ? num * 24 : num)
    // Empty EPSS field = policy off (null on the wire); anything else is a 0..1 probability.
    const epssRaw = String(proxySettings.max_epss_tolerance ?? '').trim()
    const maxEpssTolerance = epssRaw === '' || isNaN(Number(epssRaw)) ? null : Number(epssRaw)
    await submitForm(() => Promise.all([
      api.updateProxySettings({
        proxyPassthroughEnabled: proxySettings.proxy_passthrough_enabled,
        maxOsvScoreTolerance:    Number(proxySettings.max_osv_score_tolerance),
        minReleaseAgeHours,
        blockDeprecated:         proxySettings.block_deprecated,
        blockMalicious:          proxySettings.block_malicious,
        blockKev:                proxySettings.block_kev,
        maxEpssTolerance,
        blockInstallScripts:     proxySettings.block_install_scripts,
        verifyNpmSignatures:     proxySettings.verify_npm_signatures,
        verifyNuGetSignatures:   proxySettings.verify_nuget_signatures,
        verifyPyPiAttestations:  proxySettings.verify_pypi_attestations,
        verifyRpmSignatures:     proxySettings.verify_rpm_signatures,
        verifyMavenSignatures:   proxySettings.verify_maven_signatures,
      }),
      api.updateOrgSettings(settings),
    ]), {
      setSaving: v => saving = v,
      setError:  v => error  = v,
      onSuccess: () => { success = $t('settings.saved') },
    })
  }

  async function saveRetention() {
    success = ''
    await submitForm(() => api.updateRetention(retention), {
      setSaving: v => saving = v,
      setError:  v => error  = v,
      onSuccess: () => { success = $t('settings.retentionSaved') },
    })
  }

  // Allowlist handlers
  async function loadAllowlist() {
    try {
      allowlistEntries = await api.getAllowlist()
      allowlistLoaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function addAllowlist() {
    addingAl = true; error = ''
    try {
      const e = await api.addAllowlist(newAlPattern)
      allowlistEntries = [...allowlistEntries, e]
      showAddAllowlist = false; newAlPattern = ''
    } catch (e) { error = extractErrorMessage(e) }
    finally { addingAl = false }
  }

  async function removeAllowlist(id) {
    if (!confirm($t('allowlist.removeConfirm'))) return
    await api.deleteAllowlist( id)
    allowlistEntries = allowlistEntries.filter(e => e.id !== id)
  }

  // Blocklist handlers
  async function loadBlocklist() {
    try {
      blocklistEntries = await api.getBlocklist()
      blocklistLoaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function addBlocklist() {
    addingBl = true; error = ''
    try {
      const e = await api.addBlocklist(newBlPattern)
      blocklistEntries = [...blocklistEntries, e]
      showAddBlocklist = false; newBlPattern = ''
    } catch (e) { error = extractErrorMessage(e) }
    finally { addingBl = false }
  }

  async function removeBlocklist(id) {
    if (!confirm($t('blocklist.removeConfirm'))) return
    await api.deleteBlocklist( id)
    blocklistEntries = blocklistEntries.filter(e => e.id !== id)
  }

  // Reserved-namespace handlers
  async function loadReserved() {
    try {
      reservedEntries = await api.getReservedNamespaces()
      reservedLoaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function addReserved() {
    addingRsvd = true; error = ''
    try {
      const e = await api.addReservedNamespace(newRsvdEcosystem, newRsvdPattern)
      reservedEntries = [...reservedEntries, e]
      showAddReserved = false; newRsvdPattern = ''
    } catch (e) { error = extractErrorMessage(e) }
    finally { addingRsvd = false }
  }

  async function removeReserved(id) {
    if (!confirm($t('reservedNamespaces.removeConfirm'))) return
    await api.deleteReservedNamespace(id)
    reservedEntries = reservedEntries.filter(e => e.id !== id)
  }

  // Install-script allowlist handlers
  async function loadInstallScriptAllowlist() {
    try {
      installScriptAllowlistEntries = await api.getInstallScriptAllowlist()
      installScriptAllowlistLoaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function addInstallScriptAllowlist() {
    addingIsa = true; error = ''
    try {
      const e = await api.addInstallScriptAllowlist(newIsaEcosystem, newIsaName, newIsaVersionPattern)
      installScriptAllowlistEntries = [...installScriptAllowlistEntries, e]
      showAddInstallScriptAllowlist = false; newIsaName = ''; newIsaVersionPattern = ''
    } catch (e) { error = extractErrorMessage(e) }
    finally { addingIsa = false }
  }

  async function removeInstallScriptAllowlist(id) {
    if (!confirm($t('installScriptAllowlist.removeConfirm'))) return
    await api.deleteInstallScriptAllowlist(id)
    installScriptAllowlistEntries = installScriptAllowlistEntries.filter(e => e.id !== id)
  }

  // Service-tokens tab is admin-only — service tokens are an org-level resource that
  // only admins/owners can mint (controller enforces tenant:configure). Filtering here
  // is cosmetic; the backend is the authority.
  $: viewerRole = $user?.role ?? ''
  $: viewerIsAdmin = viewerRole === 'admin' || viewerRole === 'owner'
  // Instance + /metrics tabs surface only for a single-mode owner. The backend gates
  // /api/v1/instance/* on tenant:admin (owner-only) and 404s those routes in multi-tenant
  // deployments, where instance config is a control-plane concern handled by the system_admin
  // SPA. Bootstrap reports mode as 'single' or 'multi' (header collapses to multi, bound to
  // single), so gating on 'single' keeps the tenant from seeing tabs whose forms would error.
  $: showInstanceTabs = viewerRole === 'owner' && ($bootstrapInfo?.mode ?? 'single') === 'single'

  $: tabKeys = [
    { key: 'general',        label: 'settings.tabs.general' },
    { key: 'authentication', label: 'settings.tabs.authentication' },
    { key: 'upload-limits',  label: 'settings.tabs.uploadLimits' },
    { key: 'retention',      label: 'settings.tabs.retention' },
    { key: 'proxy',          label: 'settings.tabs.proxy' },
    { key: 'licenses',       label: 'settings.tabs.licenses' },
    { key: 'claims',         label: 'settings.tabs.claims' },
    ...(viewerIsAdmin ? [
      { key: 'service-tokens', label: 'settings.tabs.serviceTokens' },
      { key: 'banners',        label: 'settings.tabs.banners' },
    ] : []),
    ...(showInstanceTabs ? [
      { key: 'instance', label: 'settings.tabs.instance' },
      { key: 'metrics',  label: 'settings.tabs.metrics' },
    ] : []),
  ]

  let banners = [], bannersLoaded = false, bannerError = ''
  let newBanner = { severity: 'info', body: '', linkUrl: '', linkLabel: '', targetRole: 'all', startsAt: '', endsAt: '', enabled: true }
  let bannerSaving = false, bannerSuccess = ''

  async function loadBanners() {
    if (bannersLoaded) return
    try {
      banners = await api.listBanners()
      bannersLoaded = true
    } catch (e) { bannerError = extractErrorMessage(e) }
  }

  async function createBanner() {
    bannerSaving = true
    bannerError = ''
    bannerSuccess = ''
    try {
      const payload = {
        severity: newBanner.severity,
        body: newBanner.body,
        linkUrl: newBanner.linkUrl || null,
        linkLabel: newBanner.linkLabel || null,
        targetRole: newBanner.targetRole,
        startsAt: newBanner.startsAt,
        endsAt: newBanner.endsAt,
        enabled: newBanner.enabled,
      }
      const created = await api.createBanner(payload)
      banners = [created, ...banners]
      newBanner = { severity: 'info', body: '', linkUrl: '', linkLabel: '', targetRole: 'all', startsAt: '', endsAt: '', enabled: true }
      bannerSuccess = 'Banner created.'
    } catch (e) { bannerError = extractErrorMessage(e) }
    finally { bannerSaving = false }
  }

  async function deleteBanner(id) {
    try {
      await api.deleteBanner(id)
      banners = banners.filter(b => b.id !== id)
    } catch (e) { bannerError = extractErrorMessage(e) }
  }

</script>

<div class="page">
  <div class="page-header"><h1 class="page-title">{$t('settings.title')}</h1></div>

  {#if loading}<span class="spinner"></span>
  {:else}
    <div class="tabs">
      {#each tabKeys as tk (tk.key)}
        <button class="tab" class:active={tab===tk.key} data-testid={`tab-${tk.key}`} on:click={() => switchTab(tk.key)}>
          {$t(tk.label)}
        </button>
      {/each}
    </div>

    <ErrorBanner message={error} />
    {#if success}<div class="text-success mb-3">{success}</div>{/if}

    {#if tab === 'general'}
      <SettingsGeneral {settings} {saving} onSave={saveSettings} />

    {:else if tab === 'authentication'}
      <SettingsAuth />

    {:else if tab === 'upload-limits'}
      <SettingsUpload {settings} {instanceMax} {saving} onSave={saveSettings} />

    {:else if tab === 'retention'}
      <SettingsRetention {retention} {saving} onSave={saveRetention} />

    {:else if tab === 'proxy'}
      <SettingsProxy
        {proxySettings}
        airGapped={settings.airGapped}
        bind:allowlistMode={settings.allowlistMode}
        {allowlistEntries} {allowlistLoaded}
        {blocklistEntries} {blocklistLoaded}
        onAddAllowlist={() => showAddAllowlist = true}
        onRemoveAllowlist={removeAllowlist}
        onAddBlocklist={() => showAddBlocklist = true}
        onRemoveBlocklist={removeBlocklist}
        {reservedEntries} {reservedLoaded}
        onAddReserved={() => showAddReserved = true}
        onRemoveReserved={removeReserved}
        {installScriptAllowlistEntries} {installScriptAllowlistLoaded}
        onAddInstallScriptAllowlist={() => showAddInstallScriptAllowlist = true}
        onRemoveInstallScriptAllowlist={removeInstallScriptAllowlist}
        {saving}
        onSave={saveProxySettings} />

    {:else if tab === 'licenses'}
      <p class="tab-intro">{$t('settings.licenses.intro')}</p>

      {#if licenseMode === 'block' && licenseAllowlistEmpty}
        <div class="warning-box" role="alert">
          {$t('settings.licenses.blockEmptyWarn')}
        </div>
      {/if}

      <h3 class="section-h">{$t('settings.licenses.mode.title')}</h3>
      <table class="list-table mode-table">
        <colgroup><col><col class="col-mode-radio"></colgroup>
        <tbody>
          {#each ['off', 'warn', 'block'] as m (m)}
            <tr class:active={licenseMode === m}>
              <td>
                <label for={`license-mode-${m}`} class="mode-label">{$t(`settings.licenses.mode.${m}.label`)}</label>
                <div class="mode-hint">{$t(`settings.licenses.mode.${m}.hint`)}</div>
              </td>
              <td class="text-center">
                <input id={`license-mode-${m}`} type="radio" name="license-mode" value={m}
                       checked={licenseMode === m}
                       disabled={savingLicenseMode}
                       on:change={() => saveLicenseMode(m)} />
              </td>
            </tr>
          {/each}
        </tbody>
      </table>

      <div class="page-header list-header mt-4">
        <h3 class="section-h">{$t('settings.licenses.review.title')}</h3>
        <label class="checkbox-inline">
          <input type="checkbox" checked={licenseReviewIncludeDeprecated}
                 on:change={toggleReviewIncludeDeprecated} />
          {$t('settings.licenses.review.includeDeprecated')}
        </label>
      </div>
      <p class="section-hint">{$t('settings.licenses.review.intro')}</p>
      <table class="list-table">
        <colgroup>
          <col><!-- spdx -->
          <col class="col-narrow"><!-- packages -->
          <col class="col-added"><!-- first seen -->
          <col class="col-narrow"><!-- flags -->
          <col class="col-review-actions"><!-- actions -->
        </colgroup>
        <thead><tr>
          <th>{$t('settings.licenses.columns.spdx')}</th>
          <th>{$t('settings.licenses.review.columns.packages')}</th>
          <th>{$t('settings.licenses.review.columns.firstSeen')}</th>
          <th>{$t('settings.licenses.review.columns.flags')}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each licenseReviewEntries as r (r.licenseSpdx)}
            <tr>
              <td class="t-mono">{r.licenseSpdx}</td>
              <td class="text-center">{r.packageCount}</td>
              <td class="text-muted">{$formatDateShort(r.firstSeen)}</td>
              <td>
                {#if r.isCompound}<span class="badge warn" title={$t('settings.licenses.review.compoundTooltip')}>{$t('settings.licenses.review.compound')}</span>{/if}
                {#if r.isDeprecated}<span class="badge danger">{$t('settings.licenses.review.deprecated')}</span>{/if}
              </td>
              <td class="t-actions">
                <button class="primary btn-sm"
                        disabled={r.isCompound || !!licenseReviewBusy[r.licenseSpdx]}
                        title={r.isCompound ? $t('settings.licenses.review.compoundTooltip') : ''}
                        on:click={() => approveReview(r.licenseSpdx)}>
                  {$t('settings.licenses.review.approve')}
                </button>
                <button class="danger btn-sm"
                        disabled={r.isCompound || !!licenseReviewBusy[r.licenseSpdx]}
                        title={r.isCompound ? $t('settings.licenses.review.compoundTooltip') : ''}
                        on:click={() => blockReview(r.licenseSpdx)}>
                  {$t('settings.licenses.review.block')}
                </button>
              </td>
            </tr>
          {/each}
          {#if licenseReviewLoaded && licenseReviewEntries.length === 0}
            <tr><td colspan="5" class="text-center text-muted">{$t('settings.licenses.review.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

      <div class="page-header list-header mt-4">
        <h3 class="section-h">{$t('settings.licenses.allow.title')}</h3>
        <button class="primary" on:click={() => showAddLicenseAllow = true}>{$t('settings.licenses.allow.addEntry')}</button>
      </div>
      <table class="list-table">
        <colgroup><col><col class="col-added"><col class="col-actions"></colgroup>
        <thead><tr>
          <th>{$t('settings.licenses.columns.spdx')}</th>
          <th>{$t('settings.licenses.columns.added')}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each licenseAllowEntries as e (e.id)}
            <tr>
              <td class="t-mono">{e.licenseSpdx}</td>
              <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
              <td><button class="danger btn-sm" on:click={() => removeLicenseAllow(e.licenseSpdx)}>{$t('common.actions.remove')}</button></td>
            </tr>
          {/each}
          {#if licenseAllowEntries.length === 0}
            <tr><td colspan="3" class="text-center text-muted">{$t('settings.licenses.allow.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

      <div class="page-header list-header mt-4">
        <h3 class="section-h">{$t('settings.licenses.block.title')}</h3>
        <button class="primary" on:click={() => showAddLicenseBlock = true}>{$t('settings.licenses.block.addEntry')}</button>
      </div>
      <table class="list-table">
        <colgroup><col><col class="col-added"><col class="col-actions"></colgroup>
        <thead><tr>
          <th>{$t('settings.licenses.columns.spdx')}</th>
          <th>{$t('settings.licenses.columns.added')}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each licenseBlockEntries as e (e.id)}
            <tr>
              <td class="t-mono">{e.licenseSpdx}</td>
              <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
              <td><button class="danger btn-sm" on:click={() => removeLicenseBlock(e.licenseSpdx)}>{$t('common.actions.remove')}</button></td>
            </tr>
          {/each}
          {#if licenseBlockEntries.length === 0}
            <tr><td colspan="3" class="text-center text-muted">{$t('settings.licenses.block.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

    {:else if tab === 'claims'}
      <Claims />

    {:else if tab === 'banners' && viewerIsAdmin}
      {#if bannerError}<p class="banner-tab-error">{bannerError}</p>{/if}
      {#if bannerSuccess}<p class="banner-tab-success">{bannerSuccess}</p>{/if}

      <section class="banner-create-form">
        <div class="form-grid">
          <div class="form-row">
            <label for="bn-severity">{$t('settings.banners.severity')}</label>
            <select id="bn-severity" bind:value={newBanner.severity}>
              <option value="info">info</option>
              <option value="warn">warn</option>
              <option value="alert">alert</option>
            </select>
          </div>
          <div class="form-row">
            <label for="bn-target">{$t('settings.banners.targetRole')}</label>
            <select id="bn-target" bind:value={newBanner.targetRole}>
              <option value="all">all</option>
              <option value="member">member</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
              <option value="auditor">auditor</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <label for="bn-body">{$t('settings.banners.body')}</label>
          <textarea id="bn-body" bind:value={newBanner.body} rows="3" maxlength="2000"></textarea>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label for="bn-starts">{$t('settings.banners.startsAt')}</label>
            <input id="bn-starts" type="datetime-local" bind:value={newBanner.startsAt} />
          </div>
          <div class="form-row">
            <label for="bn-ends">{$t('settings.banners.endsAt')}</label>
            <input id="bn-ends" type="datetime-local" bind:value={newBanner.endsAt} />
          </div>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label for="bn-link-url">{$t('settings.banners.linkUrl')}</label>
            <input id="bn-link-url" type="url" bind:value={newBanner.linkUrl} placeholder="https://..." />
          </div>
          <div class="form-row">
            <label for="bn-link-label">{$t('settings.banners.linkLabel')}</label>
            <input id="bn-link-label" type="text" bind:value={newBanner.linkLabel} maxlength="200" />
          </div>
        </div>
        <div class="form-row checkbox-row">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={newBanner.enabled} />
            {$t('settings.banners.enabled')}
          </label>
        </div>
        <button on:click={createBanner} disabled={bannerSaving}>{$t('settings.banners.create')}</button>
      </section>

      <section class="banner-list">
        {#if !bannersLoaded}
          <span class="spinner"></span>
        {:else if banners.length === 0}
          <p class="empty-state">{$t('settings.banners.empty')}</p>
        {:else}
          <table class="banner-table">
            <thead>
              <tr>
                <th>{$t('settings.banners.severity')}</th>
                <th>{$t('settings.banners.body')}</th>
                <th>{$t('settings.banners.targetRole')}</th>
                <th>{$t('settings.banners.window')}</th>
                <th>{$t('settings.banners.enabled')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each banners as b (b.id)}
                <tr>
                  <td><span class="badge badge-{b.severity}">{b.severity}</span></td>
                  <td class="banner-body-cell">{b.body}</td>
                  <td>{b.targetRole}</td>
                  <td class="banner-window-cell">{b.startsAt} &ndash; {b.endsAt}</td>
                  <td>{b.enabled ? $t('settings.banners.yes') : $t('settings.banners.no')}</td>
                  <td>
                    <div class="row-actions">
                      <button class="danger" on:click={() => deleteBanner(b.id)}>{$t('common.actions.delete')}</button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>

    {:else if tab === 'service-tokens' && viewerIsAdmin}
      <SettingsServiceTokens />

    {:else if tab === 'instance' && showInstanceTabs}
      <p class="tab-intro">{$t('settings.instance.intro')}</p>
      <SettingsInstance getSettings={api.getInstanceSettings} updateSettings={api.updateInstanceSettings} />

    {:else if tab === 'metrics' && showInstanceTabs}
      <p class="tab-intro">{$t('settings.metrics.intro')}</p>
      <SettingsMetrics getAccess={api.getMetricsAccess} updateAccess={api.updateMetricsAccess} />
    {/if}
  {/if}
</div>

<style>
  /* Supply-chain warning surface used when allow_version_overwrite is on. Same shape as the
     warning-card on Claims.svelte / Import.svelte; consistent across all three places. */
  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
    color: var(--text);
    max-width: 540px;
  }

  .list-header { margin-bottom: 12px; }
  .list-table .col-added   { width: 110px; }
  .list-table .col-actions { width: 90px; }
  .list-table .col-review-actions { width: 160px; }
  .t-actions { white-space: nowrap; }

  /* Licenses tab — mode picker as a 2-col table: label+hint on the left, radio on the right.
     Matches the visual rhythm of the allow/block tables below. */
  .tab-intro {
    color: var(--text2);
    font-size: 13px;
    margin: 0 0 16px;
    max-width: 640px;
  }
  .mode-table { margin-bottom: 24px; }
  .mode-table .col-mode-radio { width: 60px; }
  .mode-table tr.active .mode-label { color: var(--accent); }
  .mode-table .mode-label { font-weight: 500; font-size: 13px; cursor: pointer; }
  .mode-table .mode-hint  { color: var(--text2); font-size: 12px; margin-top: 2px; }
  .mode-table input[type="radio"] { cursor: pointer; }

  /* Banner create form — two-up rows for the paired fields, full-width for the message. */
  .banner-create-form { max-width: 640px; margin-bottom: 24px; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 16px; }
  .checkbox-row { margin-bottom: 12px; }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text2);
    cursor: pointer;
  }
  .checkbox-label input[type="checkbox"] {
    width: auto;
    min-height: 0;
    margin: 0;
    flex-shrink: 0;
  }
</style>

{#if showAddAllowlist}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('allowlist.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label>{$t('allowlist.modal.purlPattern')}</label>
        <input bind:value={newAlPattern} placeholder={$t('allowlist.modal.purlPatternPlaceholder')} />
        <div class="form-hint">{$t('allowlist.modal.purlPatternHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddAllowlist = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={addAllowlist} disabled={addingAl}>{addingAl ? $t('common.actions.adding') : $t('common.actions.add')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAddBlocklist}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('blocklist.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label>{$t('blocklist.modal.pattern')}</label>
        <input bind:value={newBlPattern} placeholder={$t('blocklist.modal.patternPlaceholder')} />
        <div class="form-hint">{$t('blocklist.modal.patternHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddBlocklist = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={addBlocklist} disabled={addingBl}>{addingBl ? $t('common.actions.adding') : $t('common.actions.add')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAddReserved}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('reservedNamespaces.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label for="rsvd-ecosystem">{$t('reservedNamespaces.modal.ecosystem')}</label>
        <select id="rsvd-ecosystem" bind:value={newRsvdEcosystem}>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="nuget">NuGet</option>
          <option value="maven">Maven</option>
          <option value="cargo">Cargo</option>
          <option value="golang">Go</option>
        </select>
      </div>
      <div class="form-row">
        <label for="rsvd-pattern">{$t('reservedNamespaces.modal.pattern')}</label>
        <input id="rsvd-pattern" bind:value={newRsvdPattern} placeholder={$t('reservedNamespaces.modal.patternPlaceholder')} />
        <div class="form-hint">{$t('reservedNamespaces.modal.patternHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddReserved = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={addReserved} disabled={addingRsvd}>{addingRsvd ? $t('common.actions.adding') : $t('common.actions.add')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAddInstallScriptAllowlist}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('installScriptAllowlist.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label for="isa-ecosystem">{$t('installScriptAllowlist.modal.ecosystem')}</label>
        <select id="isa-ecosystem" bind:value={newIsaEcosystem}>
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="nuget">NuGet</option>
          <option value="maven">Maven</option>
          <option value="cargo">Cargo</option>
          <option value="golang">Go</option>
          <option value="rpm">RPM</option>
          <option value="oci">OCI</option>
        </select>
      </div>
      <div class="form-row">
        <label for="isa-name">{$t('installScriptAllowlist.modal.name')}</label>
        <input id="isa-name" bind:value={newIsaName} placeholder={$t('installScriptAllowlist.modal.namePlaceholder')} />
        <div class="form-hint">{$t('installScriptAllowlist.modal.nameHint')}</div>
      </div>
      <div class="form-row">
        <label for="isa-version">{$t('installScriptAllowlist.modal.versionPattern')}</label>
        <input id="isa-version" bind:value={newIsaVersionPattern} placeholder={$t('installScriptAllowlist.modal.versionPatternPlaceholder')} />
        <div class="form-hint">{$t('installScriptAllowlist.modal.versionPatternHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddInstallScriptAllowlist = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={addInstallScriptAllowlist} disabled={addingIsa || !newIsaName.trim()}>{addingIsa ? $t('common.actions.adding') : $t('common.actions.add')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAddLicenseAllow}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('settings.licenses.modal.addAllowTitle')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label>{$t('settings.licenses.modal.spdxLabel')}</label>
        <SpdxPicker exclude={licensePolicyIdentifiers}
                    placeholder={$t('settings.licenses.modal.spdxPlaceholder')}
                    on:select={e => addLicenseAllow(e.detail.identifier)} />
        <div class="form-hint">{$t('settings.licenses.modal.spdxHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddLicenseAllow = false}>{$t('common.actions.cancel')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAddLicenseBlock}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('settings.licenses.modal.addBlockTitle')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label>{$t('settings.licenses.modal.spdxLabel')}</label>
        <SpdxPicker exclude={licensePolicyIdentifiers}
                    placeholder={$t('settings.licenses.modal.spdxPlaceholder')}
                    on:select={e => addLicenseBlock(e.detail.identifier)} />
        <div class="form-hint">{$t('settings.licenses.modal.spdxHint')}</div>
      </div>
      <div class="modal-actions">
        <button on:click={() => showAddLicenseBlock = false}>{$t('common.actions.cancel')}</button>
      </div>
    </div>
  </div>
{/if}
