<script>
  import { onMount, onDestroy } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { formatDateShort } from '../lib/format.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import Claims from './Claims.svelte'
  import SpdxPicker from '../lib/SpdxPicker.svelte'

  let tab = 'general'
  let settings = null, retention = null, instanceMax = null, proxySettings = null
  let loading = true, saving = false, error = '', success = ''

  // Allowlist state
  let allowlistEntries = [], allowlistLoaded = false
  let showAddAllowlist = false, newAlEco = 'pypi', newAlPattern = '', addingAl = false

  // Blocklist state
  let blocklistEntries = [], blocklistLoaded = false
  let showAddBlocklist = false, newBlEco = 'pypi', newBlPattern = '', addingBl = false

  // License policy state (#21). Single fetch returns mode + both lists.
  let licensePolicyLoaded = false
  let licenseMode = 'off'
  let licenseAllowEntries = [], licenseBlockEntries = []
  let showAddLicenseAllow = false, newLicenseAllowSpdx = ''
  let showAddLicenseBlock = false, newLicenseBlockSpdx = ''
  let savingLicenseMode = false
  // Review queue (#21 follow-on): SPDX IDs seen during ingestion not yet on either list.
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

  // ── Authentication tab state ───────────────────────────────────────────────
  // Loaded lazily on tab switch. Populated from GET /auth-config; saved via PUT /auth-config
  // and POST /auth-config/metadata. Test SSO is a top-level navigation, not an XHR.
  let authConfig = null, authConfigLoaded = false
  let metadataUploading = false, authSaving = false
  let authError = '', authSuccess = ''

  onMount(async () => {
    window.addEventListener('message', onSamlTestMessage)
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
      proxySettings = { ...ps, max_osv_score_tolerance: Number(ps.max_osv_score_tolerance ?? 10).toFixed(1) }
    } catch (e) { error = e.message }
    finally { loading = false }
  })

  async function switchTab(key) {
    tab = key
    error = ''; success = ''
    if (key === 'allowlist' && !allowlistLoaded) await loadAllowlist()
    if (key === 'blocklist' && !blocklistLoaded) await loadBlocklist()
    if (key === 'authentication' && !authConfigLoaded) await loadAuthConfig()
    if (key === 'licenses' && !licensePolicyLoaded) await loadLicensePolicy()
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
    } catch (e) { error = e.message }
  }

  async function loadLicenseReview() {
    try {
      licenseReviewEntries = await api.getLicenseReview(licenseReviewIncludeDeprecated)
      licenseReviewLoaded = true
    } catch (e) { error = e.message }
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
      error = e.message
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
    } catch (e) { error = e.message }
  }

  async function removeLicenseAllow(spdx) {
    if (!confirm($t('settings.licenses.removeConfirm'))) return
    try {
      await api.removeLicenseAllow(spdx)
      licenseAllowEntries = licenseAllowEntries.filter(e => e.licenseSpdx !== spdx)
      // A removed license may now reappear under review — refresh in the background.
      loadLicenseReview()
    } catch (e) { error = e.message }
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
    } catch (e) { error = e.message }
  }

  async function removeLicenseBlock(spdx) {
    if (!confirm($t('settings.licenses.removeConfirm'))) return
    try {
      await api.removeLicenseBlock(spdx)
      licenseBlockEntries = licenseBlockEntries.filter(e => e.licenseSpdx !== spdx)
      loadLicenseReview()
    } catch (e) { error = e.message }
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

  async function loadAuthConfig() {
    authError = ''; authSuccess = ''
    try {
      authConfig = await api.getAuthConfig()
      authConfigLoaded = true
    } catch (e) { authError = e.message }
  }

  async function saveAuthConfig() {
    authSaving = true; authError = ''; authSuccess = ''
    try {
      await api.putAuthConfig({
        enabled: !!authConfig.enabled,
        formsLoginEnabled: !!authConfig.formsLoginEnabled,
        spEntityId: authConfig.spEntityId || null,
        nameIdFormat: authConfig.nameIdFormat,
        emailAttribute: authConfig.emailAttribute || null,
        buttonLabel: authConfig.buttonLabel || null,
      })
      authSuccess = $t('settings.saved')
      await loadAuthConfig()
    } catch (e) { authError = e.message }
    finally { authSaving = false }
  }

  async function resetAuthConfig() {
    if (!confirm($t('settings.auth.resetConfirm'))) return
    authError = ''; authSuccess = ''
    try {
      await api.deleteAuthConfig()
      authSuccess = $t('settings.auth.resetSuccess')
      await loadAuthConfig()
    } catch (e) { authError = e.message }
  }

  async function uploadMetadata(ev) {
    const file = ev.target.files?.[0]
    if (!file) return
    metadataUploading = true; authError = ''; authSuccess = ''
    try {
      const xml = await file.text()
      const parsed = await api.uploadSamlMetadata(xml)
      authSuccess = $t('settings.auth.metadataUploaded')
      authConfig = { ...authConfig,
        idpEntityId: parsed.idpEntityId,
        idpSsoUrl: parsed.idpSsoUrl,
        idpSigningCertThumbprint: parsed.idpSigningCertThumbprint,
      }
    } catch (e) { authError = e.message }
    finally { metadataUploading = false; ev.target.value = '' }
  }

  function testSso() {
    // Open the SAML round-trip in a popup so the settings page state is preserved. The popup
    // navigates to the IdP, returns to /saml/acs, and lands on /saml-test-result, which posts
    // the result back to this window via postMessage and closes itself.
    authError = ''; authSuccess = ''
    const w = 560, h = 720
    const left = window.screenX + (window.outerWidth - w) / 2
    const top  = window.screenY + (window.outerHeight - h) / 2
    const popup = window.open(
      '/saml/login?test=1',
      'saml-test',
      `width=${w},height=${h},left=${left},top=${top},popup=true`)
    if (!popup) authError = $t('settings.auth.testPopupBlocked')
  }

  function onSamlTestMessage(ev) {
    if (ev.origin !== window.location.origin) return
    if (ev.data?.type !== 'saml-test-result') return
    if (ev.data.error) {
      authSuccess = ''
      authError = $t('settings.auth.testFailed', {
        values: { reason: ev.data.detail || ev.data.error },
      })
    } else {
      authError = ''
      authSuccess = $t('settings.auth.testSucceeded', {
        values: { email: ev.data.email || '—' },
      })
      // Re-fetch so lastTestAt + lastTestEmail are reflected immediately and the
      // formsLoginEnabled toggle's lockout guard releases without a manual refresh.
      loadAuthConfig()
    }
  }

  onDestroy(() => window.removeEventListener('message', onSamlTestMessage))

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text) } catch { /* clipboard unavailable */ }
  }

  function recentTestOk(at) {
    if (!at) return false
    const ts = new Date(at).getTime()
    if (Number.isNaN(ts)) return false
    return (Date.now() - ts) < 10 * 60 * 1000
  }

  async function saveSettings() {
    saving = true; error = ''; success = ''
    try {
      await api.updateOrgSettings( settings)
      success = $t('settings.saved')
    } catch (e) { error = e.message }
    finally { saving = false }
  }

  async function saveProxySettings() {
    saving = true; error = ''; success = ''
    try {
      await api.updateProxySettings( {
        proxyPassthroughEnabled: proxySettings.proxy_passthrough_enabled,
        maxOsvScoreTolerance:    Number(proxySettings.max_osv_score_tolerance),
      })
      success = $t('settings.saved')
    } catch (e) { error = e.message }
    finally { saving = false }
  }

  async function saveRetention() {
    saving = true; error = ''; success = ''
    try {
      await api.updateRetention( retention)
      success = $t('settings.retentionSaved')
    } catch (e) { error = e.message }
    finally { saving = false }
  }

  function exceedsInstance(val) {
    if (!instanceMax || !val) return false
    return parseInt(val) > instanceMax
  }

  // Allowlist handlers
  async function loadAllowlist() {
    try {
      allowlistEntries = await api.getAllowlist()
      allowlistLoaded = true
    } catch (e) { error = e.message }
  }

  async function addAllowlist() {
    addingAl = true; error = ''
    try {
      const e = await api.addAllowlist( newAlEco, newAlPattern)
      allowlistEntries = [...allowlistEntries, e]
      showAddAllowlist = false; newAlPattern = ''
    } catch (e) { error = e.message }
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
    } catch (e) { error = e.message }
  }

  async function addBlocklist() {
    addingBl = true; error = ''
    try {
      const e = await api.addBlocklist( newBlEco, newBlPattern)
      blocklistEntries = [...blocklistEntries, e]
      showAddBlocklist = false; newBlPattern = ''
    } catch (e) { error = e.message }
    finally { addingBl = false }
  }

  async function removeBlocklist(id) {
    if (!confirm($t('blocklist.removeConfirm'))) return
    await api.deleteBlocklist( id)
    blocklistEntries = blocklistEntries.filter(e => e.id !== id)
  }

  let alSortCol = 'ecosystem', alSortDir = 'asc'
  $: sortedAllowlist = [...allowlistEntries].sort((a, b) => {
    let av = a[alSortCol] ?? '', bv = b[alSortCol] ?? ''
    if (av < bv) return alSortDir === 'asc' ? -1 : 1
    if (av > bv) return alSortDir === 'asc' ? 1 : -1
    return 0
  })
  function toggleAlSort(col) {
    if (alSortCol === col) alSortDir = alSortDir === 'asc' ? 'desc' : 'asc'
    else { alSortCol = col; alSortDir = 'asc' }
  }

  let blSortCol = 'ecosystem', blSortDir = 'asc'
  $: sortedBlocklist = [...blocklistEntries].sort((a, b) => {
    let av = a[blSortCol] ?? '', bv = b[blSortCol] ?? ''
    if (av < bv) return blSortDir === 'asc' ? -1 : 1
    if (av > bv) return blSortDir === 'asc' ? 1 : -1
    return 0
  })
  function toggleBlSort(col) {
    if (blSortCol === col) blSortDir = blSortDir === 'asc' ? 'desc' : 'asc'
    else { blSortCol = col; blSortDir = 'asc' }
  }

  const tabKeys = [
    { key: 'general',        label: 'settings.tabs.general' },
    { key: 'authentication', label: 'settings.tabs.authentication' },
    { key: 'upload-limits',  label: 'settings.tabs.uploadLimits' },
    { key: 'retention',      label: 'settings.tabs.retention' },
    { key: 'proxy',          label: 'settings.tabs.proxy' },
    { key: 'allowlist',      label: 'settings.tabs.allowlist' },
    { key: 'blocklist',      label: 'settings.tabs.blocklist' },
    { key: 'licenses',       label: 'settings.tabs.licenses' },
    { key: 'claims',         label: 'settings.tabs.claims' },
  ]

  const uploadFields = [
    ['maxUploadBytes',    'settings.uploadLimits.allEcosystems'],
    ['maxUploadBytesPyPi', 'PyPI'],
    ['maxUploadBytesNpm',  'npm'],
    ['maxUploadBytesNuGet','NuGet'],
  ]
</script>

<div class="page">
  <div class="page-header"><h1 class="page-title">{$t('settings.title')}</h1></div>

  {#if loading}<span class="spinner"></span>
  {:else}
    <div class="tabs">
      {#each tabKeys as tk (tk.key)}
        <button class="tab" class:active={tab===tk.key} on:click={() => switchTab(tk.key)}>
          {$t(tk.label)}
        </button>
      {/each}
    </div>

    {#if error}<div class="page-error">{error}</div>{/if}
    {#if success}<div class="text-success mb-3">{success}</div>{/if}

    {#if tab === 'general'}
      <div class="card card-narrow">
        <div class="form-row form-row-inline">
          <label class="flex-1">{$t('settings.general.anonymousPull')}</label>
          <input type="checkbox" bind:checked={settings.anonymousPull} class="w-auto" />
        </div>
        <div class="form-row form-row-inline">
          <label class="flex-1">{$t('settings.general.allowlistMode')}</label>
          <input type="checkbox" bind:checked={settings.allowlistMode} class="w-auto" />
        </div>
        <div class="form-row form-row-inline">
          <label class="flex-1">{$t('settings.general.defaultLanguage')}</label>
          <select bind:value={settings.defaultLanguage} class="w-auto">
            <option value="en">English</option>
            <option value="fr">Français</option>
          </select>
        </div>
        <div class="form-hint nudge-up mb-3">{$t('settings.general.defaultLanguageHint')}</div>

        <div class="form-row form-row-inline">
          <label class="flex-1">{$t('settings.general.allowVersionOverwrite')}</label>
          <input type="checkbox" bind:checked={settings.allowVersionOverwrite} class="w-auto" />
        </div>
        {#if settings.allowVersionOverwrite}
          <div class="warning-box mb-3">{$t('settings.general.allowVersionOverwriteWarning')}</div>
        {:else}
          <div class="form-hint nudge-up mb-3">{$t('settings.general.allowVersionOverwriteHint')}</div>
        {/if}

        <button class="primary" on:click={saveSettings} disabled={saving}>{saving ? $t('common.actions.saving') : $t('common.actions.save')}</button>
      </div>

    {:else if tab === 'authentication'}
      {#if !authConfig}
        <span class="spinner"></span>
      {:else}
        {#if authError}<div class="error-msg">{authError}</div>{/if}
        {#if authSuccess}<div class="text-success mb-3">{authSuccess}</div>{/if}

        <div class="card card-wide">
          <h3 class="mt-0">{$t('settings.auth.methodsTitle')}</h3>
          <div class="form-row form-row-inline">
            <label class="flex-1">{$t('settings.auth.formsLogin')}</label>
            <input type="checkbox" bind:checked={authConfig.formsLoginEnabled} class="w-auto" />
          </div>
          <div class="form-row form-row-inline gap-10">
            <label class="flex-1">{$t('settings.auth.samlLogin')}</label>
            {#if !authConfig.idpEntityId}
              <span class="badge">{$t('settings.auth.stateNotConfigured')}</span>
            {:else if !authConfig.enabled}
              <span class="badge warning">{$t('settings.auth.stateConfiguredUnpublished')}</span>
            {:else}
              <span class="badge success">{$t('settings.auth.statePublished')}</span>
            {/if}
            <input type="checkbox" bind:checked={authConfig.enabled} class="w-auto" />
          </div>
          <div class="form-hint">{$t('settings.auth.samlLoginHint')}</div>
          {#if !authConfig.formsLoginEnabled && !recentTestOk(authConfig.lastTestAt)}
            <div class="form-hint text-danger">
              {$t('settings.auth.formsDisableGuard')}
            </div>
          {/if}
        </div>

        <div class="card card-wide mt-4">
            <h3 class="mt-0">{$t('settings.auth.spInfoTitle')}</h3>
            <p class="form-hint mb-3">{$t('settings.auth.spInfoHint')}</p>
            <table class="kv-table">
              <tbody>
                <tr>
                  <th>{$t('settings.auth.spInfoAcs')}</th>
                  <td><code>{authConfig.spInfo.acsUrl}</code>
                    <button class="link-btn" on:click={() => copyText(authConfig.spInfo.acsUrl)}>{$t('common.actions.copy')}</button>
                  </td>
                </tr>
                <tr>
                  <th>{$t('settings.auth.spInfoEntityId')}</th>
                  <td><code>{authConfig.spEntityId || authConfig.spInfo.defaultSpEntityId}</code>
                    <button class="link-btn" on:click={() => copyText(authConfig.spEntityId || authConfig.spInfo.defaultSpEntityId)}>{$t('common.actions.copy')}</button>
                  </td>
                </tr>
                <tr>
                  <th>{$t('settings.auth.spInfoMetadata')}</th>
                  <td><code>{authConfig.spInfo.metadataUrl}</code>
                    <button class="link-btn" on:click={() => copyText(authConfig.spInfo.metadataUrl)}>{$t('common.actions.copy')}</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="card card-wide mt-4">
            <h3 class="mt-0">{$t('settings.auth.idpMetadataTitle')}</h3>
            <p class="form-hint">{$t('settings.auth.idpMetadataHint')}</p>
            <input type="file" accept=".xml,application/xml,text/xml" on:change={uploadMetadata} disabled={metadataUploading} />
            {#if authConfig.idpEntityId}
              <table class="kv-table mt-3">
                <tbody>
                  <tr><th>{$t('settings.auth.idpEntityId')}</th><td><code>{authConfig.idpEntityId}</code></td></tr>
                  <tr><th>{$t('settings.auth.idpSsoUrl')}</th><td><code>{authConfig.idpSsoUrl}</code></td></tr>
                  <tr><th>{$t('settings.auth.idpCertThumbprint')}</th><td><code>{authConfig.idpSigningCertThumbprint || '—'}</code></td></tr>
                </tbody>
              </table>
              <div class="reset-row">
                <button class="danger" on:click={resetAuthConfig}>{$t('settings.auth.resetButton')}</button>
                <div class="form-hint reset-hint">{$t('settings.auth.resetHint')}</div>
              </div>
            {:else}
              <p class="form-hint mt-2">{$t('settings.auth.idpNotConfigured')}</p>
            {/if}
          </div>

          <div class="card card-wide mt-4">
            <h3 class="mt-0">{$t('settings.auth.connectionTitle')}</h3>
            <div class="form-row">
              <label>{$t('settings.auth.buttonLabel')}</label>
              <input type="text" bind:value={authConfig.buttonLabel} placeholder={$t('settings.auth.buttonLabelPlaceholder')} />
            </div>
            <div class="form-row">
              <label>{$t('settings.auth.emailAttribute')}</label>
              <input type="text" bind:value={authConfig.emailAttribute} placeholder={$t('settings.auth.emailAttributePlaceholder')} />
              <div class="form-hint">{$t('settings.auth.emailAttributeHint')}</div>
            </div>
            <div class="form-row">
              <label>{$t('settings.auth.nameIdFormat')}</label>
              <select bind:value={authConfig.nameIdFormat}>
                <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">emailAddress</option>
                <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">persistent</option>
                <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">transient</option>
                <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">unspecified</option>
              </select>
            </div>
            <div class="form-row">
              <label>{$t('settings.auth.spEntityIdOverride')}</label>
              <input type="text" bind:value={authConfig.spEntityId} placeholder={authConfig.spInfo.defaultSpEntityId} />
              <div class="form-hint">{$t('settings.auth.spEntityIdHint')}</div>
            </div>
          </div>

          <div class="card card-wide mt-4">
            <h3 class="mt-0">{$t('settings.auth.testTitle')}</h3>
            <p class="form-hint">{$t('settings.auth.testHint')}</p>
            <button class="primary" on:click={testSso} disabled={!authConfig.idpEntityId}>{$t('settings.auth.testButton')}</button>
            {#if authConfig.lastTestAt}
              <p class="form-hint test-last-run">
                {$t('settings.auth.testLastRun', { values: { when: authConfig.lastTestAt, email: authConfig.lastTestEmail || '—' } })}
                {#if recentTestOk(authConfig.lastTestAt)}
                  <span class="text-success">
                    <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-check"/></svg>
                    {$t('settings.auth.testRecentOk')}
                  </span>
                {/if}
              </p>
            {/if}
          </div>

        <div class="save-row">
          <button class="primary" on:click={saveAuthConfig} disabled={authSaving}>{authSaving ? $t('common.actions.saving') : $t('common.actions.save')}</button>
        </div>
      {/if}

    {:else if tab === 'upload-limits'}
      <div class="card card-narrow">
        {#if instanceMax}<p class="form-hint">{$t('settings.uploadLimits.instanceCeiling', { values: { mb: (instanceMax/1024/1024).toFixed(0) } })}</p>{/if}
        {#each uploadFields as [key, labelKey] (key)}
          <div class="form-row">
            <label>{labelKey.startsWith('settings.') ? $t(labelKey) : labelKey} (bytes)</label>
            <input type="number" bind:value={settings[key]} placeholder={$t('settings.uploadLimits.inheritPlaceholder')} min="0" />
            {#if exceedsInstance(settings[key])}<div class="form-hint text-danger">{$t('settings.uploadLimits.exceedsCeiling', { values: { bytes: instanceMax } })}</div>{/if}
          </div>
        {/each}
        <button class="primary" on:click={saveSettings}
          disabled={saving || exceedsInstance(settings.maxUploadBytes) || exceedsInstance(settings.maxUploadBytesPyPi) || exceedsInstance(settings.maxUploadBytesNpm) || exceedsInstance(settings.maxUploadBytesNuGet)}>
          {saving ? $t('common.actions.saving') : $t('common.actions.save')}
        </button>
      </div>

    {:else if tab === 'retention'}
      <div class="card card-narrow">
        <div class="form-row"><label>{$t('settings.retention.keepVersions')}</label><input type="number" bind:value={retention.keep_versions} placeholder={$t('settings.retention.unlimited')} min="1" /></div>
        <div class="form-row"><label>{$t('settings.retention.keepDays')}</label><input type="number" bind:value={retention.keep_days} placeholder={$t('settings.retention.unlimited')} min="1" /></div>
        <div class="form-row"><label>{$t('settings.retention.activityDays')}</label><input type="number" bind:value={retention.activity_retention_days} placeholder={$t('settings.retention.unlimited')} min="1" /></div>
        <button class="primary" on:click={saveRetention} disabled={saving}>{saving ? $t('common.actions.saving') : $t('common.actions.save')}</button>
      </div>

    {:else if tab === 'proxy'}
      <div class="card card-narrow">
        <div class="form-row form-row-inline">
          <label class="flex-1">{$t('settings.proxy.passthroughEnabled')}</label>
          <input type="checkbox" bind:checked={proxySettings.proxy_passthrough_enabled} class="w-auto" />
        </div>
        <div class="form-hint nudge-up mb-3">{$t('settings.proxy.passthroughHint')}</div>
        <div class="form-row">
          <label>{$t('settings.proxy.osvTolerance')}</label>
          <input
            type="text"
            inputmode="decimal"
            pattern="[0-9]+(\.[0-9]+)?"
            bind:value={proxySettings.max_osv_score_tolerance}
            on:blur={(e) => proxySettings.max_osv_score_tolerance = Number(e.currentTarget.value || 0).toFixed(1)}
          />
          <div class="form-hint">{$t('settings.proxy.osvToleranceHint')}</div>
        </div>
        <button class="primary" on:click={saveProxySettings} disabled={saving}>{saving ? $t('common.actions.saving') : $t('common.actions.save')}</button>
      </div>

    {:else if tab === 'allowlist'}
      <div class="page-header list-header">
        <span></span>
        <button class="primary" on:click={() => showAddAllowlist = true}>{$t('allowlist.addEntry')}</button>
      </div>
      <table class="list-table">
        <colgroup>
          <col class="col-eco"><!-- ecosystem badge -->
          <col><!-- purlPattern: flexible -->
          <col class="col-added"><!-- added date -->
          <col class="col-actions"><!-- actions -->
        </colgroup>
        <thead><tr>
          <th class="sortable" on:click={() => toggleAlSort('ecosystem')}>{$t('allowlist.columns.ecosystem')}{sortIndicator('ecosystem', alSortCol, alSortDir)}</th>
          <th class="sortable" on:click={() => toggleAlSort('purlPattern')}>{$t('allowlist.columns.purlPattern')}{sortIndicator('purlPattern', alSortCol, alSortDir)}</th>
          <th class="sortable" on:click={() => toggleAlSort('createdAt')}>{$t('allowlist.columns.added')}{sortIndicator('createdAt', alSortCol, alSortDir)}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each sortedAllowlist as e (e.id)}
            <tr>
              <td><span class="badge {e.ecosystem}">{e.ecosystem}</span></td>
              <td class="t-mono">{e.purlPattern}</td>
              <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
              <td><button class="danger btn-sm" on:click={() => removeAllowlist(e.id)}>{$t('common.actions.remove')}</button></td>
            </tr>
          {/each}
          {#if allowlistEntries.length === 0}
            <tr><td colspan="4" class="text-center text-muted">{$t('allowlist.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

    {:else if tab === 'blocklist'}
      <div class="page-header list-header">
        <span></span>
        <button class="primary" on:click={() => showAddBlocklist = true}>{$t('blocklist.addEntry')}</button>
      </div>
      <table class="list-table">
        <colgroup>
          <col class="col-eco"><!-- ecosystem badge -->
          <col><!-- pattern: flexible -->
          <col class="col-added"><!-- added date -->
          <col class="col-actions"><!-- actions -->
        </colgroup>
        <thead><tr>
          <th class="sortable" on:click={() => toggleBlSort('ecosystem')}>{$t('blocklist.columns.ecosystem')}{sortIndicator('ecosystem', blSortCol, blSortDir)}</th>
          <th class="sortable" on:click={() => toggleBlSort('pattern')}>{$t('blocklist.columns.pattern')}{sortIndicator('pattern', blSortCol, blSortDir)}</th>
          <th class="sortable" on:click={() => toggleBlSort('createdAt')}>{$t('blocklist.columns.added')}{sortIndicator('createdAt', blSortCol, blSortDir)}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {#each sortedBlocklist as e (e.id)}
            <tr>
              <td><span class="badge {e.ecosystem}">{e.ecosystem}</span></td>
              <td class="t-mono">{e.pattern}</td>
              <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
              <td><button class="danger btn-sm" on:click={() => removeBlocklist(e.id)}>{$t('common.actions.remove')}</button></td>
            </tr>
          {/each}
          {#if blocklistEntries.length === 0}
            <tr><td colspan="4" class="text-center text-muted">{$t('blocklist.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

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

  .kv-table { width: 100%; border-collapse: collapse; }
  .kv-table th, .kv-table td {
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    font-size: 13px;
  }
  .kv-table th { width: 180px; color: var(--text2); font-weight: 500; }
  .kv-table td code { font-family: var(--mono, monospace); word-break: break-all; }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    padding: 0 0 0 6px;
    font-size: 12px;
    cursor: pointer;
  }

  .card-narrow { max-width: 480px; }
  .card-wide   { max-width: 680px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  .form-row-inline.gap-10 { gap: 10px; }
  .nudge-up { margin-top: -8px; }
  .mt-0 { margin-top: 0; }
  .reset-row { margin-top: 12px; }
  .reset-hint { margin-top: 6px; }
  .test-last-run { margin-top: 10px; }
  .save-row { margin-top: 16px; display: flex; gap: 8px; }
  .list-header { margin-bottom: 12px; }
  .list-table .col-eco     { width: 90px; }
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
</style>

{#if showAddAllowlist}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('allowlist.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row">
        <label>{$t('allowlist.modal.ecosystem')}</label>
        <select bind:value={newAlEco} class="w-auto">
          <option value="pypi">PyPI</option><option value="npm">npm</option><option value="nuget">NuGet</option>
        </select>
      </div>
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
        <label>{$t('blocklist.modal.ecosystem')}</label>
        <select bind:value={newBlEco} class="w-auto">
          <option value="pypi">PyPI</option><option value="npm">npm</option><option value="nuget">NuGet</option>
        </select>
      </div>
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
