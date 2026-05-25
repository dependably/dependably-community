<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { submitForm, extractErrorMessage } from '../lib/form.js'
  import { user } from '../lib/store.js'
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

  let tab = 'general'
  let settings = null, retention = null, instanceMax = null, proxySettings = null
  let loading = true, saving = false, error = '', success = ''

  // Allowlist state
  let allowlistEntries = [], allowlistLoaded = false
  let showAddAllowlist = false, newAlPattern = '', addingAl = false

  // Blocklist state
  let blocklistEntries = [], blocklistLoaded = false
  let showAddBlocklist = false, newBlPattern = '', addingBl = false

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
      // so 48 lands as "2 Days" and 36 stays as "36 Hours". A null/0 wire value collapses
      // to an empty input — the form treats that as "policy off" on save.
      const ageHours = ps.min_release_age_hours
      const ageUnit = ageHours !== null && ageHours !== undefined && ageHours > 0 && ageHours % 24 === 0 ? 'days' : 'hours'
      const ageValue = ageHours === null || ageHours === undefined || ageHours === 0
        ? ''
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
    }
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
  // toggle lives in the same tab now (#87) but the value still rides on the /settings
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
    await submitForm(() => Promise.all([
      api.updateProxySettings({
        proxyPassthroughEnabled: proxySettings.proxy_passthrough_enabled,
        maxOsvScoreTolerance:    Number(proxySettings.max_osv_score_tolerance),
        minReleaseAgeHours,
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

  // Service-tokens tab is admin-only — service tokens are an org-level resource that
  // only admins/owners can mint (controller enforces tenant:configure). Filtering here
  // is cosmetic; the backend is the authority.
  $: viewerRole = $user?.role ?? ''
  $: viewerIsAdmin = viewerRole === 'admin' || viewerRole === 'owner'

  $: tabKeys = [
    { key: 'general',        label: 'settings.tabs.general' },
    { key: 'authentication', label: 'settings.tabs.authentication' },
    { key: 'upload-limits',  label: 'settings.tabs.uploadLimits' },
    { key: 'retention',      label: 'settings.tabs.retention' },
    { key: 'proxy',          label: 'settings.tabs.proxy' },
    { key: 'licenses',       label: 'settings.tabs.licenses' },
    { key: 'claims',         label: 'settings.tabs.claims' },
    ...(viewerIsAdmin ? [{ key: 'service-tokens', label: 'settings.tabs.serviceTokens' }] : []),
  ]

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
        bind:allowlistMode={settings.allowlistMode}
        {allowlistEntries} {allowlistLoaded}
        {blocklistEntries} {blocklistLoaded}
        onAddAllowlist={() => showAddAllowlist = true}
        onRemoveAllowlist={removeAllowlist}
        onAddBlocklist={() => showAddBlocklist = true}
        onRemoveBlocklist={removeBlocklist}
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

    {:else if tab === 'service-tokens' && viewerIsAdmin}
      <SettingsServiceTokens />
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
