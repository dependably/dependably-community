<!--
  Signature trust anchors — per-org, per-ecosystem public key material. Each row is one
  anchor; the verifier accepts any of the configured anchors for the ecosystem. Self-contained:
  loads on mount, no parent state threading required.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { formatDateShort } from '../format.js'
  import ErrorBanner from '../ErrorBanner.svelte'

  const ECOSYSTEMS = [
    { key: 'rpm',   label: 'RPM' },
    { key: 'npm',   label: 'npm' },
    { key: 'nuget', label: 'NuGet' },
    { key: 'pypi',  label: 'PyPI' },
    { key: 'maven', label: 'Maven' },
  ]

  const ANCHOR_KINDS = [
    { key: 'pgp',              label: 'PGP public key' },
    { key: 'spki',             label: 'SPKI (base64 DER)' },
    { key: 'x509',             label: 'X.509 certificate (PEM)' },
    { key: 'sigstore_root',    label: 'Sigstore root' },
    { key: 'trusted_publisher',label: 'Trusted publisher' },
    { key: 'rekor_key',        label: 'Rekor public key' },
  ]

  /** @type {any[]} */
  let entries = []
  let loaded = false
  let error = ''

  let showAdd = false
  let addEco = 'rpm'
  let addKind = 'pgp'
  let addMaterial = ''
  let addLabel = ''
  let addKeyId = ''

  // PyPI trusted_publisher structured fields
  let tpIssuer = ''
  let tpSubject = ''
  let tpMatch = 'prefix'
  let tpMatchUserTouched = false

  let adding = false

  onMount(load)

  async function load() {
    try {
      entries = await api.getTrustAnchors()
      loaded = true
    } catch (e) { error = extract(e) }
  }

  function openAdd() {
    addEco = 'rpm'
    addKind = 'pgp'
    addMaterial = ''
    addLabel = ''
    addKeyId = ''
    tpIssuer = ''
    tpSubject = ''
    tpMatch = 'prefix'
    tpMatchUserTouched = false
    error = ''
    showAdd = true
  }

  // Returns true when the (ecosystem, anchorKind) pair requires a caller-supplied keyId.
  // For npm/spki the keyId is not derivable from the key bytes alone (unlike PGP fingerprints
  // or X.509 thumbprints), so the user must supply it (for example, SHA256:jl3bwswu80Pj…).
  function needsCallerKeyId(eco, kind) {
    return eco === 'npm' && kind === 'spki'
  }

  // Returns true when the (ecosystem, anchorKind) pair uses the PyPI trusted_publisher
  // structured form instead of a raw material textarea.
  function isPyPiTrustedPublisher(eco, kind) {
    return eco === 'pypi' && kind === 'trusted_publisher'
  }

  // Smart match-mode default: Exact when the subject looks like a complete workflow identity
  // (contains a .yml or .yaml extension immediately before an @ref), Prefix otherwise.
  // Mirrors TrustedPublisher.InferMatchMode on the backend.
  function inferMatchMode(subject) {
    const s = subject || ''
    return (s.includes('.yml@') || s.includes('.yaml@')) ? 'exact' : 'prefix'
  }

  // Recompute the suggested match mode as the subject changes, but only when the user has
  // not yet explicitly overridden it.
  $: if (!tpMatchUserTouched) {
    tpMatch = inferMatchMode(tpSubject)
  }

  function onMatchChange(e) {
    tpMatch = e.target.value
    tpMatchUserTouched = true
  }

  // Build the material JSON for a PyPI trusted_publisher from the structured fields.
  function buildTpMaterial() {
    return JSON.stringify({ issuer: tpIssuer.trim(), subject: tpSubject.trim(), match: tpMatch })
  }

  async function add() {
    adding = true; error = ''
    try {
      const isTP = isPyPiTrustedPublisher(addEco, addKind)
      const material = isTP ? buildTpMaterial() : addMaterial.trim()
      const keyId = addKeyId.trim() || null
      const entry = await api.addTrustAnchor({
        ecosystem: addEco,
        anchorKind: addKind,
        material,
        label: addLabel.trim() || null,
        keyId,
      })
      entries = [...entries, entry]
      showAdd = false
    } catch (e) { error = extract(e) }
    finally { adding = false }
  }

  async function remove(id) {
    if (!confirm($t('settings.security.trustAnchors.removeConfirm'))) return
    error = ''
    try {
      await api.deleteTrustAnchor(id)
      entries = entries.filter(e => e.id !== id)
    } catch (e) { error = extract(e) }
  }

  function kindLabel(key) {
    return ANCHOR_KINDS.find(k => k.key === key)?.label ?? key
  }

  function extract(e) { return e?.body?.detail || e?.message || e?.detail || String(e) }

  $: isTP = isPyPiTrustedPublisher(addEco, addKind)
  $: addDisabled = adding || (isTP
    ? (!tpIssuer.trim() || !tpSubject.trim())
    : !addMaterial.trim())

  /** Group entries by ecosystem for display. */
  $: byEco = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, entries.filter(a => a.ecosystem === e.key)]))
</script>

<div class="page-header list-header mt-4">
  <h3 class="section-h">{$t('settings.security.trustAnchors.section')}</h3>
  <button class="btn-sm" on:click={openAdd}>
    {$t('settings.security.trustAnchors.add')}
  </button>
</div>

<p class="form-hint">{$t('settings.security.trustAnchors.hint')}</p>

<ErrorBanner message={error} />

{#each ECOSYSTEMS as eco (eco.key)}
  <div class="card eco-card">
    <div class="eco-head">
      <span class="eco-label">{eco.label}</span>
    </div>

    {#if loaded && byEco[eco.key].length === 0}
      <p class="text-muted empty">{$t('settings.security.trustAnchors.emptyEco', { values: { ecosystem: eco.label } })}</p>
    {:else}
      <table class="anchor-table">
        <colgroup>
          <col>
          <col class="col-kind">
          <col class="col-label">
          <col class="col-added">
          <col class="col-actions">
        </colgroup>
        <thead>
          <tr>
            <th>{$t('settings.security.trustAnchors.colKeyId')}</th>
            <th>{$t('settings.security.trustAnchors.colKind')}</th>
            <th>{$t('settings.security.trustAnchors.colLabel')}</th>
            <th>{$t('settings.security.trustAnchors.colAdded')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each byEco[eco.key] as entry (entry.id)}
            <tr>
              <td class="t-mono">{entry.keyId || '—'}</td>
              <td><span class="kind-badge">{kindLabel(entry.anchorKind)}</span></td>
              <td>{entry.label || '—'}</td>
              <td class="text-muted">{$formatDateShort(entry.createdAt)}</td>
              <td>
                <div class="row-actions">
                  <button class="btn-sm danger" on:click={() => remove(entry.id)}>
                    {$t('common.actions.remove')}
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/each}

{#if showAdd}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('settings.security.trustAnchors.modal.title')}</h3>

      <div class="form-row">
        <label for="ta-eco">{$t('settings.security.trustAnchors.modal.ecosystem')}</label>
        <select id="ta-eco" bind:value={addEco}>
          {#each ECOSYSTEMS as e (e.key)}<option value={e.key}>{e.label}</option>{/each}
        </select>
      </div>

      <div class="form-row">
        <label for="ta-kind">{$t('settings.security.trustAnchors.modal.anchorKind')}</label>
        <select id="ta-kind" bind:value={addKind}>
          {#each ANCHOR_KINDS as k (k.key)}<option value={k.key}>{k.label}</option>{/each}
        </select>
      </div>

      <div class="form-row">
        <label for="ta-label">{$t('settings.security.trustAnchors.modal.label')}</label>
        <input id="ta-label" type="text" bind:value={addLabel}
               placeholder={$t('settings.security.trustAnchors.modal.labelPlaceholder')} />
      </div>

      {#if needsCallerKeyId(addEco, addKind)}
        <div class="form-row">
          <label for="ta-keyid">{$t('settings.security.trustAnchors.modal.keyId')}</label>
          <input id="ta-keyid" type="text" bind:value={addKeyId}
                 placeholder={$t('settings.security.trustAnchors.modal.keyIdPlaceholder')} />
          <div class="form-hint">{$t('settings.security.trustAnchors.modal.keyIdHint')}</div>
        </div>
      {/if}

      {#if isTP}
        <div class="form-row">
          <label for="ta-tp-issuer">{$t('settings.security.trustAnchors.modal.tpIssuer')}</label>
          <input id="ta-tp-issuer" type="text" bind:value={tpIssuer}
                 placeholder={$t('settings.security.trustAnchors.modal.tpIssuerPlaceholder')} />
        </div>
        <div class="form-row">
          <label for="ta-tp-subject">{$t('settings.security.trustAnchors.modal.tpSubject')}</label>
          <input id="ta-tp-subject" type="text" bind:value={tpSubject}
                 placeholder={$t('settings.security.trustAnchors.modal.tpSubjectPlaceholder')} />
        </div>
        <div class="form-row">
          <label for="ta-tp-match">{$t('settings.security.trustAnchors.modal.tpMatch')}</label>
          <select id="ta-tp-match" value={tpMatch} on:change={onMatchChange}>
            <option value="prefix">{$t('settings.security.trustAnchors.modal.tpMatchPrefix')}</option>
            <option value="exact">{$t('settings.security.trustAnchors.modal.tpMatchExact')}</option>
          </select>
          <div class="form-hint">{$t('settings.security.trustAnchors.modal.tpMatchHint')}</div>
        </div>
      {:else}
        <div class="form-row">
          <label for="ta-material">{$t('settings.security.trustAnchors.modal.material')}</label>
          <textarea id="ta-material" bind:value={addMaterial} rows="8" class="material-area"
                    placeholder={$t('settings.security.trustAnchors.modal.materialPlaceholder')}></textarea>
          <div class="form-hint">{$t('settings.security.trustAnchors.modal.materialHint')}</div>
        </div>
      {/if}

      {#if error}<p class="error-msg">{error}</p>{/if}

      <div class="modal-actions">
        <button class="primary" on:click={add} disabled={addDisabled}>
          {adding ? $t('common.actions.saving') : $t('settings.security.trustAnchors.modal.submit')}
        </button>
        <button on:click={() => { showAdd = false; error = '' }}>
          {$t('common.actions.cancel')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .eco-card { margin-bottom: 12px; }
  .eco-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .eco-label { font-weight: 600; font-size: 13px; }
  .empty { font-size: 13px; margin: 4px 0; }

  .anchor-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .anchor-table th, .anchor-table td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: middle;
  }
  .anchor-table th { color: var(--text2); font-weight: 500; }
  .anchor-table .col-kind    { width: 180px; }
  .anchor-table .col-label   { width: 140px; }
  .anchor-table .col-added   { width: 100px; }
  .anchor-table .col-actions { width: 80px; }

  .kind-badge {
    display: inline-block;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    background: var(--bg2);
    color: var(--text2);
    font-family: var(--mono, monospace);
  }

  .row-actions { display: flex; gap: 4px; }
  .btn-sm { padding: 4px 8px; font-size: 12px; min-height: 0; }

  .list-header { margin-bottom: 4px; }
  .mt-4 { margin-top: 24px; }

  .material-area { font-family: var(--mono, monospace); font-size: 12px; width: 100%; resize: vertical; }

  .modal-actions { display: flex; gap: 8px; margin-top: 12px; }
  .error-msg { color: var(--danger); font-size: 13px; margin-top: 6px; }
</style>
