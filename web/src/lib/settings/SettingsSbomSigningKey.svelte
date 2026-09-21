<!--
  SBOM author-signing key (ADR-sbom-author-signature) — the per-org key every exported CycloneDX
  document is signed with. Shows the active key's identifier, algorithm and creation time, the
  public half in a copyable form, and the full key history (retired keys stay verifiable
  forever, so they stay visible here too). Rotation retires the current key rather than deleting
  it — the confirm copy says so explicitly.

  `getSbomSigningKey` carries a `state` (signed / unsigned-no-master-key / unsigned-key-
  unavailable) resolved the same way an exported document's own signature-state is: whether the
  org has ever had a key is a fact about the org, whether THIS node can read it is a fact about
  the replica that answered. `getSbomSigningKeys` is the same unauthenticated list a document's
  recipient fetches to verify a signature — reused here so the active key's public half and its
  full history are visible even when this node cannot sign (unsigned-key-unavailable): the
  public half needs no master key to read, only the private half does.

  Self-contained: loads on mount.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { formatDateShort } from '../format.js'
  import ErrorBanner from '../ErrorBanner.svelte'

  /** @type {{ canSign: boolean, exists: boolean, keyId: string|null, publicKeyPem: string|null, createdAt: string|null, state: string } | null} */
  let active = null
  /** @type {Array<{ keyId: string, algorithm: string, publicKeyPem: string, createdAt: string, retiredAt: string|null, revokedAt: string|null }>} */
  let history = []
  let loaded = false
  let error = ''
  let rotating = false
  let copied = false

  onMount(load)

  async function load() {
    try {
      const [activeResult, historyResult] = await Promise.all([api.getSbomSigningKey(), api.getSbomSigningKeys()])
      active = activeResult
      history = historyResult
      loaded = true
    } catch (e) { error = e?.message || String(e) }
  }

  async function rotate() {
    if (!confirm($t('settings.proxy.sbomSigningKey.rotateConfirm'))) return
    rotating = true
    error = ''
    try {
      const [activeResult, historyResult] = await Promise.all([api.rotateSbomSigningKey(), api.getSbomSigningKeys()])
      active = activeResult
      history = historyResult
    } catch (e) { error = e?.message || String(e) }
    finally { rotating = false }
  }

  async function copyPem(pem) {
    if (!pem) return
    try {
      await navigator.clipboard.writeText(pem)
      copied = true
      setTimeout(() => { copied = false }, 1500)
    } catch { /* clipboard unavailable — the PEM is still visible below */ }
  }

  // The active entry from the PUBLIC list — resolvable without a master key, unlike `active`
  // above, so it is what carries the org's active key's public half when this node itself
  // cannot sign (unsigned-key-unavailable). Falls back to `active` for the ordinary signed case.
  $: activeFromHistory = history.find(k => !k.retiredAt && !k.revokedAt) || null
  $: displayKeyId = active?.keyId || activeFromHistory?.keyId || null
  $: displayAlgorithm = activeFromHistory?.algorithm || 'ES256'
  $: displayCreatedAt = active?.createdAt || activeFromHistory?.createdAt || null
  $: displayPem = active?.publicKeyPem || activeFromHistory?.publicKeyPem || null
  $: hasActiveKey = displayKeyId !== null
  $: pastKeys = history.filter(k => k.retiredAt || k.revokedAt)
</script>

<div class="card card-narrow mt-4">
  <h3 class="card-title">{$t('settings.proxy.sbomSigningKey.title')}</h3>
  <p class="form-hint">{$t('settings.proxy.sbomSigningKey.hint')}</p>
  <ErrorBanner message={error} />
  {#if loaded && active}
    {#if active.state === 'unsigned-no-master-key'}
      <p class="form-hint warning-text">{$t('settings.proxy.sbomSigningKey.noMasterKey')}</p>
    {:else if active.state === 'unsigned-key-unavailable'}
      <div class="warn-box">
        <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert" /></svg>
        {$t('settings.proxy.sbomSigningKey.keyUnavailable')}
      </div>
    {/if}

    {#if hasActiveKey}
      <div class="form-row">
        <span class="label-row">{$t('settings.proxy.sbomSigningKey.keyId')}</span>
        <code class="fingerprint">{displayKeyId}</code>
      </div>
      <div class="form-row">
        <span class="label-row">{$t('settings.proxy.sbomSigningKey.algorithm')}</span>
        <span>{displayAlgorithm}</span>
      </div>
      {#if displayCreatedAt}
        <div class="form-row">
          <span class="label-row">{$t('settings.proxy.sbomSigningKey.createdAt')}</span>
          <span>{$formatDateShort(displayCreatedAt)}</span>
        </div>
      {/if}
      {#if displayPem}
        <div class="form-row">
          <label for="sbom-public-key-pem">{$t('settings.proxy.sbomSigningKey.publicKey')}</label>
          <textarea id="sbom-public-key-pem" rows="6" readonly value={displayPem}></textarea>
        </div>
      {/if}
      <div class="row-actions">
        {#if displayPem}
          <button type="button" class="btn-secondary" on:click={() => copyPem(displayPem)}>
            {copied ? $t('settings.proxy.sbomSigningKey.copied') : $t('settings.proxy.sbomSigningKey.copy')}
          </button>
        {/if}
        <button type="button" class="btn-danger" disabled={!active.canSign || rotating} on:click={rotate}>
          {$t('settings.proxy.sbomSigningKey.rotate')}
        </button>
      </div>
    {:else}
      <div class="row-actions">
        <button type="button" class="btn-danger" disabled={!active.canSign || rotating} on:click={rotate}>
          {$t('settings.proxy.sbomSigningKey.rotate')}
        </button>
      </div>
    {/if}

    {#if pastKeys.length > 0}
      <h4 class="history-title">{$t('settings.proxy.sbomSigningKey.historyTitle')}</h4>
      <p class="form-hint">{$t('settings.proxy.sbomSigningKey.historyHint')}</p>
      <table class="key-history-table">
        <thead>
          <tr>
            <th>{$t('settings.proxy.sbomSigningKey.keyId')}</th>
            <th>{$t('settings.proxy.sbomSigningKey.createdAt')}</th>
            <th>{$t('settings.proxy.sbomSigningKey.retiredAt')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each pastKeys as k (k.keyId)}
            <tr>
              <td class="t-mono">{k.keyId}</td>
              <td class="text-muted">{$formatDateShort(k.createdAt)}</td>
              <td class="text-muted">{k.retiredAt ? $formatDateShort(k.retiredAt) : '—'}</td>
              <td>
                {#if k.revokedAt}
                  <span class="badge danger">{$t('settings.proxy.sbomSigningKey.revoked')}</span>
                {:else}
                  <span class="badge">{$t('settings.proxy.sbomSigningKey.retired')}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</div>

<style>
  .fingerprint { word-break: break-all; }
  .warning-text { color: var(--warning-text, var(--text2)); }
  .warn-box {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
    padding: 6px 10px;
    border-radius: var(--radius);
    margin: 8px 0;
    font-size: 12px;
  }
  .history-title { margin: 20px 0 4px; font-size: 13px; font-weight: 600; }
  .row-actions { display: flex; gap: 0.5rem; margin-top: 0.75rem; }
  .key-history-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .key-history-table th, .key-history-table td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: middle;
  }
  .key-history-table th { color: var(--text2); font-weight: 500; }
</style>
