<!--
  Hex registry signing key — the per-org RSA key every Hex registry resource this org serves is
  signed with. Shows the public half (what a Mix or Rebar3 client registers the repository
  with) and its fingerprint, and offers rotation. Self-contained: loads on mount.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import ErrorBanner from '../ErrorBanner.svelte'

  /** @type {any} */
  let key = null
  let loaded = false
  let error = ''
  let rotating = false
  let copied = false

  onMount(load)

  async function load() {
    try {
      key = await api.getHexSigningKey()
      loaded = true
    } catch (e) { error = e?.message || String(e) }
  }

  async function rotate() {
    if (!confirm($t('settings.proxy.hexSigningKey.rotateConfirm'))) return
    rotating = true
    error = ''
    try {
      key = await api.rotateHexSigningKey()
    } catch (e) { error = e?.message || String(e) }
    finally { rotating = false }
  }

  async function copyPem() {
    if (!key?.publicKeyPem) return
    try {
      await navigator.clipboard.writeText(key.publicKeyPem)
      copied = true
      setTimeout(() => { copied = false }, 1500)
    } catch { /* clipboard unavailable — the PEM is still visible below */ }
  }
</script>

<div class="card card-narrow mt-4">
  <h3 class="card-title">{$t('settings.proxy.hexSigningKey.title')}</h3>
  <p class="form-hint">{$t('settings.proxy.hexSigningKey.hint')}</p>
  <ErrorBanner message={error} />
  {#if loaded && key}
    {#if !key.canSign}
      <p class="form-hint warning-text">{$t('settings.proxy.hexSigningKey.noMasterKey')}</p>
    {/if}
    {#if key.exists}
      <div class="form-row">
        <span class="label-row">{$t('settings.proxy.hexSigningKey.fingerprint')}</span>
        <code class="fingerprint">{key.fingerprint}</code>
      </div>
      <div class="form-row">
        <label for="hex-public-key-pem">{$t('settings.proxy.hexSigningKey.publicKey')}</label>
        <textarea id="hex-public-key-pem" rows="9" readonly value={key.publicKeyPem}></textarea>
      </div>
      <div class="row-actions">
        <button type="button" class="btn-secondary" on:click={copyPem}>
          {copied ? $t('settings.proxy.hexSigningKey.copied') : $t('settings.proxy.hexSigningKey.copy')}
        </button>
        <button type="button" class="btn-danger" disabled={!key.canSign || rotating} on:click={rotate}>
          {$t('settings.proxy.hexSigningKey.rotate')}
        </button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .fingerprint { word-break: break-all; }
  .warning-text { color: var(--warning-text, var(--text2)); }
  .row-actions { display: flex; gap: 0.5rem; margin-top: 0.75rem; }
</style>
