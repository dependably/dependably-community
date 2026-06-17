<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'

  // /metrics access editor, shared by the multi-mode system SPA and the single-mode tenant
  // Settings page. The two surfaces differ only in which endpoints back it, so the caller
  // passes the load/save fns. PUT returns 409 when env locks a knob; warnings from broad
  // CIDRs come back in the 200 response body.
  export let getAccess     // () => Promise<access>
  export let updateAccess  // (body) => Promise<{ warnings }>

  let access = null
  let accessEnabled = false
  let accessAllowedText = ''
  let recentDeniedIps = []
  let loading = true
  let accessSaving = false
  let accessError = ''
  let accessWarnings = []
  let accessSavedAt = null

  async function load() {
    loading = true
    accessError = ''
    try {
      const acc = await getAccess()
      access = acc
      accessEnabled = acc.enabled
      accessAllowedText = (acc.allowedIps || []).join('\n')
      recentDeniedIps = acc.recentDeniedIps || []
    } catch (e) { accessError = e.message }
    finally { loading = false }
  }

  onMount(load)

  function broadCidrWarning(list) {
    return list.some((s) => s === '0.0.0.0/0' || s === '::/0')
  }

  async function saveAccess() {
    accessSaving = true
    accessError = ''
    accessWarnings = []
    try {
      const body = {}
      if (!access.enabledLockedByEnv) body.enabled = accessEnabled
      if (!access.allowlistLockedByEnv) {
        body.allowedIps = accessAllowedText
          .split('\n')
          .map((s) => s.trim())
          .filter((s) => s.length > 0)
      }
      const resp = await updateAccess(body)
      if (resp && Array.isArray(resp.warnings)) accessWarnings = resp.warnings
      accessSavedAt = new Date()
      // Refresh so source badges / effective values reflect persisted state.
      const refreshed = await getAccess()
      access = refreshed
      accessEnabled = refreshed.enabled
      accessAllowedText = (refreshed.allowedIps || []).join('\n')
      recentDeniedIps = refreshed.recentDeniedIps || []
    } catch (e) { accessError = e.message }
    finally { accessSaving = false }
  }

  function addDeniedIp(ip) {
    const current = accessAllowedText
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
    if (!current.includes(ip)) {
      accessAllowedText = [...current, ip].join('\n')
    }
  }

  function relativeTime(ts) {
    const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
    if (diff < 60) return $t('system.settings.metrics.recentDenied.justNow')
    if (diff < 3600) return $t('system.settings.metrics.recentDenied.minutesAgo', { values: { n: Math.floor(diff / 60) } })
    if (diff < 86400) return $t('system.settings.metrics.recentDenied.hoursAgo', { values: { n: Math.floor(diff / 3600) } })
    return $t('system.settings.metrics.recentDenied.daysAgo', { values: { n: Math.floor(diff / 86400) } })
  }
</script>

{#if loading}
  <span class="spinner"></span>
{:else if access}
  <p class="subtitle">{$t('system.settings.metrics.subtitle')}</p>

  {#if access.enabledLockedByEnv || access.allowlistLockedByEnv}
    <div class="env-banner">{$t('system.settings.metrics.envLocked')}</div>
  {/if}

  {#if accessError}<div class="page-error">{accessError}</div>{/if}

  <form on:submit|preventDefault={saveAccess}>
    <div class="form-row">
      <label for="metrics-enabled">{$t('system.settings.metrics.enabled')}</label>
      <div class="field">
        <div class="input-row">
          <input
            id="metrics-enabled"
            type="checkbox"
            bind:checked={accessEnabled}
            disabled={access.enabledLockedByEnv}
          />
          <span class="source-tag source-tag-{access.enabledSource}">{access.enabledSource}</span>
        </div>
        <small class="hint">{$t('system.settings.metrics.enabledHint')}</small>
      </div>
    </div>

    <div class="form-row">
      <label for="metrics-allowed-ips">{$t('system.settings.metrics.allowedIps')}</label>
      <div class="field">
        <textarea
          id="metrics-allowed-ips"
          rows="5"
          bind:value={accessAllowedText}
          disabled={access.allowlistLockedByEnv}
          placeholder="127.0.0.1&#10;::1"
        ></textarea>
        <small class="hint">
          {$t('system.settings.metrics.allowedIpsHint')}
          <span class="source-tag source-tag-{access.allowlistSource}">{access.allowlistSource}</span>
        </small>
        {#if broadCidrWarning(accessAllowedText.split('\n').map((s) => s.trim()).filter(Boolean))}
          <small class="warn">{$t('system.settings.metrics.broadCidrWarn')}</small>
        {/if}
      </div>
    </div>

    <button
      class="primary"
      type="submit"
      disabled={accessSaving || (access.enabledLockedByEnv && access.allowlistLockedByEnv)}
    >
      {accessSaving ? $t('system.settings.saving') : $t('system.settings.metrics.save')}
    </button>
    {#if accessSavedAt}<span class="saved">{$t('system.settings.savedAt', { values: { time: accessSavedAt.toLocaleTimeString() } })}</span>{/if}

    {#each accessWarnings as warning, i (i)}
      <div class="warn-box"><svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg> {warning}</div>
    {/each}
  </form>

  {#if recentDeniedIps.length > 0}
    <div class="denied-section">
      <h4 class="denied-title">{$t('system.settings.metrics.recentDenied.title')}</h4>
      <p class="denied-hint">{$t('system.settings.metrics.recentDenied.hint')}</p>
      <ul class="denied-list">
        {#each recentDeniedIps as entry (entry.ip)}
          <li class="denied-row">
            <span class="denied-ip">{entry.ip}</span>
            <span class="denied-time">{relativeTime(entry.lastSeen)}</span>
            {#if !access.allowlistLockedByEnv}
              <button
                type="button"
                class="add-btn"
                title={$t('system.settings.metrics.recentDenied.addTitle')}
                on:click={() => addDeniedIp(entry.ip)}
              >
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-check"/></svg>
                {$t('system.settings.metrics.recentDenied.add')}
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    </div>
  {/if}
{/if}

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
  form { display: flex; flex-direction: column; gap: 16px; max-width: 560px; }
  .form-row { display: grid; grid-template-columns: 1fr 240px; gap: 12px; align-items: start; }
  .form-row label { font-size: 13px; color: var(--text2); padding-top: 8px; }
  .field { display: flex; flex-direction: column; gap: 4px; }
  .input-row { display: flex; align-items: center; gap: 6px; }
  .input-row input { flex: 1; }
  .hint { font-size: 11px; color: var(--text2); }
  .warn { font-size: 11px; color: orange; }
  .saved { color: var(--text2); font-size: 13px; margin-left: 12px; }
  textarea {
    width: 100%;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono, monospace);
    font-size: 12px;
  }
  textarea:disabled { opacity: 0.6; cursor: not-allowed; }
  .env-banner {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 8px 12px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    max-width: 560px;
    font-size: 13px;
  }
  .warn-box {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 6px 10px;
    border-radius: var(--radius);
    margin-top: 8px;
    font-size: 12px;
    max-width: 560px;
  }
  .source-tag {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-left: 8px;
  }
  .source-tag-env { background: var(--accent); color: white; }
  .source-tag-db { background: var(--bg3); color: var(--text); border: 1px solid var(--border); }
  .source-tag-default { background: var(--bg); color: var(--text2); border: 1px solid var(--border); }

  .denied-section { margin-top: 24px; max-width: 560px; }
  .denied-title { font-size: 13px; font-weight: 600; margin: 0 0 4px; color: var(--text); }
  .denied-hint { font-size: 11px; color: var(--text2); margin: 0 0 8px; }
  .denied-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; }
  .denied-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
    font-size: 12px;
  }
  .denied-ip { font-family: var(--font-mono, monospace); flex: 1; }
  .denied-time { color: var(--text2); font-size: 11px; }
  .add-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    font-size: 11px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    cursor: pointer;
    min-height: 0;
  }
  .add-btn:hover { background: var(--bg3); }
</style>
