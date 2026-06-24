<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

  let banners = []
  let loading = true
  let error = ''

  let createOpen = false
  let createBusy = false
  let createError = ''
  let newBanner = emptyForm()

  function emptyForm() {
    return {
      severity: 'info',
      body: '',
      linkUrl: '',
      linkLabel: '',
      targetRole: 'all',
      startsAt: '',
      endsAt: '',
      enabled: true
    }
  }

  async function load() {
    loading = true
    error = ''
    try {
      banners = await systemApi.listSystemBanners()
    } catch (e) {
      error = e?.message || $t('system.banners.loadError')
    } finally {
      loading = false
    }
  }

  async function createBanner() {
    createBusy = true
    createError = ''
    try {
      await systemApi.createSystemBanner({
        severity: newBanner.severity,
        body: newBanner.body,
        linkUrl: newBanner.linkUrl || null,
        linkLabel: newBanner.linkLabel || null,
        targetRole: newBanner.targetRole,
        startsAt: newBanner.startsAt,
        endsAt: newBanner.endsAt,
        enabled: newBanner.enabled
      })
      newBanner = emptyForm()
      createOpen = false
      await load()
    } catch (e) {
      createError = e?.message || $t('system.banners.createError')
    } finally {
      createBusy = false
    }
  }

  async function deleteBanner(id) {
    if (!confirm($t('system.banners.deleteConfirm'))) return
    try {
      await systemApi.deleteSystemBanner(id)
      await load()
    } catch (e) {
      error = e?.message || $t('system.banners.deleteError')
    }
  }

  function formatWindow(b) {
    return `${b.startsAt.replace('T', ' ').replace('Z', '')} – ${b.endsAt.replace('T', ' ').replace('Z', '')}`
  }

  onMount(load)
</script>

<div class="page">
  <div class="page-header">
    <div>
      <h1>{$t('system.banners.title')}</h1>
      <p class="subtitle">{$t('system.banners.subtitle')}</p>
    </div>
    <button class="primary" on:click={() => { createOpen = !createOpen; createError = '' }}>
      {createOpen ? $t('system.banners.cancelCreate') : $t('system.banners.newBanner')}
    </button>
  </div>

  {#if createOpen}
    <div class="card create-card">
      <h2 class="section-title">{$t('system.banners.createTitle')}</h2>
      {#if createError}
        <div class="error-msg">{createError}</div>
      {/if}
      <form on:submit|preventDefault={createBanner}>
        <div class="form-row">
          <label for="sb-body">{$t('system.banners.body')}</label>
          <textarea id="sb-body" bind:value={newBanner.body} required maxlength="2000" rows="3"></textarea>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label for="sb-severity">{$t('system.banners.severity')}</label>
            <select id="sb-severity" bind:value={newBanner.severity}>
              <option value="info">info</option>
              <option value="warn">warn</option>
              <option value="alert">alert</option>
            </select>
          </div>
          <div class="form-row">
            <label for="sb-target">{$t('system.banners.targetRole')}</label>
            <select id="sb-target" bind:value={newBanner.targetRole}>
              <option value="all">all</option>
              <option value="member">member</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
              <option value="auditor">auditor</option>
            </select>
          </div>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <label for="sb-starts">{$t('system.banners.startsAt')}</label>
            <input id="sb-starts" type="datetime-local" bind:value={newBanner.startsAt} required />
          </div>
          <div class="form-row">
            <label for="sb-ends">{$t('system.banners.endsAt')}</label>
            <input id="sb-ends" type="datetime-local" bind:value={newBanner.endsAt} required />
          </div>
        </div>
        <div class="form-row">
          <label for="sb-link-url">{$t('system.banners.linkUrl')}</label>
          <input id="sb-link-url" type="url" bind:value={newBanner.linkUrl} maxlength="2048" placeholder="https://" />
        </div>
        <div class="form-row">
          <label for="sb-link-label">{$t('system.banners.linkLabel')}</label>
          <input id="sb-link-label" type="text" bind:value={newBanner.linkLabel} maxlength="200" />
        </div>
        <div class="form-row checkbox-row">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={newBanner.enabled} />
            {$t('system.banners.enabled')}
          </label>
        </div>
        <div class="form-actions">
          <button type="submit" class="primary" disabled={createBusy}>
            {createBusy ? $t('system.banners.creating') : $t('system.banners.create')}
          </button>
        </div>
      </form>
    </div>
  {/if}

  {#if error}
    <div class="error-msg">{error}</div>
  {/if}

  {#if loading}
    <div class="loading-row"><span class="spinner"></span></div>
  {:else if banners.length === 0}
    <p class="empty">{$t('system.banners.empty')}</p>
  {:else}
    <div class="card">
      <table class="data-table">
        <thead>
          <tr>
            <th>{$t('system.banners.severity')}</th>
            <th>{$t('system.banners.body')}</th>
            <th>{$t('system.banners.targetRole')}</th>
            <th>{$t('system.banners.window')}</th>
            <th>{$t('system.banners.enabled')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each banners as b (b.id)}
            <tr>
              <td><span class="sev-badge sev-{b.severity}">{b.severity}</span></td>
              <td class="body-cell">{b.body}</td>
              <td>{b.targetRole}</td>
              <td class="window-cell">{formatWindow(b)}</td>
              <td>{b.enabled ? $t('system.banners.yes') : $t('system.banners.no')}</td>
              <td>
                <div class="row-actions">
                  <button class="danger-link" on:click={() => deleteBanner(b.id)}>
                    {$t('system.banners.delete')}
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 16px;
  }
  h1 { margin: 0 0 4px; }
  .subtitle { color: var(--text2); font-size: 13px; margin: 0; }
  .section-title { margin: 0 0 16px; font-size: 15px; }
  .create-card { margin-bottom: 16px; }
  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0 16px;
  }
  .form-actions { margin-top: 8px; }
  .checkbox-row { margin-bottom: 4px; }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    cursor: pointer;
  }
  .checkbox-label input[type="checkbox"] {
    margin: 0;
    min-height: 0;
    width: auto;
    flex-shrink: 0;
  }
  .data-table { width: 100%; border-collapse: collapse; }
  .data-table th, .data-table td {
    padding: 8px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .data-table th { color: var(--text2); font-weight: 500; }
  .body-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .window-cell { white-space: nowrap; font-size: 12px; color: var(--text2); }
  .sev-badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .sev-info { background: var(--info-bg); color: var(--info-text); }
  .sev-warn { background: var(--warning-bg); color: var(--warning-text); }
  .sev-alert { background: var(--danger-bg); color: var(--danger-text); }
  .row-actions { display: flex; gap: 8px; }
  .danger-link {
    background: none;
    border: none;
    padding: 0;
    color: var(--danger);
    font-size: 13px;
    cursor: pointer;
    min-height: 0;
  }
  .danger-link:hover { text-decoration: underline; }
  .loading-row { padding: 24px 0; text-align: center; }
  .empty { color: var(--text2); font-size: 13px; }
  .error-msg {
    background: var(--danger-bg);
    color: var(--danger-text);
    border-radius: var(--radius);
    padding: 8px 12px;
    font-size: 13px;
    margin-bottom: 12px;
  }
</style>
