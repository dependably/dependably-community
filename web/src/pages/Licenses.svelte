<script>
  import { createEventDispatcher, onMount } from 'svelte'
  import { api } from '../lib/api.js'

  const dispatch = createEventDispatcher()

  let components = []
  let count = 0
  let generatedAt = null
  let devModeStub = false
  let loading = true
  let error = ''

  onMount(async () => {
    try {
      const data = await api.getLicenses()
      components = data.components ?? []
      count = data.count ?? components.length
      generatedAt = data.generatedAt ?? null
      devModeStub = data.devModeStub === true
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  })

  function close() { dispatch('close') }
  function onKeydown(e) { if (e.key === 'Escape') close() }
  function onBackdropClick(e) { if (e.target === e.currentTarget) close() }

  function licenseLabel(license) {
    if (!license) return '—'
    return license.spdx ?? license.name ?? '—'
  }
</script>

<svelte:window on:keydown={onKeydown} />

<div class="overlay" on:click={onBackdropClick} role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="notices-title">
    <header>
      <h2 id="notices-title">Open source notices</h2>
      <button class="close" on:click={close} aria-label="Close">×</button>
    </header>

    <div class="body">
      {#if error}
        <div class="page-error">{error}</div>
      {:else if loading}
        <span class="spinner"></span>
      {:else if devModeStub}
        <div class="stub">
          Notices are populated during the Docker build; not available when running <code>dotnet run</code> locally.
        </div>
      {:else}
        <p class="meta">
          {count} component{count === 1 ? '' : 's'}{generatedAt ? ` · generated ${generatedAt}` : ''}
        </p>
        <table class="licenses-table">
          <colgroup>
            <col>
            <col class="col-version">
            <col class="col-license">
            <col>
          </colgroup>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>License</th>
              <th>Copyright</th>
            </tr>
          </thead>
          <tbody>
            {#each components as c (c.purl ?? `${c.name}@${c.version}`)}
              <tr>
                <td><code>{c.name}</code></td>
                <td class="nowrap text-muted">{c.version ?? '—'}</td>
                <td>
                  {#if c.license?.url}
                    <a href={c.license.url} target="_blank" rel="noopener noreferrer">{licenseLabel(c.license)}</a>
                  {:else}
                    {licenseLabel(c.license)}
                  {/if}
                </td>
                <td class="detail-cell text-muted">{c.copyright ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 24px;
  }
  .dialog {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: 100%;
    max-width: 960px;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .close {
    background: transparent;
    border: 0;
    font-size: 22px;
    line-height: 1;
    color: var(--text2);
    cursor: pointer;
    padding: 4px 8px;
  }
  .close:hover { color: var(--text); }
  .body {
    padding: 16px 20px;
    overflow-y: auto;
    flex: 1;
  }
  .meta { color: var(--text2); font-size: 12px; margin: 0 0 12px; }
  .stub {
    color: var(--text2);
    font-size: 13px;
    padding: 16px;
    border: 1px dashed var(--border);
    border-radius: 6px;
  }
  .licenses-table .col-version { width: 120px; }
  .licenses-table .col-license { width: 140px; }
</style>
