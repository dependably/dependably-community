<!--
  Topbar bell → per-tenant alert center dropdown. Fetch-on-load (badge count only) +
  fetch-on-open (full active list) — no polling, per the resolved design decision. Admin/owner
  only; TopBar.svelte gates the whole component behind isAdmin so it never mounts for a member.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import { formatRelativeTime } from './format.js'

  let open = false
  let activeCount = 0
  /** @type {any[]} */
  let alerts = []
  let loaded = false
  let loading = false
  let error = ''
  /** @type {HTMLElement} */
  let wrapEl

  onMount(loadSummary)

  async function loadSummary() {
    try {
      const s = await api.getAlertsSummary()
      activeCount = s.activeCount ?? 0
    } catch {
      // Best-effort badge — a failed summary fetch just leaves the badge stale, not broken.
    }
  }

  async function toggle() {
    open = !open
    if (open) {
      await loadAlerts()
    }
  }

  async function loadAlerts() {
    loading = true
    error = ''
    try {
      const data = await api.listAlerts('active')
      alerts = data.items ?? []
      loaded = true
    } catch (e) {
      error = e?.body?.detail || e?.message || String(e)
    } finally {
      loading = false
    }
  }

  async function dismiss(alert) {
    try {
      await api.dismissAlert(alert.id)
      alerts = alerts.filter(a => a.id !== alert.id)
      activeCount = Math.max(0, activeCount - 1)
    } catch (e) {
      error = e?.body?.detail || e?.message || String(e)
    }
  }

  function close() {
    open = false
  }

  // Close on any click outside the wrapper (button + dropdown). Checking containment — rather
  // than stopPropagation inside the dropdown — avoids putting a click handler directly on a
  // non-interactive wrapper div (a11y_click_events_have_key_events).
  function onWindowClick(e) {
    if (open && wrapEl && !wrapEl.contains(e.target)) {
      close()
    }
  }
</script>

<svelte:window on:click={onWindowClick} />

<div class="alerts-panel-wrap" bind:this={wrapEl}>
  <button
    class="icon-btn"
    aria-label={$t('nav.notifications')}
    title={$t('nav.notifications')}
    aria-expanded={open}
    on:click={toggle}
  >
    <svg width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-bell"/></svg>
    {#if activeCount > 0}
      <span class="badge-dot" aria-hidden="true"></span>
    {/if}
  </button>

  {#if open}
    <div class="alerts-dropdown">
      <div class="alerts-dropdown-header">
        <h3>{$t('alerts.panel.title')}</h3>
        <button class="icon-btn close-btn" aria-label={$t('alerts.panel.close')} on:click={close}>
          <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-x"/></svg>
        </button>
      </div>

      {#if error}
        <p class="alerts-error">{error}</p>
      {/if}

      {#if loading && !loaded}
        <p class="alerts-status">{$t('alerts.panel.loading')}</p>
      {:else if alerts.length === 0}
        <p class="alerts-status">{$t('alerts.panel.empty')}</p>
      {:else}
        <ul class="alerts-list">
          {#each alerts as alert (alert.id)}
            <li class="alerts-item">
              <div class="alerts-item-body">
                <span class="alerts-item-title">{alert.title}</span>
                <span class="alerts-item-meta">{$formatRelativeTime(alert.createdAt)}</span>
              </div>
              <button class="btn-sm alerts-dismiss" on:click={() => dismiss(alert)}>
                {$t('common.actions.dismiss')}
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</div>

<style>
  .alerts-panel-wrap {
    position: relative;
    display: inline-flex;
  }
  .icon-btn {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    min-height: 0;
    padding: 0;
    border: none;
    background: none;
    color: var(--text2);
    border-radius: var(--radius);
    cursor: pointer;
  }
  .icon-btn:hover { background: var(--bg3); color: var(--text); }
  .badge-dot {
    position: absolute;
    top: 3px;
    right: 3px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--danger);
    border: 1px solid var(--bg2);
  }
  .alerts-dropdown {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    z-index: 50;
    width: 320px;
    max-height: 400px;
    overflow-y: auto;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  }
  .alerts-dropdown-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
  }
  .alerts-dropdown-header h3 {
    margin: 0;
    font-size: 13px;
    font-weight: 600;
  }
  .close-btn {
    width: 22px;
    height: 22px;
    min-height: 0;
  }
  .alerts-status,
  .alerts-error {
    padding: 16px 12px;
    margin: 0;
    font-size: 12px;
    color: var(--text2);
    text-align: center;
  }
  .alerts-error {
    color: var(--danger);
  }
  .alerts-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .alerts-item {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
  }
  .alerts-item:last-child { border-bottom: none; }
  .alerts-item-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .alerts-item-title {
    font-size: 12px;
    color: var(--text);
    word-break: break-word;
  }
  .alerts-item-meta {
    font-size: 11px;
    color: var(--text2);
  }
  .alerts-dismiss {
    flex-shrink: 0;
    min-height: 0;
  }
</style>
