<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { formatDate } from '../lib/format.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import Pagination from '../lib/Pagination.svelte'

  // Tab state — Lifecycle (activity feed) is the default; Admin actions (audit_log) loads when its tab is selected.
  let activeTab = 'lifecycle'

  // ── Lifecycle tab (activity) ─────────────────────────────────────────────
  let lcItems = [], lcLoading = true, lcError = ''
  let lcFilterType = ''
  let lcPage = 1, lcLimit = 50, lcTotal = 0
  let lcSortCol = 'createdAt', lcSortDir = 'desc'

  $: lcSorted = [...lcItems].sort((a, b) => {
    let av = a[lcSortCol] ?? '', bv = b[lcSortCol] ?? ''
    if (typeof av === 'string') av = av.toLowerCase()
    if (typeof bv === 'string') bv = bv.toLowerCase()
    if (av < bv) return lcSortDir === 'asc' ? -1 : 1
    if (av > bv) return lcSortDir === 'asc' ? 1 : -1
    return 0
  })

  async function loadLifecycle() {
    lcLoading = true
    lcError = ''
    try {
      const p = { page: lcPage, limit: lcLimit }
      if (lcFilterType) p.event_type = lcFilterType
      const data = await api.getActivity(p)
      lcItems = data.items
      lcTotal = data.total
    } catch (e) { lcError = e.message }
    finally { lcLoading = false }
  }

  function lcOnPageChange(e) { lcPage = e.detail.page; loadLifecycle() }
  function lcOnLimitChange(e) { lcLimit = e.detail.limit; lcPage = 1; loadLifecycle() }
  function lcOnFilterChange() { lcPage = 1; loadLifecycle() }
  function lcToggleSort(col) {
    if (lcSortCol === col) lcSortDir = lcSortDir === 'asc' ? 'desc' : 'asc'
    else { lcSortCol = col; lcSortDir = col === 'createdAt' ? 'desc' : 'asc' }
  }

  const EVENT_COLORS = {
    first_fetch: 'first-fetch',
    push: 'hosted',
    pull: 'proxy',
    cache_miss: 'warning',
    vuln_scan: 'vuln-scan',
    vuln_scan_pass: 'vuln-scan',
    vuln_rescan_pass: 'vuln-scan',
    delete: 'yanked',
    blocked: 'yanked',
    blocked_vuln_score: 'yanked',
    blocked_manual: 'yanked',
    manual_block: 'warning',
    manual_unblock: 'cicd',
  }
  const SYSTEM_EVENTS = new Set(['vuln_scan', 'vuln_scan_pass', 'vuln_rescan_pass'])

  // ── Admin actions tab (audit_log scope='tenant') ─────────────────────────
  let adItems = [], adLoading = false, adError = ''
  let adPage = 1, adLimit = 50, adTotal = 0

  async function loadAdmin() {
    adLoading = true
    adError = ''
    try {
      const data = await api.getAudit({ page: adPage, limit: adLimit })
      adItems = data.items
      adTotal = data.total
    } catch (e) { adError = e.message }
    finally { adLoading = false }
  }

  function adOnPageChange(e) { adPage = e.detail.page; loadAdmin() }
  function adOnLimitChange(e) { adLimit = e.detail.limit; adPage = 1; loadAdmin() }

  function selectTab(tab) {
    activeTab = tab
    if (tab === 'admin') loadAdmin()
  }

  // Reload everything when the org changes. Both tabs' state is reset; the inactive tab refetches
  // the next time it's selected.
  $: org = $currentOrg
  $: if (org) {
    loadLifecycle()
    if (activeTab === 'admin') loadAdmin()
  }
</script>

<div class="page page-wide">
  <div class="page-header">
    <h1 class="page-title">{$t('audit.title')}</h1>
  </div>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'lifecycle'} role="tab" aria-selected={activeTab === 'lifecycle'} on:click={() => selectTab('lifecycle')}>
      {$t('audit.tabs.lifecycle')}
    </button>
    <button class="tab" class:active={activeTab === 'admin'} role="tab" aria-selected={activeTab === 'admin'} on:click={() => selectTab('admin')}>
      {$t('audit.tabs.adminActions')}
    </button>
  </div>

  {#if activeTab === 'lifecycle'}
    <div class="tab-toolbar">
      <select bind:value={lcFilterType} on:change={lcOnFilterChange} class="event-select">
        <option value="">{$t('activity.allEvents')}</option>
        <option value="first_fetch">{$t('activity.events.firstFetch')}</option>
        <option value="push">{$t('activity.events.push')}</option>
        <option value="pull">{$t('activity.events.pull')}</option>
        <option value="vuln_scan">{$t('activity.events.vulnScan')}</option>
        <option value="vuln_scan_pass">{$t('activity.events.vulnScanPass')}</option>
        <option value="vuln_rescan_pass">{$t('activity.events.vulnRescanPass')}</option>
        <option value="delete">{$t('activity.events.delete')}</option>
      </select>
    </div>

    {#if lcError}<div class="page-error">{lcError}</div>{/if}
    {#if lcLoading}<span class="spinner"></span>
    {:else}
      <table class="table-auto activity-table">
        <colgroup>
          <col class="col-time">
          <col class="col-event">
          <col>
          <col class="col-detail">
          <col class="col-actor">
        </colgroup>
        <thead>
          <tr>
            <th class="sortable" on:click={() => lcToggleSort('createdAt')}>{$t('activity.columns.time')}{sortIndicator('createdAt', lcSortCol, lcSortDir)}</th>
            <th class="sortable" on:click={() => lcToggleSort('eventType')}>{$t('activity.columns.event')}{sortIndicator('eventType', lcSortCol, lcSortDir)}</th>
            <th class="sortable" on:click={() => lcToggleSort('purl')}>{$t('activity.columns.purl')}{sortIndicator('purl', lcSortCol, lcSortDir)}</th>
            <th class="sortable" on:click={() => lcToggleSort('detail')}>{$t('activity.columns.detail')}{sortIndicator('detail', lcSortCol, lcSortDir)}</th>
            <th class="sortable" on:click={() => lcToggleSort('actorEmail')}>{$t('activity.columns.actor')}{sortIndicator('actorEmail', lcSortCol, lcSortDir)}</th>
          </tr>
        </thead>
        <tbody>
          {#each lcSorted as ev, i (i)}
            <tr class:first-fetch-row={ev.eventType === 'first_fetch'}>
              <td class="nowrap text-muted">{$formatDate(ev.createdAt)}</td>
              <td class="nowrap"><span class="badge {EVENT_COLORS[ev.eventType] || ''}">{ev.eventType}</span></td>
              <td class="mono purl-cell" title={ev.purl ?? ''}>{ev.purl ?? '—'}</td>
              <td class="detail-cell text-muted t-sm" title={ev.detail ?? ''}>{ev.detail ?? ''}</td>
              <td class="actor-cell text-muted">{ev.actorEmail ?? (SYSTEM_EVENTS.has(ev.eventType) ? $t('activity.system') : $t('activity.anonymous'))}</td>
            </tr>
          {/each}
          {#if lcItems.length === 0}
            <tr><td colspan="5" class="text-center text-muted">{$t('activity.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

      <Pagination total={lcTotal} page={lcPage} limit={lcLimit}
        on:pagechange={lcOnPageChange}
        on:limitchange={lcOnLimitChange} />
    {/if}
  {:else}
    {#if adError}<div class="page-error">{adError}</div>{/if}
    {#if adLoading}<span class="spinner"></span>
    {:else}
      <table class="table-auto audit-table">
        <colgroup>
          <col class="col-time">
          <col class="col-action">
          <col class="col-actor">
          <col>
        </colgroup>
        <thead>
          <tr>
            <th>{$t('audit.columns.time')}</th>
            <th>{$t('audit.columns.action')}</th>
            <th>{$t('audit.columns.actor')}</th>
            <th>{$t('audit.columns.detail')}</th>
          </tr>
        </thead>
        <tbody>
          {#each adItems as e (e.id)}
            <tr>
              <td class="nowrap text-muted">{$formatDate(e.createdAt)}</td>
              <td><code>{e.action}</code></td>
              <td class="text-muted">{e.actorEmail ?? e.actorId ?? '—'}</td>
              <td class="audit-detail-cell">{e.detail ?? ''}</td>
            </tr>
          {/each}
          {#if adItems.length === 0}
            <tr><td colspan="4" class="text-center text-muted">{$t('audit.empty')}</td></tr>
          {/if}
        </tbody>
      </table>

      <Pagination total={adTotal} page={adPage} limit={adLimit}
        on:pagechange={adOnPageChange}
        on:limitchange={adOnLimitChange} />
    {/if}
  {/if}
</div>

<style>
  .tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 12px; }
  .tab {
    border: none;
    background: none;
    color: var(--text2);
    padding: 8px 14px;
    font-size: 13px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  .tab-toolbar { display: flex; justify-content: flex-end; margin-bottom: 8px; }

  .first-fetch-row td { background: var(--badge-warning-bg) !important; color: var(--badge-warning-text); }
  .nowrap { white-space: nowrap; }
  .purl-cell { font-size: 12px; overflow-wrap: anywhere; }
  .detail-cell { overflow-wrap: anywhere; }
  .actor-cell { overflow-wrap: anywhere; }
  .event-select { width: auto; }
  .activity-table .col-time   { width: 150px; }
  .activity-table .col-event  { width: 110px; }
  .activity-table .col-detail { width: 200px; }
  .activity-table .col-actor  { width: 180px; }
  :global(.badge.vuln-scan) { background: var(--badge-sky-bg); color: var(--badge-sky-text); }

  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .audit-detail-cell { font-family: var(--font-mono, monospace); font-size: 12px; color: var(--text2); white-space: pre-wrap; word-break: break-word; }
  .audit-table .col-time   { width: 150px; }
  .audit-table .col-action { width: 220px; }
  .audit-table .col-actor  { width: 200px; }
</style>
