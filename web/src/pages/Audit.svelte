<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg } from '../lib/store.js'
  import { formatDate } from '../lib/format.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'

  // Tab state — Lifecycle (activity feed) is the default; Admin actions (audit_log) loads when its tab is selected.
  let activeTab = 'lifecycle'

  // ── Lifecycle tab (activity) ─────────────────────────────────────────────
  let lcItems = [], lcLoading = true, lcError = ''
  let lcFilterType = ''
  let lcPage = 1, lcLimit = 50, lcTotal = 0

  $: lcColumns = [
    { key: 'createdAt',  label: $t('activity.columns.time'),   sortable: true, defaultDir: 'desc', width: '150px' },
    { key: 'eventType',  label: $t('activity.columns.event'),  sortable: true, width: '110px' },
    { key: 'purl',       label: $t('activity.columns.purl'),   sortable: true },
    { key: 'detail',     label: $t('activity.columns.detail'), sortable: true, width: '200px' },
    { key: 'actorEmail', label: $t('activity.columns.actor'),  sortable: true, width: '180px' },
  ]

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

  async function lcExport() {
    try {
      const p = {}
      if (lcFilterType) p.event_type = lcFilterType
      await api.exportActivity(p)
    } catch (e) { lcError = e.message }
  }
  async function adExport() {
    try {
      const p = {}
      if (adFilterAction) p.action = adFilterAction
      await api.exportAudit(p)
    } catch (e) { adError = e.message }
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
  let adFilterAction = ''
  let adPage = 1, adLimit = 50, adTotal = 0

  // Tenant audit actions, grouped for the filter dropdown. Backend uses exact-match
  // filtering on the action column at scope='tenant'; system-scope actions
  // (tenant.created, system_admin.*, instance_settings_updated) are deliberately
  // excluded because ListAuditAsync filters them out and they'd be dead options.
  // Mirrors the catalogue tracked in en.json#audit.actions / en.json#audit.groups.
  const TENANT_AUDIT_ACTION_GROUPS = [
    { labelKey: 'audit.groups.tenantConfig', actions: ['org_settings_updated', 'retention_updated', 'proxy_settings_updated', 'tenant.setting.change'] },
    { labelKey: 'audit.groups.auth',         actions: ['login.success', 'login.failure', 'lockout.triggered', 'user.password_changed', 'user.language_changed'] },
    { labelKey: 'audit.groups.saml',         actions: ['saml.config_updated', 'saml.metadata_uploaded', 'saml.config_deleted', 'auth.saml.login.success', 'auth.saml.login.failure', 'auth.saml.user_linked', 'auth.saml.user_provisioned', 'auth.saml.test.success'] },
    { labelKey: 'audit.groups.tokens',       actions: ['token_created', 'token_revoked', 'cicd_token_created', 'cicd_token_revoked'] },
    { labelKey: 'audit.groups.usersInvites', actions: ['member_role_changed', 'member_removed', 'invite_created', 'invite_deleted'] },
    { labelKey: 'audit.groups.lists',        actions: ['allowlist_added', 'allowlist_removed', 'blocklist_added', 'blocklist_removed'] },
    { labelKey: 'audit.groups.licenses',     actions: ['license_policy_mode_changed', 'license_allowlist_added', 'license_allowlist_removed', 'license_blocklist_added', 'license_blocklist_removed'] },
    { labelKey: 'audit.groups.claims',       actions: ['claim.create', 'claim.transition', 'claim.release'] },
    { labelKey: 'audit.groups.supplyChain',  actions: ['package.replace', 'allowlist_blocked', 'conflict_resolved'] },
    { labelKey: 'audit.groups.upstream',     actions: ['upstream_response_too_large', 'ssrf_blocked', 'checksum_failure'] },
  ]

  $: adColumns = [
    { key: 'createdAt',  label: $t('audit.columns.time'),   sortable: true, defaultDir: 'desc', width: '150px' },
    { key: 'action',     label: $t('audit.columns.action'), sortable: true, width: '220px' },
    { key: 'actorEmail', label: $t('audit.columns.actor'),  sortable: true, width: '200px' },
    { key: 'detail',     label: $t('audit.columns.detail'), sortable: true },
  ]

  async function loadAdmin() {
    adLoading = true
    adError = ''
    try {
      const p = { page: adPage, limit: adLimit }
      if (adFilterAction) p.action = adFilterAction
      const data = await api.getAudit(p)
      adItems = data.items
      adTotal = data.total
    } catch (e) { adError = e.message }
    finally { adLoading = false }
  }

  function adOnPageChange(e) { adPage = e.detail.page; loadAdmin() }
  function adOnLimitChange(e) { adLimit = e.detail.limit; adPage = 1; loadAdmin() }
  function adOnFilterChange() { adPage = 1; loadAdmin() }

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
        <option value="import">{$t('activity.events.import')}</option>
        <option value="download">{$t('activity.events.download')}</option>
        <option value="vuln_scan">{$t('activity.events.vulnScan')}</option>
        <option value="vuln_scan_pass">{$t('activity.events.vulnScanPass')}</option>
        <option value="vuln_rescan_pass">{$t('activity.events.vulnRescanPass')}</option>
        <option value="delete">{$t('activity.events.delete')}</option>
        <option value="manual_block">{$t('activity.events.manualBlock')}</option>
        <option value="manual_unblock">{$t('activity.events.manualUnblock')}</option>
        <option value="blocked">{$t('activity.events.blocked')}</option>
        <option value="blocked_manual">{$t('activity.events.blockedManual')}</option>
        <option value="blocked_vuln_score">{$t('activity.events.blockedVulnScore')}</option>
        <option value="login.success">{$t('activity.events.loginSuccess')}</option>
        <option value="login.failure">{$t('activity.events.loginFailure')}</option>
        <option value="login.locked">{$t('activity.events.loginLocked')}</option>
      </select>
      <button type="button" class="btn btn-secondary" on:click={lcExport}>{$t('activity.export')}</button>
    </div>

    <ErrorBanner message={lcError} />
    <DataTable
      columns={lcColumns}
      rows={lcItems}
      loading={lcLoading}
      initialSort={{ key: 'createdAt', dir: 'desc' }}
      emptyText={$t('activity.empty')}
      tableClass="table-auto activity-table"
      let:row={ev}
    >
      <tr class:first-fetch-row={ev.eventType === 'first_fetch'}>
        <td class="nowrap text-muted">{$formatDate(ev.createdAt)}</td>
        <td class="nowrap"><span class="badge {EVENT_COLORS[ev.eventType] || ''}">{ev.eventType}</span></td>
        <td class="mono purl-cell" title={ev.purl ?? ''}>{ev.purl ?? '—'}</td>
        <td class="detail-cell text-muted t-sm" title={ev.detail ?? ''}>
          {#if ev.detail && ev.sourceIp}{ev.detail} · {ev.sourceIp}
          {:else if ev.detail}{ev.detail}
          {:else if ev.sourceIp}{ev.sourceIp}
          {/if}
        </td>
        <td class="actor-cell text-muted">{ev.actorEmail ?? (SYSTEM_EVENTS.has(ev.eventType) ? $t('activity.system') : $t('activity.anonymous'))}</td>
      </tr>
    </DataTable>

    {#if !lcLoading}
      <Pagination total={lcTotal} page={lcPage} limit={lcLimit}
        on:pagechange={lcOnPageChange}
        on:limitchange={lcOnLimitChange} />
    {/if}
  {:else}
    <div class="tab-toolbar">
      <select bind:value={adFilterAction} on:change={adOnFilterChange} class="event-select">
        <option value="">{$t('audit.allActions')}</option>
        {#each TENANT_AUDIT_ACTION_GROUPS as g (g.labelKey)}
          <optgroup label={$t(g.labelKey)}>
            {#each g.actions as a (a)}
              <option value={a}>{$t(`audit.actions.${a}`)}</option>
            {/each}
          </optgroup>
        {/each}
      </select>
      <button type="button" class="btn btn-secondary" on:click={adExport}>{$t('audit.export')}</button>
    </div>

    <ErrorBanner message={adError} />
    <DataTable
      columns={adColumns}
      rows={adItems}
      loading={adLoading}
      initialSort={{ key: 'createdAt', dir: 'desc' }}
      emptyText={$t('audit.empty')}
      tableClass="table-auto audit-table"
      let:row={e}
    >
      <tr>
        <td class="nowrap text-muted">{$formatDate(e.createdAt)}</td>
        <td><code>{e.action}</code></td>
        <td class="text-muted">{e.actorEmail ?? e.actorId ?? '—'}</td>
        <td class="audit-detail-cell">{e.detail ?? ''}</td>
      </tr>
    </DataTable>

    {#if !adLoading}
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

  .tab-toolbar { display: flex; justify-content: flex-end; gap: 8px; margin-bottom: 8px; }

  .first-fetch-row td { background: var(--badge-warning-bg) !important; color: var(--badge-warning-text); }
  .nowrap { white-space: nowrap; }
  .purl-cell { font-size: 12px; overflow-wrap: anywhere; }
  .detail-cell { overflow-wrap: anywhere; }
  .actor-cell { overflow-wrap: anywhere; }
  .event-select { width: auto; }
  :global(.badge.vuln-scan) { background: var(--badge-sky-bg); color: var(--badge-sky-text); }

  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .audit-detail-cell { font-family: var(--font-mono, monospace); font-size: 12px; color: var(--text2); white-space: pre-wrap; word-break: break-word; }
</style>
