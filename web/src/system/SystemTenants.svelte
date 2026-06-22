<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import DataTable from '../lib/DataTable.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Search state lives in the URL query string so it survives route changes,
  // reloads, and copied links.
  const DEFAULTS = { q: '' }
  const init = readQuery(DEFAULTS)

  let tenants = [], loading = true, error = ''
  let showCreate = false
  let newSlug = '', newOwnerEmail = ''
  let createBusy = false
  let createdResult = null  // { tenant, owner: { email, ownerPassword } }

  // Client-side filter on slug. The list endpoint caps at 200 rows so client-side scales fine.
  let searchQuery = init.q

  // Track which tenant row is expanded by id. Only one open at a time.
  let expandedId = null

  function sync() {
    writeQuery({ q: searchQuery }, DEFAULTS)
  }

  // Currently open actions popover (tenant id) — owned here, bound through RowActionsMenu.
  let openActionsId = null

  // Quota editing — null = modal closed; otherwise the tenant currently being edited.
  let quotaEdit = null            // { slug, quotaBytes (number|null), inputValue (string), unit (string) }
  let quotaBusy = false

  // Soft-delete confirm — null = modal closed; otherwise the tenant pending deletion.
  let deleteTarget = null
  let deleteBusy = false

  // Lifecycle gate toggle — null = closed; otherwise { tenant, newStatus: 'active' | 'suspended' }.
  let statusTarget = null
  let statusBusy = false

  async function load() {
    loading = true
    error = ''
    try {
      const data = await systemApi.listTenants(1, 200)
      tenants = data.items
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  async function create() {
    createBusy = true
    error = ''
    try {
      createdResult = await systemApi.createTenant(newSlug, newOwnerEmail)
      newSlug = ''
      newOwnerEmail = ''
      await load()
    } catch (e) { error = e.message }
    finally { createBusy = false }
  }

  function openDelete(ten) {
    openActionsId = null
    deleteTarget = ten
    error = ''
  }

  async function confirmDelete() {
    if (!deleteTarget) return
    const slug = deleteTarget.slug
    deleteBusy = true
    error = ''
    try {
      await systemApi.softDeleteTenant(slug)
      deleteTarget = null
      await load()
    } catch (e) { error = e.message }
    finally { deleteBusy = false }
  }

  async function restore(slug) {
    openActionsId = null
    try {
      await systemApi.restoreTenant(slug)
      await load()
    } catch (e) { error = e.message }
  }

  function openStatusChange(ten, newStatus) {
    openActionsId = null
    statusTarget = { tenant: ten, newStatus }
    error = ''
  }

  async function confirmStatusChange() {
    if (!statusTarget) return
    const { tenant, newStatus } = statusTarget
    statusBusy = true
    error = ''
    try {
      await systemApi.setTenantStatus(tenant.slug, newStatus)
      statusTarget = null
      await load()
    } catch (e) { error = e.message }
    finally { statusBusy = false }
  }

  // ── Row expand/collapse ────────────────────────────────────────────────────

  function toggleExpand(ten, e) {
    // Guard: ignore clicks inside the row-actions wrapper so the actions menu doesn't
    // also collapse the row. RowActionsMenu trigger does not stopPropagation; check by element.
    if (e.target.closest('.row-actions')) return
    expandedId = expandedId === ten.id ? null : ten.id
  }

  function handleExpandKeydown(ten, e) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      expandedId = expandedId === ten.id ? null : ten.id
    }
  }

  // ── Health reason sentences ────────────────────────────────────────────────

  function reasonSentence(reason, stats) {
    switch (reason) {
      case 'suspended': return $t('system.tenants.detail.reasonDetail.suspended')
      case 'storage_quota_exceeded': return $t('system.tenants.detail.reasonDetail.storage_quota_exceeded')
      case 'storage_quota_near': return $t('system.tenants.detail.reasonDetail.storage_quota_near')
      case 'stats_stale': return $t('system.tenants.detail.reasonDetail.stats_stale')
      case 'stats_missing': return $t('system.tenants.detail.reasonDetail.stats_missing')
      case 'quarantine_pending': {
        const count = stats?.quarantinePending ?? 0
        return $t('system.tenants.detail.reasonDetail.quarantine_pending', { values: { count } })
      }
      default: return reason
    }
  }

  // ── Vulnerability summary ───────────────────────────────────────────────────

  // Severity display order for the per-tenant vulnerability summary, highest first.
  const vulnSeverityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

  // Collapse the per-(ecosystem, severity) snapshot rows into one total per severity so the
  // overview shows a single count per category rather than one chip per ecosystem.
  function vulnTotalsBySeverity(stats) {
    const totals = Object.create(null)
    for (const v of stats?.vulnsByEcosystemAndSeverity ?? []) {
      const sev = (v.severity ?? 'UNKNOWN').toUpperCase()
      totals[sev] = (totals[sev] ?? 0) + (v.count ?? 0)
    }
    const ordered = vulnSeverityOrder
      .filter(sev => sev in totals)
      .map(sev => ({ severity: sev, count: totals[sev] }))
    const extra = Object.keys(totals)
      .filter(sev => !vulnSeverityOrder.includes(sev))
      .sort()
      .map(sev => ({ severity: sev, count: totals[sev] }))
    return [...ordered, ...extra]
  }

  // ── Quota helpers ──────────────────────────────────────────────────────────

  // Pick the largest unit the bytes value divides evenly into, so an operator who set
  // 5 GB sees "5 GB" rather than "5368709120 B" round-tripping back through the form.
  function chooseUnit(bytes) {
    if (bytes === null || bytes === undefined) return { value: '', unit: 'GB' }
    const units = [
      { name: 'TB', factor: 1024 ** 4 },
      { name: 'GB', factor: 1024 ** 3 },
      { name: 'MB', factor: 1024 ** 2 },
      { name: 'KB', factor: 1024 },
      { name: 'B',  factor: 1 },
    ]
    for (const u of units) {
      if (bytes >= u.factor && bytes % u.factor === 0) {
        return { value: String(bytes / u.factor), unit: u.name }
      }
    }
    return { value: String(bytes), unit: 'B' }
  }

  function formatQuota(bytes) {
    if (bytes === null || bytes === undefined) return $t('system.tenants.quota.unlimited')
    const { value, unit } = chooseUnit(bytes)
    return `${value} ${unit}`
  }

  // Approximate human-readable bytes for the "Storage used" column. Distinct from
  // formatQuota/chooseUnit because measured usage rarely divides evenly into a unit, so we
  // pick the largest unit >= 1 and round (1 decimal under 10, integer above).
  function fmtBytes(bytes) {
    if (bytes === null || bytes === undefined) return '—'
    if (bytes === 0) return '0 B'
    const units = [
      { name: 'TB', factor: 1024 ** 4 },
      { name: 'GB', factor: 1024 ** 3 },
      { name: 'MB', factor: 1024 ** 2 },
      { name: 'KB', factor: 1024 },
    ]
    for (const u of units) {
      if (bytes >= u.factor) {
        const v = bytes / u.factor
        return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u.name}`
      }
    }
    return `${bytes} B`
  }

  function unitFactor(unit) {
    return { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 }[unit] || 1
  }

  function openQuotaEditor(ten) {
    openActionsId = null
    const display = chooseUnit(ten.storageQuotaBytes)
    quotaEdit = {
      slug: ten.slug,
      quotaBytes: ten.storageQuotaBytes,
      inputValue: display.value,
      unit: display.unit,
    }
  }

  async function saveQuota() {
    if (!quotaEdit) return
    quotaBusy = true
    error = ''
    try {
      // Empty input clears the quota (null = unlimited).
      const raw = quotaEdit.inputValue.trim()
      let payload = null
      if (raw !== '') {
        const n = Number(raw)
        if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
          throw new Error($t('system.tenants.quota.invalid'))
        }
        payload = n * unitFactor(quotaEdit.unit)
      }
      await systemApi.setTenantStorageQuota(quotaEdit.slug, payload)
      quotaEdit = null
      await load()
    } catch (e) { error = e.message }
    finally { quotaBusy = false }
  }

  async function clearQuota() {
    if (!quotaEdit) return
    quotaBusy = true
    error = ''
    try {
      await systemApi.setTenantStorageQuota(quotaEdit.slug, null)
      quotaEdit = null
      await load()
    } catch (e) { error = e.message }
  finally { quotaBusy = false }
  }

  // Soft-deleted overrides the lifecycle status visually — operators see one state per row.
  function effectiveStatus(ten) {
    if (ten.deletedAt) return 'softDeleted'
    return ten.status ?? 'active'
  }

  // ── Table wiring ──────────────────────────────────────────────────────────

  $: filteredTenants = (() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return tenants
    return tenants.filter(t => t.slug?.toLowerCase().includes(q))
  })()

  $: columns = [
    { key: 'expand',  label: '',                                                 sortable: false, width: '28px' },
    { key: 'slug',    label: $t('system.tenants.columns.slug'),    sortable: true },
    { key: 'status',  label: $t('system.tenants.columns.status'),  sortable: true },
    { key: 'health',  label: $t('system.tenants.columns.health'),  sortable: true, width: '90px' },
    { key: 'users',   label: $t('system.tenants.columns.users'),   sortable: true, width: '90px' },
    { key: 'storage', label: $t('system.tenants.columns.storage'), sortable: true, width: '110px' },
    { key: 'quota',   label: $t('system.tenants.columns.quota'),   sortable: false, width: '140px' },
    { key: 'created', label: $t('system.tenants.columns.created'), sortable: true, width: '120px' },
    { key: 'deleted', label: $t('system.tenants.columns.deleted'), sortable: true, width: '120px' },
    { key: 'actions', label: '', sortable: false, width: '52px' },
  ]

  // Push nulls to the end regardless of direction so unset values don't crowd the top half.
  const dateAsc = (a, b) => {
    const ta = a ? new Date(a).getTime() : Number.POSITIVE_INFINITY
    const tb = b ? new Date(b).getTime() : Number.POSITIVE_INFINITY
    return ta - tb
  }

  // Health sort: critical > warn > ok. Higher severity ranks first descending.
  function healthRank(ten) {
    const s = ten.health?.status ?? 'ok'
    if (s === 'critical') return 2
    if (s === 'warn') return 1
    return 0
  }

  // Build a readable title for the health dot from the reasons list.
  function healthTitle(ten) {
    const reasons = ten.health?.reasons ?? []
    if (reasons.length === 0) return $t('system.tenants.health.ok')
    return reasons
      .map(r => $t(`system.tenants.health.reasons.${r}`, { default: r }))
      .join(', ')
  }

  const comparators = {
    slug:    (a, b) => (a.slug ?? '').localeCompare(b.slug ?? ''),
    status:  (a, b) => effectiveStatus(a).localeCompare(effectiveStatus(b)),
    health:  (a, b) => healthRank(a) - healthRank(b),
    users:   (a, b) => (a.memberCount ?? 0) - (b.memberCount ?? 0),
    storage: (a, b) => (a.storageBytes ?? 0) - (b.storageBytes ?? 0),
    created: (a, b) => dateAsc(a.createdAt, b.createdAt),
    deleted: (a, b) => dateAsc(a.deletedAt, b.deletedAt),
  }
</script>

<div class="page">
  <div class="page-header">
    <h1>{$t('system.tenants.title')}</h1>
    <button class="primary" on:click={() => { showCreate = true; createdResult = null }}>{$t('system.tenants.newTenant')}</button>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}

  <div class="toolbar">
    <SearchInput
      class="table-search"
      placeholder={$t('system.tenants.searchPlaceholder')}
        ariaLabel={$t('system.tenants.searchPlaceholder')}
      bind:value={searchQuery}
      on:search={sync}
    />
  </div>

  <DataTable
    {columns}
    {comparators}
    rows={filteredTenants}
    {loading}
    initialSort={{ key: 'created', dir: 'desc' }}
    emptyText={$t('system.tenants.empty')}
    tableClass="table-auto tenants-table"
    let:row={ten}
  >
    <!-- Main data row -->
    <tr
      class:deleted={ten.deletedAt}
      class:expandable-row={true}
      class:expanded={expandedId === ten.id}
      on:click={(e) => toggleExpand(ten, e)}
      tabindex="0"
      aria-expanded={expandedId === ten.id}
      on:keydown={(e) => handleExpandKeydown(ten, e)}
    >
      <!-- Chevron affordance column -->
      <td class="chevron-cell" aria-hidden="true">
        <svg class="chevron-icon" class:open={expandedId === ten.id}
             width="12" height="12" aria-hidden="true">
          <use href="/icons.svg#icon-chevron-down"/>
        </svg>
      </td>
      <td><strong>{ten.slug}</strong></td>
      <td>
        {#if effectiveStatus(ten) === 'softDeleted'}
          <span class="status-pill status-softDeleted">{$t('system.tenants.status.softDeleted')}</span>
        {:else if effectiveStatus(ten) === 'suspended'}
          <span class="status-pill status-suspended">{$t('system.tenants.status.suspended')}</span>
        {:else}
          <span class="status-pill status-active">{$t('system.tenants.status.active')}</span>
        {/if}
      </td>
      <td>
        <span class="health-dot health-dot-{ten.health?.status ?? 'ok'}"
              title={healthTitle(ten)}></span>
      </td>
      <td class="num">{ten.memberCount ?? 0}</td>
      <td class="num">{fmtBytes(ten.storageBytes ?? 0)}</td>
      <td><span class="quota">{formatQuota(ten.storageQuotaBytes)}</span></td>
      <td>{new Date(ten.createdAt).toLocaleDateString()}</td>
      <td>{ten.deletedAt ? new Date(ten.deletedAt).toLocaleDateString() : '—'}</td>
      <td class="actions-cell">
        <div class="row-actions">
          <RowActionsMenu id={ten.id} bind:openId={openActionsId} ariaLabel={$t('system.tenants.actionsMenu.open')}>
            {#if ten.deletedAt}
              <button class="popover-item" on:click|stopPropagation={() => restore(ten.slug)}>
                {$t('system.tenants.actionsMenu.restore')}
              </button>
            {:else}
              <button class="popover-item" on:click|stopPropagation={() => openQuotaEditor(ten)}>
                {$t('system.tenants.actionsMenu.editQuota')}
              </button>
              {#if ten.status === 'suspended'}
                <button class="popover-item" on:click|stopPropagation={() => openStatusChange(ten, 'active')}>
                  {$t('system.tenants.actionsMenu.enable')}
                </button>
              {:else}
                <button class="popover-item" on:click|stopPropagation={() => openStatusChange(ten, 'suspended')}>
                  {$t('system.tenants.actionsMenu.disable')}
                </button>
              {/if}
              <div class="popover-divider"></div>
              <button class="popover-item danger" on:click|stopPropagation={() => openDelete(ten)}>
                {$t('system.tenants.actionsMenu.delete')}
              </button>
            {/if}
          </RowActionsMenu>
        </div>
      </td>
    </tr>

    <!-- Detail expansion row — rendered in the same slot, conditionally shown -->
    {#if expandedId === ten.id}
      <tr class="detail-row">
        <td colspan={columns.length}>
          <div class="detail-panel">
            <!-- Health breakdown in plain language -->
            <div class="detail-section">
              <div class="detail-section-title">{$t('system.tenants.detail.sectionHealth')}</div>
              {#if (ten.health?.reasons ?? []).length === 0}
                <p class="detail-ok">{$t('system.tenants.detail.healthOk')}</p>
              {:else}
                <ul class="reason-list">
                  {#each ten.health.reasons as reason (reason)}
                    <li>
                      <span class="health-dot health-dot-{ten.health.status}"></span>
                      {reasonSentence(reason, ten.stats)}
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>

            <!-- Core facts -->
            <div class="detail-section">
              <div class="detail-section-title">{$t('system.tenants.detail.sectionInventory')}</div>
              <dl class="detail-dl">
                <dt>{$t('system.tenants.detail.status')}</dt>
                <dd>
                  {#if effectiveStatus(ten) === 'softDeleted'}
                    <span class="status-pill status-softDeleted">{$t('system.tenants.status.softDeleted')}</span>
                  {:else if effectiveStatus(ten) === 'suspended'}
                    <span class="status-pill status-suspended">{$t('system.tenants.status.suspended')}</span>
                  {:else}
                    <span class="status-pill status-active">{$t('system.tenants.status.active')}</span>
                  {/if}
                </dd>
                <dt>{$t('system.tenants.detail.members')}</dt>
                <dd>{ten.memberCount ?? 0}</dd>
                <dt>{$t('system.tenants.detail.created')}</dt>
                <dd>{new Date(ten.createdAt).toLocaleString()}</dd>
                {#if ten.deletedAt}
                  <dt>{$t('system.tenants.detail.deleted')}</dt>
                  <dd>{new Date(ten.deletedAt).toLocaleString()}</dd>
                {/if}
                <dt>{$t('system.tenants.columns.storage')}</dt>
                <dd>
                  {#if ten.storageQuotaBytes}
                    {$t('system.tenants.detail.storagePct', {
                      values: {
                        used: fmtBytes(ten.storageBytes ?? 0),
                        quota: formatQuota(ten.storageQuotaBytes),
                        pct: ten.storageQuotaBytes > 0
                          ? Math.round((ten.storageBytes / ten.storageQuotaBytes) * 100)
                          : 0
                      }
                    })}
                  {:else}
                    {$t('system.tenants.detail.storageUnlimited', { values: { used: fmtBytes(ten.storageBytes ?? 0) } })}
                  {/if}
                </dd>
              </dl>
            </div>

            <!-- Stats from snapshot: inventory + activity -->
            {#if ten.stats}
              <div class="detail-section">
                <div class="detail-section-title">{$t('system.tenants.detail.sectionActivity')}</div>
                <dl class="detail-dl">
                  <dt>{$t('system.tenants.detail.downloads30d')
                    .replace('{count}', '')
                    .replace(',', '')
                    .trim()}</dt>
                  <dd>{ten.stats.totalDownloads30d ?? 0}</dd>
                  {#if (ten.stats.quarantinePending ?? 0) > 0}
                    <dt>{$t('system.tenants.columns.health')}</dt>
                    <dd class="warn-text">
                      {$t('system.tenants.detail.quarantinePending', { values: { count: ten.stats.quarantinePending } })}
                    </dd>
                  {/if}
                </dl>
              </div>

              {#if (ten.stats.packagesByEcosystem ?? []).length > 0}
                <div class="detail-section">
                  <div class="detail-section-title">{$t('system.tenants.detail.sectionInventory')} — packages</div>
                  <div class="eco-chips">
                    {#each ten.stats.packagesByEcosystem as e (e.ecosystem)}
                      <span class="eco-chip">{e.ecosystem}: {e.count}</span>
                    {/each}
                  </div>
                </div>
              {/if}

              {#if (ten.stats.diskByEcosystem ?? []).length > 0}
                <div class="detail-section">
                  <div class="detail-section-title">{$t('system.tenants.detail.sectionStorage')}</div>
                  <div class="eco-chips">
                    {#each ten.stats.diskByEcosystem as e (e.ecosystem)}
                      <span class="eco-chip">{e.ecosystem}: {fmtBytes(e.totalBytes)}</span>
                    {/each}
                  </div>
                </div>
              {/if}

              {#if (ten.stats.vulnsByEcosystemAndSeverity ?? []).length > 0}
                <div class="detail-section">
                  <div class="detail-section-title">Vulnerabilities</div>
                  <div class="eco-chips">
                    {#each vulnTotalsBySeverity(ten.stats) as v (v.severity)}
                      <span class="eco-chip vuln-chip-{v.severity.toLowerCase()}">{v.severity}: {v.count}</span>
                    {/each}
                  </div>
                </div>
              {/if}
            {:else}
              <p class="detail-no-stats muted">{$t('system.tenants.detail.noStats')}</p>
            {/if}
          </div>
        </td>
      </tr>
    {/if}
  </DataTable>
</div>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      {#if createdResult}
        <h3>{$t('system.tenants.created.title')}</h3>
        <p><strong>{$t('system.tenants.created.warning')}</strong></p>
        <dl>
          <dt>{$t('system.tenants.created.tenantSlug')}</dt><dd>{createdResult.tenant.slug}</dd>
          <dt>{$t('system.tenants.created.ownerEmail')}</dt><dd>{createdResult.owner.email}</dd>
          <dt>{$t('system.tenants.created.ownerPassword')}</dt><dd><code>{createdResult.owner.ownerPassword}</code></dd>
        </dl>
        <div class="modal-actions">
          <button class="primary" on:click={() => { showCreate = false; createdResult = null }}>{$t('system.tenants.created.done')}</button>
        </div>
      {:else}
        <h3>{$t('system.tenants.modal.title')}</h3>
        <div class="form-row">
          <label>{$t('system.tenants.modal.slug')}</label>
          <input bind:value={newSlug} placeholder={$t('system.tenants.modal.slugPlaceholder')} />
        </div>
        <div class="form-row">
          <label>{$t('system.tenants.modal.ownerEmail')}</label>
          <input type="email" bind:value={newOwnerEmail} placeholder={$t('system.tenants.modal.ownerEmailPlaceholder')} />
        </div>
        <div class="modal-actions">
          <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
          <button class="primary" on:click={create} disabled={createBusy || !newSlug || !newOwnerEmail}>
            {createBusy ? $t('system.tenants.modal.creating') : $t('system.tenants.modal.create')}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if quotaEdit}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.tenants.quota.modalTitle', { values: { slug: quotaEdit.slug } })}</h3>
      <p class="text-muted">{$t('system.tenants.quota.modalHint')}</p>
      <div class="form-row quota-row">
        <label>{$t('system.tenants.quota.label')}</label>
        <div class="quota-inputs">
          <input type="number" min="1" step="1" bind:value={quotaEdit.inputValue}
                 placeholder={$t('system.tenants.quota.placeholder')} />
          <select bind:value={quotaEdit.unit}>
            <option value="B">B</option>
            <option value="KB">KB</option>
            <option value="MB">MB</option>
            <option value="GB">GB</option>
            <option value="TB">TB</option>
          </select>
        </div>
      </div>
      <div class="modal-actions">
        <button on:click={() => quotaEdit = null} disabled={quotaBusy}>
          {$t('common.actions.cancel')}
        </button>
        {#if quotaEdit.quotaBytes !== null && quotaEdit.quotaBytes !== undefined}
          <button class="danger" on:click={clearQuota} disabled={quotaBusy}>
            {$t('system.tenants.quota.clear')}
          </button>
        {/if}
        <button class="primary" on:click={saveQuota} disabled={quotaBusy}>
          {quotaBusy ? $t('system.tenants.quota.saving') : $t('system.tenants.quota.save')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if deleteTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.tenants.deleteModalTitle')}</h3>
      <p>{$t('system.tenants.deleteConfirm', { values: { slug: deleteTarget.slug } })}</p>
      <div class="modal-actions">
        <button on:click={() => deleteTarget = null} disabled={deleteBusy}>{$t('common.actions.cancel')}</button>
        <button class="danger" on:click={confirmDelete} disabled={deleteBusy}>
          {deleteBusy ? $t('common.actions.saving') : $t('system.tenants.delete')}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if statusTarget}
  <div class="modal-backdrop">
    <div class="modal">
      {#if statusTarget.newStatus === 'suspended'}
        <h3>{$t('system.tenants.disableModalTitle')}</h3>
        <p>{$t('system.tenants.disableConfirm', { values: { slug: statusTarget.tenant.slug } })}</p>
      {:else}
        <h3>{$t('system.tenants.enableModalTitle')}</h3>
        <p>{$t('system.tenants.enableConfirm', { values: { slug: statusTarget.tenant.slug } })}</p>
      {/if}
      <div class="modal-actions">
        <button on:click={() => statusTarget = null} disabled={statusBusy}>{$t('common.actions.cancel')}</button>
        <button class={statusTarget.newStatus === 'suspended' ? 'danger' : 'primary'}
                on:click={confirmStatusChange} disabled={statusBusy}>
          {#if statusBusy}{$t('system.tenants.statusUpdating')}
          {:else if statusTarget.newStatus === 'suspended'}{$t('system.tenants.actionsMenu.disable')}
          {:else}{$t('system.tenants.actionsMenu.enable')}
          {/if}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  /* Toolbar proportions: override the global `input { width: 100% }` rule so the search input
     doesn't span the whole row. Pattern mirrored from SystemAudit / SystemAdmins. */
  .toolbar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }
  .toolbar :global(.table-search) {
    flex: 1 1 240px; min-width: 200px; max-width: 360px;
  }
  .toolbar :global(.table-search input) { font-size: 13px; }
  tr.deleted { color: var(--text2); }
  /* Wrap row buttons in a flex container — never put display:flex on the <td> itself
     (breaks the row's border-bottom alignment). Pattern copied from web/src/pages/Users.svelte. */
  .row-actions { display: flex; gap: 6px; align-items: center; justify-content: flex-end; }
  .actions-cell { text-align: right; }
  .quota { font-variant-numeric: tabular-nums; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }

  /* Expandable row interaction */
  .expandable-row { cursor: pointer; }
  .expandable-row:hover { background: var(--bg); }
  .expandable-row:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

  .chevron-cell { padding-right: 2px; }
  .chevron-icon {
    display: inline-block;
    transition: transform 0.15s ease;
    color: var(--text2);
  }
  .chevron-icon.open { transform: rotate(180deg); }

  /* Detail expansion row */
  .detail-row { background: var(--bg); }
  .detail-row td { padding: 0; border-bottom: 1px solid var(--border); }
  .detail-panel {
    padding: 12px 20px 16px 36px;
    display: flex;
    flex-wrap: wrap;
    gap: 16px 32px;
  }

  .detail-section { flex: 0 0 auto; min-width: 180px; }
  .detail-section-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text2);
    margin-bottom: 6px;
  }

  .detail-dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 10px;
    font-size: 12px;
  }
  .detail-dl dt { color: var(--text2); }
  .detail-dl dd { margin: 0; }

  .detail-ok { font-size: 13px; color: var(--success); margin: 0; }
  .detail-no-stats { font-size: 12px; margin: 0; }
  .warn-text { color: var(--warning); }

  .reason-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
  }
  .reason-list li { display: flex; align-items: center; gap: 6px; }

  .eco-chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .eco-chip {
    display: inline-block;
    font-size: 11px;
    padding: 2px 7px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg2);
  }
  .vuln-chip-critical { color: var(--danger); border-color: var(--danger); }
  .vuln-chip-high { color: var(--warning); border-color: var(--warning); }
  .vuln-chip-medium { color: var(--info); border-color: var(--info); }
  .vuln-chip-low { color: var(--text2); border-color: var(--text2); }
  .vuln-chip-unknown { color: var(--text2); border-color: var(--text2); }

  .status-pill {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg);
    font-size: 11px;
    line-height: 18px;
    font-weight: 500;
    text-transform: capitalize;
  }
  .status-pill.status-active { color: var(--success); }
  .status-pill.status-suspended { color: var(--warning); }
  .status-pill.status-softDeleted { color: var(--text2); }

  .health-dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--border);
    vertical-align: middle;
    flex-shrink: 0;
  }
  .health-dot.health-dot-ok { background: var(--success); }
  .health-dot.health-dot-warn { background: var(--warning); }
  .health-dot.health-dot-critical { background: var(--danger); }

  .modal-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-scrim);
    display: flex; align-items: center; justify-content: center;
    z-index: 100;
  }
  .modal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    width: 400px;
  }
  .form-row { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
  .form-row label { font-size: 13px; color: var(--text2); }
  .form-row input {
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  .quota-inputs { display: flex; gap: 6px; align-items: stretch; }
  .quota-inputs input { flex: 1 1 auto; width: auto; min-width: 0; }
  .quota-inputs select { flex: 0 0 auto; width: 90px; }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }
  dt { font-weight: 600; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; }
</style>
