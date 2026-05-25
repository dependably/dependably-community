<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import DataTable from '../lib/DataTable.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'

  let tenants = [], loading = true, error = ''
  let showCreate = false
  let newSlug = '', newOwnerEmail = ''
  let createBusy = false
  let createdResult = null  // { tenant, owner: { email, ownerPassword } }

  // Client-side filter on slug. The list endpoint caps at 200 rows so client-side scales fine.
  let searchQuery = ''

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
  // pick the largest unit ≥ 1 and round (1 decimal under 10, integer above).
  function formatBytes(bytes) {
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
    { key: 'slug',    label: $t('system.tenants.columns.slug'),    sortable: true },
    { key: 'status',  label: $t('system.tenants.columns.status'),  sortable: true },
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

  const comparators = {
    slug:    (a, b) => (a.slug ?? '').localeCompare(b.slug ?? ''),
    status:  (a, b) => effectiveStatus(a).localeCompare(effectiveStatus(b)),
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
    <input
      type="search"
      class="table-search"
      placeholder={$t('system.tenants.searchPlaceholder')}
      bind:value={searchQuery}
      aria-label={$t('system.tenants.searchPlaceholder')}
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
    <tr class:deleted={ten.deletedAt}>
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
      <td class="num">{ten.memberCount ?? 0}</td>
      <td class="num">{formatBytes(ten.storageBytes ?? 0)}</td>
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
  .table-search {
    flex: 1 1 240px; min-width: 200px; max-width: 360px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
  }
  tr.deleted { color: var(--text2); }
  /* Wrap row buttons in a flex container — never put display:flex on the <td> itself
     (breaks the row's border-bottom alignment). Pattern copied from web/src/pages/Users.svelte. */
  .row-actions { display: flex; gap: 6px; align-items: center; justify-content: flex-end; }
  .actions-cell { text-align: right; }
  .quota { font-variant-numeric: tabular-nums; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }

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
