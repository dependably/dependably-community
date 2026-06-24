<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { user } from '../lib/store.js'
  import { extractErrorMessage } from '../lib/form.js'
  import DataTable from '../lib/DataTable.svelte'

  // ── State ────────────────────────────────────────────────────────────────
  let admins = []
  let loading = true
  let error = ''
  let searchQuery = ''

  let createOpen = false
  let createEmail = ''
  let createBusy = false
  let createError = ''

  let statusTarget = null      // { id, email, accountStatus }
  let statusNew = ''
  let statusBusy = false
  let statusError = ''

  let resetTarget = null
  let resetBusy = false
  let resetError = ''

  let deleteTarget = null
  let deleteBusy = false
  let deleteError = ''

  // Shared by Create and Reset success paths.
  let tempPasswordReveal = null  // { email, password, issuedAt }
  let tempCopied = false

  $: meId = $user?.id ?? null
  $: totalActiveCount = admins.filter(a => a.accountStatus === 'active').length

  // ── Error mapping ────────────────────────────────────────────────────────
  // Backend returns ProblemDetails with `reason` extension on guard rejections.
  // Translate the reason to a localized string; fall back to the raw detail.
  function mapError(e) {
    const reason = e?.body?.reason
    if (reason && knownReasons.has(reason)) return $t(`system.admins.errors.${reason}`)
    return extractErrorMessage(e)
  }
  const knownReasons = new Set([
    'cannot_modify_self',
    'last_active_admin',
    'must_disable_first',
    'duplicate_email',
  ])

  // ── Loading ──────────────────────────────────────────────────────────────
  async function load() {
    loading = true
    error = ''
    try {
      admins = await systemApi.listAdmins()
    } catch (e) {
      error = mapError(e)
    } finally {
      loading = false
    }
  }

  onMount(load)

  // ── Create ───────────────────────────────────────────────────────────────
  function openCreate() {
    createEmail = ''
    createError = ''
    createOpen = true
  }

  async function submitCreate() {
    if (!createEmail.trim()) return
    createBusy = true
    createError = ''
    try {
      const result = await systemApi.createAdmin(createEmail.trim())
      createOpen = false
      tempPasswordReveal = {
        email: result.email,
        password: result.temporaryPassword,
        issuedAt: result.issuedAt,
      }
      tempCopied = false
      await load()
    } catch (e) {
      createError = mapError(e)
    } finally {
      createBusy = false
    }
  }

  // ── Status change ────────────────────────────────────────────────────────
  function pickStatus(row, newStatus) {
    if (newStatus === row.accountStatus) return
    // Activating is non-destructive; skip the confirm modal.
    if (newStatus === 'active') {
      void applyStatus(row, newStatus)
      return
    }
    statusTarget = row
    statusNew = newStatus
    statusError = ''
  }

  async function applyStatus(row, newStatus) {
    error = ''
    try {
      await systemApi.setAdminAccountStatus(row.id, newStatus)
      await load()
    } catch (e) {
      error = mapError(e)
    }
  }

  async function confirmStatus() {
    if (!statusTarget) return
    statusBusy = true
    statusError = ''
    try {
      await systemApi.setAdminAccountStatus(statusTarget.id, statusNew)
      statusTarget = null
      statusNew = ''
      await load()
    } catch (e) {
      statusError = mapError(e)
    } finally {
      statusBusy = false
    }
  }

  // ── Reset password ───────────────────────────────────────────────────────
  function openReset(row) {
    resetTarget = row
    resetError = ''
  }

  async function confirmReset() {
    if (!resetTarget) return
    resetBusy = true
    resetError = ''
    try {
      const result = await systemApi.resetAdminPassword(resetTarget.id)
      const target = resetTarget
      resetTarget = null
      tempPasswordReveal = {
        email: result.email ?? target.email,
        password: result.temporaryPassword,
        issuedAt: result.issuedAt,
      }
      tempCopied = false
      await load()
    } catch (e) {
      resetError = mapError(e)
    } finally {
      resetBusy = false
    }
  }

  // ── Delete ───────────────────────────────────────────────────────────────
  function openDelete(row) {
    deleteTarget = row
    deleteError = ''
  }

  async function confirmDelete() {
    if (!deleteTarget) return
    deleteBusy = true
    deleteError = ''
    try {
      await systemApi.deleteAdmin(deleteTarget.id)
      deleteTarget = null
      await load()
    } catch (e) {
      deleteError = mapError(e)
    } finally {
      deleteBusy = false
    }
  }

  // ── Temp-password modal ──────────────────────────────────────────────────
  async function copyTemp() {
    if (!tempPasswordReveal) return
    try {
      await navigator.clipboard.writeText(tempPasswordReveal.password)
      tempCopied = true
    } catch {
      // Clipboard may be unavailable (e.g. HTTP without secure context); leave
      // the password visible so the operator can still select it manually.
    }
  }

  function dismissTemp() {
    tempPasswordReveal = null
    tempCopied = false
  }

  // ── Derived row UX ───────────────────────────────────────────────────────
  function statusOptions(row) {
    // Disable non-active options for the last active admin (last-active guard).
    const isLastActive = row.accountStatus === 'active' && totalActiveCount === 1
    return [
      { value: 'active',   disabled: false },
      { value: 'locked',   disabled: isLastActive },
      { value: 'disabled', disabled: isLastActive },
    ]
  }

  function fmtDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  // ── Table wiring ─────────────────────────────────────────────────────────
  $: filteredAdmins = (() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return admins
    return admins.filter(a => a.email?.toLowerCase().includes(q))
  })()

  $: columns = [
    { key: 'email',         label: $t('system.admins.columns.email'),         sortable: true },
    { key: 'status',        label: $t('system.admins.columns.status'),        sortable: true, width: '160px' },
    { key: 'mfa',           label: $t('system.admins.columns.mfa'),           sortable: true, width: '60px' },
    { key: 'lastLogin',     label: $t('system.admins.columns.lastLogin'),     sortable: true, width: '180px' },
    { key: 'passwordReset', label: $t('system.admins.columns.passwordReset'), sortable: true, width: '180px' },
    { key: 'created',       label: $t('system.admins.columns.created'),       sortable: true, width: '180px' },
    { key: 'actions',       label: $t('system.admins.columns.actions'),       sortable: false, width: '220px' },
  ]

  const dateAsc = (a, b) => {
    const ta = a ? new Date(a).getTime() : Number.POSITIVE_INFINITY
    const tb = b ? new Date(b).getTime() : Number.POSITIVE_INFINITY
    return ta - tb
  }

  const comparators = {
    email:         (a, b) => (a.email ?? '').localeCompare(b.email ?? ''),
    status:        (a, b) => (a.accountStatus ?? '').localeCompare(b.accountStatus ?? ''),
    mfa:           (a, b) => (a.mfaEnabled ? 1 : 0) - (b.mfaEnabled ? 1 : 0),
    lastLogin:     (a, b) => dateAsc(a.lastLoginAt, b.lastLoginAt),
    passwordReset: (a, b) => dateAsc(a.passwordResetIssuedAt, b.passwordResetIssuedAt),
    created:       (a, b) => dateAsc(a.createdAt, b.createdAt),
  }
</script>

<div class="page">
  <div class="page-header">
    <div>
      <h1>{$t('system.admins.title')}</h1>
      <p class="subtitle">{$t('system.admins.description')}</p>
    </div>
    <button class="primary" on:click={openCreate}>{$t('system.admins.create.button')}</button>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}

  <div class="toolbar">
    <input
      type="search"
      class="table-search"
      placeholder={$t('system.admins.searchPlaceholder')}
      bind:value={searchQuery}
      aria-label={$t('system.admins.searchPlaceholder')}
    />
  </div>

  <DataTable
    {columns}
    {comparators}
    rows={filteredAdmins}
    {loading}
    initialSort={{ key: 'email', dir: 'asc' }}
    emptyText={$t('system.admins.empty')}
    tableClass="table-auto admins-table"
    let:row={admin}
  >
    {@const isSelf = admin.id === meId}
    <tr class:disabled-row={admin.accountStatus === 'disabled'}>
      <td class="email-cell">
        <strong>{admin.email}</strong>
        {#if isSelf}<span class="you-badge">{$t('system.admins.you')}</span>{/if}
      </td>
      <td>
        {#if isSelf}
          <span class="status-pill status-{admin.accountStatus}">{$t(`system.admins.status.${admin.accountStatus}`)}</span>
        {:else}
          <select
            value={admin.accountStatus}
            on:change={(e) => pickStatus(admin, e.currentTarget.value)}
            aria-label={$t('system.admins.columns.status')}>
            {#each statusOptions(admin) as opt (opt.value)}
              <option value={opt.value} disabled={opt.disabled}>
                {$t(`system.admins.status.${opt.value}`)}
              </option>
            {/each}
          </select>
        {/if}
      </td>
      <td class="mfa-cell">
        {#if admin.mfaEnabled}
          <svg class="mfa-check" width="14" height="14" role="img" aria-label={$t('system.admins.columns.mfa')}><use href="/icons.svg#icon-check"/></svg>
        {:else}
          <span class="text-muted" aria-hidden="true">—</span>
        {/if}
      </td>
      <td>{fmtDate(admin.lastLoginAt)}</td>
      <td>{fmtDate(admin.passwordResetIssuedAt)}</td>
      <td>{fmtDate(admin.createdAt)}</td>
      <td>
        <div class="row-actions">
          {#if isSelf}
            <small class="text-muted">{$t('system.admins.selfHint')}</small>
          {:else}
            <button on:click={() => openReset(admin)}>{$t('system.admins.reset.button')}</button>
            {#if admin.accountStatus === 'disabled'}
              <button class="danger" on:click={() => openDelete(admin)}>{$t('system.admins.delete.button')}</button>
            {/if}
          {/if}
        </div>
      </td>
    </tr>
  </DataTable>
</div>

<!-- Create modal -->
{#if createOpen}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.admins.create.title')}</h3>
      {#if createError}<div class="modal-error">{createError}</div>{/if}
      <div class="form-row">
        <label>{$t('system.admins.create.email')}</label>
        <input type="email" bind:value={createEmail} placeholder="ops@example.com" />
      </div>
      <div class="modal-actions">
        <button on:click={() => createOpen = false} disabled={createBusy}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={submitCreate} disabled={createBusy || !createEmail.trim()}>
          {createBusy ? $t('common.actions.saving') : $t('system.admins.create.submit')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Status-change confirm modal -->
{#if statusTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.admins.statusConfirm.title')}</h3>
      {#if statusError}<div class="modal-error">{statusError}</div>{/if}
      <p>
        {$t('system.admins.statusConfirm.body', { values: {
          email: statusTarget.email,
          status: $t(`system.admins.status.${statusNew}`),
        } })}
      </p>
      <div class="modal-actions">
        <button on:click={() => { statusTarget = null; statusNew = '' }} disabled={statusBusy}>
          {$t('common.actions.cancel')}
        </button>
        <button class="primary" on:click={confirmStatus} disabled={statusBusy}>
          {statusBusy ? $t('common.actions.saving') : $t('system.admins.statusConfirm.apply')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Reset-password confirm modal -->
{#if resetTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.admins.reset.title')}</h3>
      {#if resetError}<div class="modal-error">{resetError}</div>{/if}
      <p>{$t('system.admins.reset.body', { values: { email: resetTarget.email } })}</p>
      <div class="modal-actions">
        <button on:click={() => resetTarget = null} disabled={resetBusy}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={confirmReset} disabled={resetBusy}>
          {resetBusy ? $t('common.actions.saving') : $t('system.admins.reset.button')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete confirm modal -->
{#if deleteTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.admins.delete.title')}</h3>
      {#if deleteError}<div class="modal-error">{deleteError}</div>{/if}
      <p>{$t('system.admins.delete.body', { values: { email: deleteTarget.email } })}</p>
      <div class="modal-actions">
        <button on:click={() => deleteTarget = null} disabled={deleteBusy}>{$t('common.actions.cancel')}</button>
        <button class="danger" on:click={confirmDelete} disabled={deleteBusy}>
          {deleteBusy ? $t('common.actions.saving') : $t('system.admins.delete.button')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Temp-password reveal (shared by Create + Reset) -->
{#if tempPasswordReveal}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.admins.tempPassword.title')}</h3>
      <p><strong>{$t('system.admins.tempPassword.notice')}</strong></p>
      <dl>
        <dt>{$t('system.admins.create.email')}</dt>
        <dd>{tempPasswordReveal.email}</dd>
        <dt>{$t('system.admins.tempPassword.title')}</dt>
        <dd><code>{tempPasswordReveal.password}</code></dd>
      </dl>
      <div class="modal-actions">
        <button on:click={copyTemp}>
          {tempCopied ? $t('system.admins.tempPassword.copied') : $t('system.admins.tempPassword.copy')}
        </button>
        <button class="primary" on:click={dismissTemp}>{$t('system.admins.tempPassword.done')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }
  .page-header h1 { margin: 0; }
  .subtitle { margin: 4px 0 0; color: var(--text2); font-size: 13px; }
  /* Toolbar proportions: override the global `input { width: 100% }` rule. Pattern shared
     with SystemTenants / SystemAudit. */
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
  /* Override the global table-layout: fixed so the email column can size to its
     content (email + YOU badge) instead of being clipped under a 6-way equal split. */
  table { width: 100%; border-collapse: collapse; table-layout: auto; }
  th, td { padding: 8px; text-align: left; border-bottom: 1px solid var(--border); }
  /* Keep the email and YOU badge on one line — the badge is inline-only chrome,
     wrapping it below the address reads as a layout glitch. */
  td.email-cell { white-space: nowrap; }
  .mfa-cell { text-align: center; }
  .mfa-check { display: inline-block; color: var(--success); vertical-align: middle; }
  tr.disabled-row { color: var(--text2); }
  .row-actions { display: flex; gap: 6px; align-items: center; }
  .you-badge {
    margin-left: 8px;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    background: var(--accent);
    color: white;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .status-pill {
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg);
    border: 1px solid var(--border);
  }
  .status-pill.status-active { color: var(--success); }
  .status-pill.status-locked { color: var(--warning); }
  .status-pill.status-disabled { color: var(--text2); }
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
    width: 440px;
    max-width: 90vw;
  }
  .modal-error {
    background: var(--bg);
    border: 1px solid var(--danger);
    color: var(--danger);
    padding: 6px 10px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    font-size: 13px;
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
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }
  dt { font-weight: 600; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; word-break: break-all; }
  select {
    padding: 4px 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
  }
</style>
