<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { submitForm, extractErrorMessage } from '../lib/form.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg, user } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import DataTable from '../lib/DataTable.svelte'

  let users = [], invites = [], tab = 'members', loading = true, error = ''
  let showInvite = false, inviteEmail = '', inviteRole = 'member', inviting = false, inviteLink = null
  let inviteCopyState = '' // '', 'copied', 'failed'
  // Per-row inline role edit state — at most one row in edit mode at a time.
  let editingUserId = null, editingRole = '', savingRole = false

  // Viewer can change a row's role iff they have tenant:configure (admin/owner). Owner-touch
  // (modifying owner rows or granting owner) is gated separately by the backend; the UI mirrors
  // that by hiding the owner option and disabling the change button on owner rows for admins.
  $: viewerRole = $user?.role ?? ''
  $: viewerCanManageRoles = viewerRole === 'admin' || viewerRole === 'owner'
  $: viewerIsOwner = viewerRole === 'owner'
  function rolesAvailableTo(viewer) {
    // Admins cannot grant owner; owners can grant any tenant role.
    return viewer === 'owner'
      ? ['member', 'admin', 'auditor', 'owner']
      : ['member', 'admin', 'auditor']
  }
  function canEditRow(row) {
    if (!viewerCanManageRoles) return false
    return row.role === 'owner' ? viewerIsOwner : true
  }

  async function copyInvite() {
    const ok = await copyToClipboard(inviteLink)
    inviteCopyState = ok ? 'copied' : 'failed'
    setTimeout(() => inviteCopyState = '', 2000)
  }

  function inviteStatus(inv) { return inv.acceptedAt ? 'accepted' : inviteExpired(inv) ? 'expired' : 'pending' }

  $: memberColumns = [
    { key: 'email',       label: $t('users.members.columns.email'),  sortable: true },
    { key: 'role',        label: $t('users.members.columns.role'),   sortable: true, width: '110px' },
    { key: 'accountType', label: $t('users.members.columns.type'),   sortable: true, width: '80px' },
    { key: 'mfaEnabled',  label: $t('users.members.columns.mfa'),   sortable: true, width: '60px' },
    { key: 'joinedAt',    label: $t('users.members.columns.joined'), sortable: true, width: '110px' },
    { key: 'actions',     label: '',                                 sortable: false, width: '180px' },
  ]

  $: inviteColumns = [
    { key: 'email',     label: $t('users.invites.columns.email'),   sortable: true },
    { key: 'createdAt', label: $t('users.invites.columns.invited'), sortable: true, width: '110px', defaultDir: 'desc' },
    { key: 'expiresAt', label: $t('users.invites.columns.expires'), sortable: true, width: '110px' },
    { key: 'status',    label: $t('users.invites.columns.status'),  sortable: true, width: '90px' },
    { key: 'actions',   label: '',                                  sortable: false, width: '90px' },
  ]
  const inviteComparators = {
    status: (a, b) => inviteStatus(a).localeCompare(inviteStatus(b)),
  }

  $: org = $currentOrg
  $: if (org) loadAll()
  function roleLabel(role) {
    if (role === 'owner') return $t('users.members.role.owner')
    if (role === 'admin') return $t('users.members.role.admin')
    if (role === 'auditor') return $t('users.members.role.auditor')
    return $t('users.members.role.member')
  }
  function accountTypeLabel(type) {
    if (type === 'saml') return $t('users.members.accountType.saml')
    return $t('users.members.accountType.forms')
  }

  async function loadAll() {
    loading = true
    try {
      const [u, inv] = await Promise.all([api.listUsers(), api.listInvites()])
      users = u; invites = inv
    } catch (e) { error = extractErrorMessage(e) }
    finally { loading = false }
  }

  async function removeUser(userId) {
    if (!confirm($t('users.members.removeConfirm'))) return
    await api.removeUser( userId)
    users = users.filter(u => u.userId !== userId)
  }

  function startEditRole(u) {
    editingUserId = u.userId
    editingRole = u.role
  }
  function cancelEditRole() {
    editingUserId = null
    editingRole = ''
  }
  async function saveRole(u) {
    if (editingRole === u.role) { cancelEditRole(); return }
    await submitForm(() => api.updateUserRole(u.userId, editingRole), {
      setSaving: v => savingRole = v,
      setError:  v => error      = v,
      onSuccess: () => {
        users = users.map(row => row.userId === u.userId ? { ...row, role: editingRole } : row)
        cancelEditRole()
      },
    })
  }

  async function invite() {
    await submitForm(() => api.createInvite(inviteEmail, inviteRole), {
      setSaving: v => inviting = v,
      setError:  v => error    = v,
      onSuccess: (data) => {
        inviteLink = data.invite_link
        invites = [...invites, data.record]
        showInvite = false; inviteEmail = ''; inviteRole = 'member'
      },
    })
  }

  async function cancelInvite(id) {
    await api.deleteInvite( id)
    invites = invites.filter(i => i.id !== id)
  }

  function inviteExpired(inv) { return new Date(inv.expiresAt) < new Date() }

  $: pendingCount = invites.filter(i => !i.acceptedAt).length
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('users.title')}</h1>
    <button class="primary" on:click={() => showInvite = true}>{$t('users.inviteUser')}</button>
  </div>

  {#if inviteLink}
    <div class="card success mb-4">
      <strong>{$t('users.inviteLink')}</strong>
      <div class="copy-block mt-2">
        <span class="copy-block-text">{inviteLink}</span>
        <button class="copy-btn" on:click={copyInvite}>
          {inviteCopyState === 'copied' ? $t('common.actions.copied') : inviteCopyState === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
        </button>
      </div>
      <button class="mt-2" on:click={() => inviteLink = null}>{$t('common.actions.dismiss')}</button>
    </div>
  {/if}

  <ErrorBanner message={error} />

  <div class="tabs">
    <button class="tab" class:active={tab==='members'} on:click={() => tab='members'}>{$t('users.tabs.members', { values: { count: users.length } })}</button>
    <button class="tab" class:active={tab==='invites'} on:click={() => tab='invites'}>{$t('users.tabs.pendingInvites', { values: { count: pendingCount } })}</button>
  </div>

  {#if tab === 'members'}
    <DataTable
      columns={memberColumns}
      rows={users}
      {loading}
      initialSort={{ key: 'email', dir: 'asc' }}
      emptyText={$t('users.members.empty')}
      tableClass="table-auto members-table"
      let:row={u}
    >
      <tr>
        <td>{u.email}</td>
        <td>
          {#if editingUserId === u.userId}
            <select bind:value={editingRole} class="role-select">
              {#each rolesAvailableTo(viewerRole) as r (r)}
                <option value={r}>{roleLabel(r)}</option>
              {/each}
            </select>
          {:else}
            {roleLabel(u.role)}
          {/if}
        </td>
        <td>{accountTypeLabel(u.accountType)}</td>
        <td class="mfa-cell">
          {#if u.mfaEnabled}
            <svg class="mfa-check" width="14" height="14" role="img" aria-label={$t('users.members.columns.mfa')}><use href="/icons.svg#icon-check"/></svg>
          {:else}
            <span class="text-muted" aria-hidden="true">—</span>
          {/if}
        </td>
        <td class="text-muted">{$formatDateShort(u.joinedAt)}</td>
        <td>
          <div class="row-actions">
            {#if editingUserId === u.userId}
              <button class="primary btn-sm" disabled={savingRole} on:click={() => saveRole(u)}>{$t('users.members.saveRole')}</button>
              <button class="btn-sm" disabled={savingRole} on:click={cancelEditRole}>{$t('users.members.cancelRole')}</button>
            {:else}
              {#if canEditRow(u)}
                <button class="btn-sm" on:click={() => startEditRole(u)}>{$t('users.members.changeRole')}</button>
              {:else if u.role === 'owner' && viewerCanManageRoles}
                <span class="text-muted btn-sm" title={$t('users.members.ownerLocked')}>—</span>
              {/if}
              <button class="danger btn-sm" on:click={() => removeUser(u.userId)}>{$t('common.actions.remove')}</button>
            {/if}
          </div>
        </td>
      </tr>
    </DataTable>
  {:else}
    <DataTable
      columns={inviteColumns}
      rows={invites}
      comparators={inviteComparators}
      {loading}
      initialSort={{ key: 'createdAt', dir: 'desc' }}
      emptyText={$t('users.invites.empty')}
      tableClass="table-auto invites-table"
      let:row={inv}
    >
      <tr>
        <td>{inv.email}</td>
        <td class="text-muted">{$formatDateShort(inv.createdAt)}</td>
        <td>{$formatDateShort(inv.expiresAt)}</td>
        <td>
          {#if inv.acceptedAt}<span class="badge success">{$t('users.invites.status.accepted')}</span>
          {:else if inviteExpired(inv)}<span class="badge expired">{$t('users.invites.status.expired')}</span>
          {:else}<span class="badge">{$t('users.invites.status.pending')}</span>{/if}
        </td>
        <td>
          {#if !inv.acceptedAt}<button class="danger btn-sm" on:click={() => cancelInvite(inv.id)}>{$t('users.invites.cancel')}</button>{/if}
        </td>
      </tr>
    </DataTable>
  {/if}
</div>

<style>
  .row-actions { display: flex; gap: 6px; align-items: center; }
  .role-select { padding: 2px 6px; }
  .mfa-cell { text-align: center; }
  .mfa-check { display: inline-block; color: var(--success); vertical-align: middle; }
</style>

{#if showInvite}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('users.modal.title')}</h3>
      <div class="form-row"><label>{$t('users.modal.email')}</label><input type="email" bind:value={inviteEmail} /></div>
      <div class="form-row">
        <label>{$t('users.modal.role')}</label>
        <select bind:value={inviteRole}>
          {#each rolesAvailableTo(viewerRole) as r (r)}
            <option value={r}>{roleLabel(r)}</option>
          {/each}
        </select>
      </div>
      <div class="modal-actions">
        <button on:click={() => showInvite = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={invite} disabled={inviting}>{inviting ? $t('users.modal.sending') : $t('users.modal.sendInvite')}</button>
      </div>
    </div>
  </div>
{/if}
