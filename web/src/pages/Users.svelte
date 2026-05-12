<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg, user } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { sortIndicator } from '../lib/sortIndicator.js'

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

  let memberSortCol = 'email', memberSortDir = 'asc'
  $: sortedUsers = [...users].sort((a, b) => {
    let av = a[memberSortCol] ?? '', bv = b[memberSortCol] ?? ''
    if (av < bv) return memberSortDir === 'asc' ? -1 : 1
    if (av > bv) return memberSortDir === 'asc' ? 1 : -1
    return 0
  })
  function toggleMemberSort(col) {
    if (memberSortCol === col) memberSortDir = memberSortDir === 'asc' ? 'desc' : 'asc'
    else { memberSortCol = col; memberSortDir = 'asc' }
  }

  let inviteSortCol = 'createdAt', inviteSortDir = 'desc'
  function inviteStatus(inv) { return inv.acceptedAt ? 'accepted' : inviteExpired(inv) ? 'expired' : 'pending' }
  $: sortedInvites = [...invites].sort((a, b) => {
    let av = inviteSortCol === 'status' ? inviteStatus(a) : (a[inviteSortCol] ?? '')
    let bv = inviteSortCol === 'status' ? inviteStatus(b) : (b[inviteSortCol] ?? '')
    if (av < bv) return inviteSortDir === 'asc' ? -1 : 1
    if (av > bv) return inviteSortDir === 'asc' ? 1 : -1
    return 0
  })
  function toggleInviteSort(col) {
    if (inviteSortCol === col) inviteSortDir = inviteSortDir === 'asc' ? 'desc' : 'asc'
    else { inviteSortCol = col; inviteSortDir = 'asc' }
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
    } catch (e) { error = e.message }
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
    savingRole = true
    try {
      await api.updateUserRole(u.userId, editingRole)
      users = users.map(row => row.userId === u.userId ? { ...row, role: editingRole } : row)
      cancelEditRole()
    } catch (e) {
      error = e.message
    } finally {
      savingRole = false
    }
  }

  async function invite() {
    inviting = true
    try {
      const data = await api.createInvite(inviteEmail, inviteRole)
      inviteLink = data.invite_link
      invites = [...invites, data.record]
      showInvite = false; inviteEmail = ''; inviteRole = 'member'
    } catch (e) { error = e.message }
    finally { inviting = false }
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

  {#if error}<div class="page-error">{error}</div>{/if}

  <div class="tabs">
    <button class="tab" class:active={tab==='members'} on:click={() => tab='members'}>{$t('users.tabs.members', { values: { count: users.length } })}</button>
    <button class="tab" class:active={tab==='invites'} on:click={() => tab='invites'}>{$t('users.tabs.pendingInvites', { values: { count: pendingCount } })}</button>
  </div>

  {#if loading}<span class="spinner"></span>
  {:else if tab === 'members'}
    <table class="table-auto members-table">
      <colgroup>
        <col><!-- email: flexible -->
        <col class="col-role"><!-- role -->
        <col class="col-type"><!-- type -->
        <col class="col-joined"><!-- joined date -->
        <col class="col-actions"><!-- actions -->
      </colgroup>
      <thead><tr>
        <th class="sortable" on:click={() => toggleMemberSort('email')}>{$t('users.members.columns.email')}{sortIndicator('email', memberSortCol, memberSortDir)}</th>
        <th class="sortable" on:click={() => toggleMemberSort('role')}>{$t('users.members.columns.role')}{sortIndicator('role', memberSortCol, memberSortDir)}</th>
        <th class="sortable" on:click={() => toggleMemberSort('accountType')}>{$t('users.members.columns.type')}{sortIndicator('accountType', memberSortCol, memberSortDir)}</th>
        <th class="sortable" on:click={() => toggleMemberSort('joinedAt')}>{$t('users.members.columns.joined')}{sortIndicator('joinedAt', memberSortCol, memberSortDir)}</th>
        <th></th>
      </tr></thead>
      <tbody>
        {#each sortedUsers as u (u.userId)}
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
        {/each}
        {#if users.length === 0}<tr><td colspan="5" class="text-center text-muted">{$t('users.members.empty')}</td></tr>{/if}
      </tbody>
    </table>
  {:else}
    <table class="table-auto invites-table">
      <colgroup>
        <col><!-- email: flexible -->
        <col class="col-invited"><!-- invited date -->
        <col class="col-expires"><!-- expires date -->
        <col class="col-status"><!-- status badge -->
        <col class="col-actions"><!-- actions -->
      </colgroup>
      <thead><tr>
        <th class="sortable" on:click={() => toggleInviteSort('email')}>{$t('users.invites.columns.email')}{sortIndicator('email', inviteSortCol, inviteSortDir)}</th>
        <th class="sortable" on:click={() => toggleInviteSort('createdAt')}>{$t('users.invites.columns.invited')}{sortIndicator('createdAt', inviteSortCol, inviteSortDir)}</th>
        <th class="sortable" on:click={() => toggleInviteSort('expiresAt')}>{$t('users.invites.columns.expires')}{sortIndicator('expiresAt', inviteSortCol, inviteSortDir)}</th>
        <th class="sortable" on:click={() => toggleInviteSort('status')}>{$t('users.invites.columns.status')}{sortIndicator('status', inviteSortCol, inviteSortDir)}</th>
        <th></th>
      </tr></thead>
      <tbody>
        {#each sortedInvites as inv (inv.id)}
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
        {/each}
        {#if invites.length === 0}<tr><td colspan="5" class="text-center text-muted">{$t('users.invites.empty')}</td></tr>{/if}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .row-actions { display: flex; gap: 6px; align-items: center; }
  .role-select { padding: 2px 6px; }
  .members-table .col-role    { width: 110px; }
  .members-table .col-type    { width: 80px; }
  .members-table .col-joined  { width: 110px; }
  .members-table .col-actions { width: 180px; }
  .invites-table .col-invited { width: 110px; }
  .invites-table .col-expires { width: 110px; }
  .invites-table .col-status  { width: 90px; }
  .invites-table .col-actions { width: 90px; }
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
