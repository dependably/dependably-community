<!--
  Review queue for policy-gate blocks. Every automatic 403 (deprecated, release-age,
  malicious, KEV, EPSS, vuln-score) lands here as a pending entry; an admin approves
  (sets the version's manual allow override) or denies (manual block). Filterable by
  state; pending is the default working view.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { formatDate } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'

  let items = [], loading = true, error = ''
  let stateFilter = 'pending'
  // Per-row in-flight flag so both buttons disable while a decision posts.
  let busy = {}

  async function load() {
    loading = true; error = ''
    try {
      const resp = await api.getQuarantine(stateFilter === 'all' ? null : stateFilter)
      items = resp.items
    } catch (e) { error = extractErrorMessage(e) }
    finally { loading = false }
  }

  async function decide(entry, decision) {
    busy = { ...busy, [entry.id]: true }
    error = ''
    try {
      await api.decideQuarantine(entry.id, decision)
      await load()
    } catch (e) { error = extractErrorMessage(e) }
    finally { busy = { ...busy, [entry.id]: false } }
  }

  function gateLabel(gate) {
    const key = `quarantine.gates.${gate}`
    const label = $t(key)
    return label === key ? gate : label
  }

  onMount(load)
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('quarantine.title')}</h1>
    <select bind:value={stateFilter} on:change={load} class="w-auto">
      <option value="pending">{$t('quarantine.filters.pending')}</option>
      <option value="approved">{$t('quarantine.filters.approved')}</option>
      <option value="denied">{$t('quarantine.filters.denied')}</option>
      <option value="all">{$t('quarantine.filters.all')}</option>
    </select>
  </div>
  <p class="tab-intro">{$t('quarantine.intro')}</p>

  {#if error}<div class="error-msg">{error}</div>{/if}

  {#if loading}
    <p class="text-muted">{$t('common.loading')}</p>
  {:else if items.length === 0}
    <p class="text-muted">{$t('quarantine.empty')}</p>
  {:else}
    <table class="list-table">
      <thead>
        <tr>
          <th>{$t('quarantine.columns.package')}</th>
          <th>{$t('quarantine.columns.gate')}</th>
          <th>{$t('quarantine.columns.detail')}</th>
          <th>{$t('quarantine.columns.updated')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each items as e (e.id)}
          <tr>
            <td class="t-mono" title={e.purl}>
              <span class="badge {e.ecosystem}">{e.ecosystem}</span>
              {e.purl}
            </td>
            <td><span class="badge">{gateLabel(e.gate)}</span></td>
            <td class="text-muted t-sm detail-cell" title={e.detail ?? ''}>{e.detail ?? '—'}</td>
            <td class="text-muted t-sm">{$formatDate(e.updated_at)}</td>
            <td>
              {#if e.state === 'pending'}
                <div class="row-actions">
                  <button class="primary btn-sm" disabled={busy[e.id]} on:click={() => decide(e, 'approved')}>{$t('quarantine.approve')}</button>
                  <button class="danger btn-sm" disabled={busy[e.id]} on:click={() => decide(e, 'denied')}>{$t('quarantine.deny')}</button>
                </div>
              {:else}
                <span class="badge state-{e.state}">{$t(`quarantine.states.${e.state}`)}</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  /* Action buttons live in a flex DIV inside the cell — never flex on the td itself,
     which breaks the row's border-bottom alignment. */
  .row-actions { display: flex; gap: 6px; align-items: center; }
  .detail-cell { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .state-approved { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .state-denied { background: var(--badge-red-bg, var(--badge-warning-bg)); color: var(--badge-red-text); }
</style>
