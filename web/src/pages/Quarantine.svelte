<!--
  Review queue for policy-gate blocks. Every automatic 403 (deprecated, release-age,
  malicious, KEV, EPSS, vuln-score) lands here as a pending entry; an admin approves
  (sets the version's manual allow override) or denies (manual block). A decided entry can
  be re-decided or reset to pending from the row's "…" menu — the change-my-mind path.
  Filterable by state; pending is the default working view. Clicking a row expands the full
  policy detail and decision metadata.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { formatDate } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'

  let items = [], loading = true, error = ''
  let stateFilter = 'pending'
  // Per-row in-flight flag so the row's controls disable while a decision posts.
  let busy = {}
  // Id of the row whose detail is expanded, and of the row whose "…" menu is open.
  let expandedId = null
  let openActionsId = null

  async function load() {
    loading = true; error = ''
    try {
      const resp = await api.getQuarantine(stateFilter === 'all' ? null : stateFilter)
      items = resp.items
    } catch (e) { error = extractErrorMessage(e) }
    finally { loading = false }
  }

  async function decide(entry, decision) {
    openActionsId = null
    busy = { ...busy, [entry.id]: true }
    error = ''
    try {
      await api.decideQuarantine(entry.id, decision)
      await load()
    } catch (e) { error = extractErrorMessage(e) }
    finally { busy = { ...busy, [entry.id]: false } }
  }

  function toggleRow(entry) {
    expandedId = expandedId === entry.id ? null : entry.id
  }

  function gateLabel(gate) {
    const key = `quarantine.gates.${gate}`
    const label = $t(key)
    return label === key ? gate : label
  }

  // The gate detail is stored as a JSON string. Parse it into {key,value} rows for display;
  // returns null when it isn't a JSON object, so the caller can fall back to the raw text.
  function parseDetail(raw) {
    if (!raw) return null
    try {
      const obj = JSON.parse(raw)
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        return Object.entries(obj).map(([k, v]) => ({
          key: humanizeKey(k),
          value: Array.isArray(v) ? v.join(', ') : String(v),
        }))
      }
    } catch { /* not JSON — fall back to the raw string */ }
    return null
  }

  // published_at -> "Published at"
  function humanizeKey(k) {
    const s = String(k).replace(/_/g, ' ')
    return s.charAt(0).toUpperCase() + s.slice(1)
  }

  onMount(load)
</script>

<div class="page page-fluid">
  <div class="page-header">
    <h1 class="page-title">{$t('quarantine.title')}</h1>
  </div>
  <div class="page-toolbar">
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
      <!-- Explicit column widths: the table is table-layout:fixed, and an empty actions <th>
           would otherwise collapse to the global th:empty 90px and clip the buttons. -->
      <colgroup>
        <col />
        <col class="col-gate" />
        <col class="col-detail" />
        <col class="col-updated" />
        <col class="col-actions" />
      </colgroup>
      <thead>
        <tr>
          <th>{$t('quarantine.columns.package')}</th>
          <th>{$t('quarantine.columns.gate')}</th>
          <th>{$t('quarantine.columns.detail')}</th>
          <th>{$t('quarantine.columns.updated')}</th>
          <th class="col-actions"></th>
        </tr>
      </thead>
      <tbody>
        {#each items as e (e.id)}
          <tr
            class="cursor-pointer"
            class:expanded-row={expandedId === e.id}
            on:click={() => toggleRow(e)}
          >
            <td class="t-mono" title={e.purl}>
              <span class="badge {e.ecosystem}">{e.ecosystem}</span>
              {e.purl}
            </td>
            <td><span class="badge">{gateLabel(e.gate)}</span></td>
            <td class="text-muted t-sm">
              <div class="detail-preview">
                <span class="detail-text">{e.detail ?? '—'}</span>
                <svg class="chev" class:open={expandedId === e.id} width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-chevron-down" /></svg>
              </div>
            </td>
            <td class="text-muted t-sm nowrap">{$formatDate(e.updated_at)}</td>
            <td class="actions-cell">
              {#if e.state === 'pending'}
                <div class="row-actions">
                  <button class="primary btn-sm" disabled={busy[e.id]} on:click|stopPropagation={() => decide(e, 'approved')}>{$t('quarantine.approve')}</button>
                  <button class="danger btn-sm" disabled={busy[e.id]} on:click|stopPropagation={() => decide(e, 'denied')}>{$t('quarantine.deny')}</button>
                </div>
              {:else}
                <div class="row-actions">
                  <span class="badge state-{e.state}">{$t(`quarantine.states.${e.state}`)}</span>
                  <RowActionsMenu id={e.id} bind:openId={openActionsId} ariaLabel={$t('quarantine.actions.menuLabel')}>
                    {#if e.state === 'approved'}
                      <button class="popover-item danger" disabled={busy[e.id]} on:click|stopPropagation={() => decide(e, 'denied')}>{$t('quarantine.deny')}</button>
                    {:else}
                      <button class="popover-item" disabled={busy[e.id]} on:click|stopPropagation={() => decide(e, 'approved')}>{$t('quarantine.approve')}</button>
                    {/if}
                    <div class="popover-divider"></div>
                    <button class="popover-item" disabled={busy[e.id]} on:click|stopPropagation={() => decide(e, 'pending')}>{$t('quarantine.actions.resetToPending')}</button>
                  </RowActionsMenu>
                </div>
              {/if}
            </td>
          </tr>

          {#if expandedId === e.id}
            {@const rows = parseDetail(e.detail)}
            <tr class="detail-row">
              <td colspan="5">
                <div class="detail-panel">
                  <div class="detail-section col">
                    <span class="detail-label">{$t('quarantine.detail.policyDetail')}</span>
                    {#if rows}
                      <div class="detail-meta">
                        {#each rows as r (r.key)}
                          <div class="meta-item">
                            <span class="kv-key">{r.key}</span>
                            <span class="detail-value">{r.value}</span>
                          </div>
                        {/each}
                      </div>
                    {:else if e.detail}
                      <pre class="detail-json">{e.detail}</pre>
                    {:else}
                      <span class="detail-value text-muted">—</span>
                    {/if}
                  </div>

                  <div class="detail-meta">
                    <div class="meta-item">
                      <span class="kv-key">{$t('quarantine.columns.package')}</span>
                      <span class="detail-value t-mono">{e.purl}</span>
                    </div>
                    <div class="meta-item">
                      <span class="kv-key">{$t('quarantine.detail.created')}</span>
                      <span class="detail-value">{e.created_at ? $formatDate(e.created_at) : '—'}</span>
                    </div>
                    {#if e.decided_at}
                      <div class="meta-item">
                        <span class="kv-key">{$t('quarantine.detail.decidedAt')}</span>
                        <span class="detail-value">{$formatDate(e.decided_at)}</span>
                      </div>
                    {/if}
                    {#if e.decided_by}
                      <div class="meta-item">
                        <span class="kv-key">{$t('quarantine.detail.decidedBy')}</span>
                        <span class="detail-value t-mono">{e.decided_by}</span>
                      </div>
                    {/if}
                  </div>

                  {#if e.note}
                    <div class="detail-section col">
                      <span class="detail-label">{$t('quarantine.detail.note')}</span>
                      <span class="detail-value">{e.note}</span>
                    </div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .nowrap { white-space: nowrap; }

  /* Fixed column widths. The scoped class outranks the global th:empty{width:90px}, so the
     actions column keeps room for both buttons (or the state badge + "…" menu) instead of
     clipping them under td{overflow:hidden}. Package (first col) absorbs the remaining width. */
  .col-gate { width: 110px; }
  .col-detail { width: 240px; }
  .col-updated { width: 150px; }
  .col-actions { width: 180px; }

  /* Action buttons live in a flex DIV inside the cell — never flex on the td itself, which
     breaks the row's border-bottom alignment. The cell stays nowrap so the buttons (or the
     state badge + "…" menu) are never clipped at the page edge. */
  .actions-cell { white-space: nowrap; }
  .row-actions { display: flex; gap: 6px; align-items: center; }

  /* Detail is a narrow one-line preview + expand chevron; the full, formatted detail lives in
     the expandable row below. Keeping this column narrow is what frees the actions column. */
  .detail-preview { display: flex; align-items: center; gap: 6px; }
  .detail-text { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .chev { flex-shrink: 0; color: var(--text2); transition: transform 0.15s; }
  .chev.open { transform: rotate(180deg); }

  /* Expandable detail row — mirrors the Vulnerabilities.svelte pattern. */
  .expanded-row td { background: var(--surface2); }
  .detail-row td { padding: 0; border-top: none; background: var(--surface2); }

  .detail-panel {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 12px 16px 16px;
    font-size: 13px;
  }
  .detail-meta { display: flex; flex-wrap: wrap; gap: 6px 24px; }
  .meta-item { display: flex; gap: 8px; align-items: baseline; }
  .detail-section { display: flex; gap: 10px; align-items: baseline; }
  .detail-section.col { flex-direction: column; gap: 6px; }
  .detail-label {
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    flex-shrink: 0;
  }
  .kv-key { color: var(--text2); flex-shrink: 0; min-width: 110px; }
  .detail-value { color: var(--text); overflow-wrap: anywhere; }

  .detail-json {
    margin: 0;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px 10px;
    font-size: 12px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 320px;
    overflow: auto;
  }
</style>
