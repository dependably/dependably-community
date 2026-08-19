<!--
  Review queue for policy-gate blocks. Every automatic 403 (deprecated, release-age,
  malicious, KEV, EPSS, vuln-score) lands here as a pending entry; an admin approves
  (sets the version's manual allow override) or denies (manual block). A decided entry can
  be re-decided or reset to pending from the row's "…" menu — the change-my-mind path.
  Searchable and filterable by ecosystem, gate, and state (pending is the default working
  view), sorted by any of the sortable column headers, and paged — all server-side, since a
  page of the queue is not the queue. Clicking a row expands the full policy detail and
  decision metadata.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { formatDate } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Every gate the block gate can record. Drives the gate filter, so a value missing here is a
  // gate the queue cannot be narrowed to.
  const GATES = [
    'deprecated', 'revoked', 'release_age', 'license', 'install_script',
    'provenance', 'malicious', 'kev', 'epss', 'vuln_score',
  ]

  // Table state lives in the URL query string so it survives navigating into a detail page and
  // back (this component is recreated on every route change) as well as reloads and copied links.
  const DEFAULTS = { q: '', eco: '', gate: '', state: 'pending', page: 1, limit: 50, sort: 'updated', dir: 'desc' }
  const init = readQuery(DEFAULTS)

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let items = [], loading = true, error = ''
  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)
  let search = init.q, filterEco = init.eco, filterGate = init.gate, stateFilter = init.state
  let page = init.page, limit = init.limit, total = 0
  let sortCol = init.sort, sortDir = init.dir
  // Per-row in-flight flag so the row's controls disable while a decision posts.
  let busy = {}
  // Id of the row whose detail is expanded, and of the row whose "…" menu is open.
  let expandedId = null
  let openActionsId = null
  // Request sequence — page/filter/search changes can fire overlapping loads; a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  function sync() {
    writeQuery(
      { q: search, eco: filterEco, gate: filterGate, state: stateFilter, page, limit, sort: sortCol, dir: sortDir },
      DEFAULTS)
  }

  async function load() {
    const mine = ++seq
    loading = true; error = ''
    // An expansion and an open row menu are both anchored to a row of the page being replaced.
    expandedId = null; openActionsId = null
    try {
      const params = { limit, offset: (page - 1) * limit, sort: sortCol, dir: sortDir }
      if (stateFilter !== 'all') params.state = stateFilter
      if (filterEco) params.ecosystem = filterEco
      if (filterGate) params.gate = filterGate
      if (search) params.search = search
      const resp = await api.getQuarantine(params)
      if (mine !== seq) return
      items = resp.items
      total = resp.total
    } catch (e) {
      if (mine !== seq) return
      error = extractErrorMessage(e)
    } finally {
      if (mine === seq) loading = false
    }
  }

  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }
  // Any narrowing invalidates the current page number — page 4 of the old result set is rarely
  // a page of the new one.
  function onFilterChange() { page = 1; sync(); load() }

  // The server already sorted and returned the page in order. DataTable's local sort is bypassed
  // by returning 0 for every comparator — the stable sort preserves the server order regardless
  // of which column is "active".
  const NOOP_CMP = () => 0
  $: columns = [
    { key: 'package',   label: $t('quarantine.columns.package'),   sortable: true },
    { key: 'gate',      label: $t('quarantine.columns.gate'),      sortable: true,  width: '130px' },
    { key: 'detail',    label: $t('quarantine.columns.detail'),    sortable: false, width: '220px' },
    { key: 'decidedBy', label: $t('quarantine.columns.decidedBy'), sortable: true,  width: '180px' },
    { key: 'updated',   label: $t('quarantine.columns.updated'),   sortable: true,  width: '150px', defaultDir: 'desc' },
    { key: 'actions',   label: '',                                 sortable: false, width: '180px' },
  ]
  const comparators = {
    package: NOOP_CMP, gate: NOOP_CMP, detail: NOOP_CMP,
    decidedBy: NOOP_CMP, updated: NOOP_CMP, actions: NOOP_CMP,
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

  load()
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('quarantine.title')}</h1>
  </div>
  <div class="page-toolbar">
    <SearchInput
      placeholder={$t('quarantine.searchPlaceholder')}
      bind:value={search}
      on:search={onFilterChange}
      class="toolbar-search"
    />
    <select bind:value={filterEco} on:change={onFilterChange} class="eco-select" aria-label={$t('common.allEcosystems')}>
      <option value="">{$t('common.allEcosystems')}</option>
      {#each ECOSYSTEMS as eco (eco)}
        <option value={eco}>{ECO_LABEL[eco]}</option>
      {/each}
    </select>
    <select bind:value={filterGate} on:change={onFilterChange} class="w-auto" aria-label={$t('quarantine.filters.gateLabel')}>
      <option value="">{$t('quarantine.filters.allGates')}</option>
      {#each GATES as gate (gate)}
        <option value={gate}>{gateLabel(gate)}</option>
      {/each}
    </select>
    <select bind:value={stateFilter} on:change={onFilterChange} class="w-auto" aria-label={$t('quarantine.filters.stateLabel')}>
      <option value="pending">{$t('quarantine.filters.pending')}</option>
      <option value="approved">{$t('quarantine.filters.approved')}</option>
      <option value="denied">{$t('quarantine.filters.denied')}</option>
      <option value="all">{$t('quarantine.filters.all')}</option>
    </select>
  </div>
  <p class="tab-intro">{$t('quarantine.intro')}</p>

  {#if error}<div class="error-msg">{error}</div>{/if}

  <DataTable
    {columns}
    rows={items}
    {comparators}
    {loading}
    loadingRows={limit}
    loadingRowHeight="40px"
    memoryKey="quarantine"
    initialSort={{ key: sortCol, dir: sortDir }}
    emptyText={$t('quarantine.empty')}
    tableClass=""
    on:sortchange={onSortChange}
    let:row={e}
  >
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
      <!-- Email when the decider is still a member of this org, their id when the account has
           since been erased, an em dash while the entry is undecided. -->
      <td class="text-muted t-sm decider" title={e.decided_by_email ?? e.decided_by ?? ''}>
        {e.decided_by_email ?? e.decided_by ?? '—'}
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
        <td colspan={columns.length}>
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
                  <!-- The id keeps the monospace treatment; a resolved email is prose. -->
                  <span class="detail-value" class:t-mono={!e.decided_by_email}>
                    {e.decided_by_email ?? e.decided_by}
                  </span>
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
  </DataTable>

  <Pagination {total} {page} {limit} on:pagechange={onPageChange} on:limitchange={onLimitChange} />
</div>

<style>
  .nowrap { white-space: nowrap; }

  /* Column widths, the placeholder rows, and the empty row are DataTable's now — the widths ride
     on the `columns` definitions, which is also what keeps the actions column from collapsing to
     the global th:empty{width:90px} and clipping its buttons. */

  /* An email overruns its column sooner than the other cells do; the full value is on the title
     attribute either way. */
  .decider { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

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
