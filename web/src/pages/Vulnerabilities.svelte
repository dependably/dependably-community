<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatDate } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { ASSISTANTS, remediationBrief, remediationSkillIds, resolvedFixedVersion, skillInstallCommand, skillPrompt } from '../lib/remediation.js'
  import { aliasUrl } from '../lib/advisories.js'
  import Pagination from '../lib/Pagination.svelte'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import Toggle from '../lib/Toggle.svelte'

  // Table state lives in the URL query string so it survives route changes,
  // reloads, and copied links.
  const DEFAULTS = { q: '', eco: '', sev: '', page: 1, limit: 50, sort: 'severity', dir: 'desc' }
  const init = readQuery(DEFAULTS)

  // Severity filter chips. '' = all. Matches the lockfile/advisory vocabulary
  // (critical/high/medium/low) — note it's "medium", not "moderate".
  const SEVERITIES = ['critical', 'high', 'medium', 'low']

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let items = [], loading = true, error = ''
  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)
  let ecosystem = init.eco
  let search = init.q
  let severityFilter = init.sev
  // Client-side lifecycle filter over the loaded page. Revoked is a distinct lifecycle signal
  // (the version was removed upstream), not a vulnerability severity — so it filters the report
  // rather than scoring it.
  let revokedOnly = false
  let page = init.page, limit = init.limit, total = 0
  let sortCol = init.sort, sortDir = init.dir

  function sync() {
    writeQuery({ q: search, eco: ecosystem, sev: severityFilter, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS)
  }

  // Severity is filtered client-side over the loaded page (like search + revoked), so no reload.
  function setSeverity(s) { severityFilter = s; sync() }

  // Which row is expanded, keyed by `${purl}::${osvId}` so the same advisory under two
  // versions expands independently. The open row's detail lives in `expandedDetail`, a plain
  // reassigned binding that re-renders reliably through the DataTable slot. Fetched advisories
  // are cached by osvId + installed version — the server resolves remediation.fixedVersion
  // against the installed version, so the same advisory under another version is a distinct fetch.
  let expandedKey = null
  let expandedDetail = null      // { loading, error, detail } for the open row, or null
  // Deliberately a plain Map — reactivity is driven by `expandedDetail`, not this cache.
  // eslint-disable-next-line svelte/prefer-svelte-reactivity
  const detailCache = new Map()  // `${osvId}::${version}` -> loaded { loading, error, detail }
  // Request sequence — page/filter/sort changes can fire overlapping loads; a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  $: org = $currentOrg

  async function load() {
    const mine = ++seq
    if (!org) { loading = false; return }
    loading = true; error = ''
    expandedKey = null
    expandedDetail = null
    try {
      const params = { page, limit, sort: sortCol, dir: sortDir }
      if (ecosystem) params.ecosystem = ecosystem
      const data = await api.getVulnReport( params)
      if (mine !== seq) return
      items = data.items || []
      total = data.total
    } catch (e) {
      if (mine !== seq) return
      error = e.message; console.error(e)
    } finally {
      if (mine === seq) loading = false
    }
  }

  $: if (org !== undefined) load()

  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
  function handleEcoChange() { page = 1; sync(); load() }
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }

  async function toggleRow(r) {
    const key = `${r.purl}::${r.osvId}`
    if (expandedKey === key) { expandedKey = null; expandedDetail = null; return }
    expandedKey = key

    const cacheKey = `${r.osvId}::${r.version ?? ''}`
    const cached = detailCache.get(cacheKey)
    if (cached) { expandedDetail = cached; return }

    expandedDetail = { loading: true, error: false, detail: null }
    try {
      const detail = await api.getVulnDetail(r.osvId, r.version)
      const loaded = { loading: false, error: false, detail }
      detailCache.set(cacheKey, loaded)
      // Ignore a late resolve if the user collapsed this row or opened another meanwhile.
      if (expandedKey === key) expandedDetail = loaded
    } catch (e) {
      console.error(e)
      if (expandedKey === key) expandedDetail = { loading: false, error: true, detail: null }
    }
  }

  // Remediation skill descriptions (id → description from frontmatter), fetched once — the
  // endpoint is anonymous and tenant-agnostic, so it's shared across every expanded row rather
  // than refetched per advisory. A failed fetch (air-gapped instance still reachable, but a
  // transient error) just falls back to showing the skill id with no subtitle.
  let skillDescriptions = {}
  onMount(async () => {
    try {
      const skills = await api.getRemediationSkills()
      skillDescriptions = Object.fromEntries((skills ?? []).map(s => [s.id, s.description]))
    } catch (e) { console.error(e) }
  })

  // Copy-state per (row key)::(skillId)::(install|prompt) — mirrors the Setup page's pattern.
  let remediationCopyState = {}
  async function copyRemediation(stateKey, text) {
    const ok = await copyToClipboard(text)
    remediationCopyState[stateKey] = ok ? 'copied' : 'failed'
    setTimeout(() => { remediationCopyState[stateKey] = ''; remediationCopyState = remediationCopyState }, 2000)
  }

  // Which AI assistant the install command and prompt target. Persisted per browser —
  // a developer uses one assistant, not one per advisory.
  const ASSISTANT_STORAGE_KEY = 'remediationAssistant'
  const storedAssistant = localStorage.getItem(ASSISTANT_STORAGE_KEY) ?? ''
  let assistant = ASSISTANTS.some(a => a.id === storedAssistant) ? storedAssistant : 'claude'
  function setAssistant(id) {
    assistant = id
    localStorage.setItem(ASSISTANT_STORAGE_KEY, id)
  }

  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 }

  $: filtered = items.filter(r => {
    if (revokedOnly && !r.revokedAt) return false
    if (severityFilter && r.severity?.toLowerCase() !== severityFilter) return false
    if (!search) return true
    const q = search.toLowerCase()
    return r.packageName?.toLowerCase().includes(q)
      || r.osvId?.toLowerCase().includes(q)
      || r.summary?.toLowerCase().includes(q)
      || r.version?.toLowerCase().includes(q)
  })

  $: columns = [
    { key: 'package',   label: $t('vulnerabilities.columns.package'),   sortable: true,  width: '200px' },
    { key: 'version',   label: $t('vulnerabilities.columns.version'),   sortable: true,  width: '110px' },
    { key: 'severity',  label: $t('vulnerabilities.columns.severity'),  sortable: true,  width: '90px',  defaultDir: 'desc' },
    { key: 'score',     label: $t('vulnerabilities.columns.score'),     sortable: true,  width: '70px',  defaultDir: 'desc' },
    { key: 'epss',      label: $t('vulnerabilities.columns.epss'),      sortable: true,  width: '70px',  defaultDir: 'desc' },
    { key: 'osvId',     label: $t('vulnerabilities.columns.osvId'),     sortable: true,  width: '170px' },
    { key: 'summary',   label: $t('vulnerabilities.columns.summary'),   sortable: true },
    { key: 'published', label: $t('vulnerabilities.columns.published'), sortable: true,  width: '135px', defaultDir: 'desc' },
  ]

  const comparators = {
    package:   (a, b) => (a.packageName ?? '').localeCompare(b.packageName ?? ''),
    version:   (a, b) => (a.version ?? '').localeCompare(b.version ?? ''),
    severity:  (a, b) => (SEVERITY_RANK[a.severity?.toLowerCase()] ?? 0) - (SEVERITY_RANK[b.severity?.toLowerCase()] ?? 0),
    score:     (a, b) => (a.cvssScore ?? -1) - (b.cvssScore ?? -1),
    epss:      (a, b) => (a.epssScore ?? -1) - (b.epssScore ?? -1),
    osvId:     (a, b) => (a.osvId ?? '').localeCompare(b.osvId ?? ''),
    summary:   (a, b) => (a.summary ?? '').localeCompare(b.summary ?? ''),
    published: (a, b) => (a.publishedAt ?? '').localeCompare(b.publishedAt ?? ''),
  }
</script>

<div class="page page-fluid">
  <div class="page-header">
    <h1 class="page-title">{$t('vulnerabilities.title')}</h1>
  </div>

  <div class="page-toolbar">
    <SearchInput placeholder="Search package, OSV ID, summary…" bind:value={search} on:search={sync} class="toolbar-search" />
    <select bind:value={ecosystem} on:change={handleEcoChange} class="eco-select">
      <option value="">{$t('common.allEcosystems')}</option>
      {#each ECOSYSTEMS as eco (eco)}
        <option value={eco}>{ECO_LABEL[eco]}</option>
      {/each}
    </select>
    <div class="sev-filter" role="group" aria-label={$t('vulnerabilities.severityFilter.label')}>
      <button class="sev-chip" class:active={severityFilter === ''} on:click={() => setSeverity('')}>
        {$t('vulnerabilities.severityFilter.all')}
      </button>
      {#each SEVERITIES as s (s)}
        <button class="sev-chip" class:active={severityFilter === s} on:click={() => setSeverity(s)}>
          <span class="sev-dot sev-{s}" aria-hidden="true"></span>{$t(`vulnerabilities.severityFilter.${s}`)}
        </button>
      {/each}
    </div>
    <span class="revoked-filter">
      <Toggle bind:checked={revokedOnly} ariaLabel={$t('vulnerabilities.revokedOnly')} />
      {$t('vulnerabilities.revokedOnly')}
    </span>
  </div>

  <ErrorBanner message={error} />

  <DataTable
    {columns}
    rows={filtered}
    {comparators}
    {loading}
    loadingRows={limit}
    memoryKey="vulnerabilities"
    loadingRowHeight="48px"
    initialSort={{ key: sortCol, dir: sortDir }}
    on:sortchange={onSortChange}
    emptyText={$t('vulnerabilities.empty')}
    tableClass="table-auto vulns-table"
    let:row={r}
  >
    <tr
      class="vuln-row cursor-pointer"
      class:expanded-row={expandedKey === `${r.purl}::${r.osvId}`}
      on:click={() => toggleRow(r)}
    >
      <td>
        <div class="pkg-cell">
          <span class="badge {r.ecosystem}">{r.ecosystem}</span>
          <span class="mono pkg-name" title={r.packageName}>{r.packageName}</span>
        </div>
      </td>
      <td class="mono nowrap" title={r.purl}>
        {r.version}
        {#if r.revokedAt}<span class="badge revoked ml-1" title={$t('vulnerabilities.revokedHelp', { values: { at: $formatDate(r.revokedAt) } })}><svg width="10" height="10" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>{$t('vulnerabilities.revoked')}</span>{/if}
      </td>
      <td class="nowrap">
        {#if r.osvId?.startsWith('MAL-')}
          <!-- Malicious-package advisories are a verdict, not a score — surfaced ahead of any
               CVSS severity the advisory might also carry. -->
          <span class="sev sev-malicious">{$t('vulnerabilities.malicious')}</span>
        {:else if r.severity}
          <span class="sev sev-{r.severity.toLowerCase()}">{r.severity}</span>
        {:else}
          <span class="text-muted">—</span>
        {/if}
        {#if r.isKev}
          <span class="badge kev ml-1" title={$t('vulnerabilities.kevHelp')}>{$t('vulnerabilities.kev')}</span>
        {/if}
      </td>
      <td class="mono nowrap text-muted">
        {r.cvssScore !== null && r.cvssScore !== undefined ? r.cvssScore.toFixed(1) : '—'}
      </td>
      <td class="mono nowrap text-muted">
        {r.epssScore !== null && r.epssScore !== undefined ? `${(r.epssScore * 100).toFixed(1)}%` : '—'}
      </td>
      <td class="mono nowrap">
        <a href="https://osv.dev/vulnerability/{r.osvId}" target="_blank" rel="noreferrer" on:click|stopPropagation>{r.osvId}</a>
      </td>
      <td class="summary-cell text-muted">
        <div class="summary-clamp" title={r.summary ?? ''}>{r.summary ?? '—'}</div>
      </td>
      <td class="nowrap text-muted t-sm">
        {r.publishedAt ? $formatDate(r.publishedAt) : '—'}
      </td>
    </tr>

    {#if expandedKey === `${r.purl}::${r.osvId}`}
      {@const d = expandedDetail}
      <tr class="detail-row">
        <td colspan={columns.length}>
          <div class="detail-panel">
            {#if !d || d.loading}
              <div class="detail-status">{$t('vulnerabilities.detail.loading')}</div>
            {:else if d.error}
              <div class="detail-status detail-error">{$t('vulnerabilities.detail.error')}</div>
            {:else if d.detail}
              {@const v = d.detail}
              {@const fixedVersion = resolvedFixedVersion(v.remediation, v.affected)}
              {@const briefKey = `${r.purl}::${r.osvId}::brief`}

              {#if v.withdrawn}
                <div class="withdrawn-notice">{$t('vulnerabilities.detail.withdrawnNotice')}</div>
              {/if}

              <div class="brief-actions">
                <button
                  class="brief-copy-btn"
                  on:click|stopPropagation={() => copyRemediation(briefKey, remediationBrief({
                    osvId: r.osvId,
                    summary: v.summary ?? r.summary,
                    purl: r.purl,
                    installedVersion: r.version,
                    fixedVersion,
                    remediation: v.remediation,
                  }))}
                  title={$t('vulnerabilities.detail.remediation.copyBriefHelp')}
                >
                  {remediationCopyState[briefKey] === 'copied' ? $t('common.actions.copied') : remediationCopyState[briefKey] === 'failed' ? $t('common.actions.copyFailed') : $t('vulnerabilities.detail.remediation.copyBrief')}
                </button>
              </div>

              <div class="detail-meta">
                <div class="meta-item">
                  <span class="detail-label">{$t('vulnerabilities.columns.checkedAt')}</span>
                  <span class="detail-value">{r.vulnCheckedAt ? $formatDate(r.vulnCheckedAt) : '—'}</span>
                </div>
                <div class="meta-item">
                  <span class="detail-label">{$t('vulnerabilities.columns.published')}</span>
                  <span class="detail-value">{(r.publishedAt ?? v.published) ? $formatDate(r.publishedAt ?? v.published) : '—'}</span>
                </div>
                {#if v.modified}
                  <div class="meta-item">
                    <span class="detail-label">{$t('vulnerabilities.detail.modified')}</span>
                    <span class="detail-value">{$formatDate(v.modified)}</span>
                  </div>
                {/if}
                {#if v.withdrawn}
                  <div class="meta-item">
                    <span class="detail-label">{$t('vulnerabilities.detail.withdrawn')}</span>
                    <span class="detail-value">{$formatDate(v.withdrawn)}</span>
                  </div>
                {/if}
                {#if v.threatIntel?.epssScore !== null && v.threatIntel?.epssScore !== undefined}
                  <div class="meta-item">
                    <span class="detail-label">{$t('vulnerabilities.detail.epss')}</span>
                    <span class="detail-value mono" title={$t('vulnerabilities.detail.epssHelp')}>{(v.threatIntel.epssScore * 100).toFixed(1)}%</span>
                  </div>
                {/if}
                {#if v.threatIntel?.isKev}
                  <div class="meta-item">
                    <span class="detail-label">{$t('vulnerabilities.detail.kev')}</span>
                    <a class="badge kev" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer" on:click|stopPropagation title={$t('vulnerabilities.kevHelp')}>{$t('vulnerabilities.kev')}</a>
                  </div>
                {/if}
              </div>

              {#if v.summary ?? r.summary}
                <p class="detail-summary">{v.summary ?? r.summary}</p>
              {/if}

              {#if v.aliases?.length}
                <div class="detail-section">
                  <span class="detail-label">{$t('vulnerabilities.detail.aliases')}</span>
                  <span class="chip-list">{#each v.aliases as a (a)}{#if aliasUrl(a)}<a class="chip mono" href={aliasUrl(a)} target="_blank" rel="noreferrer" on:click|stopPropagation>{a}</a>{:else}<span class="chip mono">{a}</span>{/if}{/each}</span>
                </div>
              {/if}

              {#if v.related?.length}
                <div class="detail-section">
                  <span class="detail-label">{$t('vulnerabilities.detail.related')}</span>
                  <span class="chip-list">{#each v.related as a (a)}{#if aliasUrl(a)}<a class="chip mono" href={aliasUrl(a)} target="_blank" rel="noreferrer" on:click|stopPropagation>{a}</a>{:else}<span class="chip mono">{a}</span>{/if}{/each}</span>
                </div>
              {/if}

              {#if v.references?.length}
                <div class="detail-section col">
                  <span class="detail-label">{$t('vulnerabilities.detail.references')}</span>
                  <ul class="ref-list">
                    {#each v.references as ref, ri (ri)}
                      <li>
                        {#if ref.type}<span class="ref-type">{ref.type}</span>{/if}
                        <a href={ref.url} target="_blank" rel="noreferrer" on:click|stopPropagation>{ref.url}</a>
                      </li>
                    {/each}
                  </ul>
                </div>
              {/if}

              {@const skillIds = remediationSkillIds(v.remediation)}
              {#if v.remediation?.entries?.length || skillIds.length}
                <div class="detail-section col remediation-section">
                  <span class="detail-label">{$t('vulnerabilities.detail.remediation.title')}</span>

                  {#if fixedVersion}
                    <div class="fixed-in">
                      <span class="text-muted">{$t('vulnerabilities.detail.remediation.fixedIn')}</span>
                      <span class="mono">{fixedVersion}</span>
                    </div>
                  {/if}

                  {#if v.remediation.entries.length}
                    <div class="cwe-list">
                      {#each v.remediation.entries as entry, ei (ei)}
                        <span class="cwe-entry">
                          <a class="chip mono" href={entry.cweUrl} target="_blank" rel="noreferrer" on:click|stopPropagation>{entry.cweId}</a>
                          {#if entry.owaspId}
                            <a class="chip owasp-chip" href={entry.owaspUrl} target="_blank" rel="noreferrer" on:click|stopPropagation>{entry.owaspId} {entry.owaspTitle}</a>
                          {/if}
                        </span>
                      {/each}
                    </div>
                  {/if}

                  {#if skillIds.length}
                    <div class="agent-heading-row">
                      <span class="detail-label agent-heading">{$t('vulnerabilities.detail.remediation.fixWithAgent')}</span>
                      <div class="assistant-picker" role="group" aria-label={$t('vulnerabilities.detail.remediation.assistantLabel')}>
                        {#each ASSISTANTS as a (a.id)}
                          <button class="assistant-chip" class:active={assistant === a.id} on:click|stopPropagation={() => setAssistant(a.id)}>{a.label}</button>
                        {/each}
                      </div>
                    </div>
                  {/if}
                  {#each skillIds as skillId (skillId)}
                    {@const installKey = `${r.purl}::${r.osvId}::${skillId}::${assistant}::install`}
                    {@const promptKey = `${r.purl}::${r.osvId}::${skillId}::${assistant}::prompt`}
                    <div class="skill-block">
                      <div class="skill-heading">
                        <span class="skill-name mono">{skillId}</span>
                        {#if skillDescriptions[skillId]}<span class="skill-desc text-muted">{skillDescriptions[skillId]}</span>{/if}
                      </div>

                      <span class="skill-copy-label text-muted">{$t('vulnerabilities.detail.remediation.installLabel')}</span>
                      <div class="copy-block skill-copy-block">
                        <span class="copy-block-text">{skillInstallCommand(skillId, window.location.origin, assistant)}</span>
                        <button class="copy-btn" on:click|stopPropagation={() => copyRemediation(installKey, skillInstallCommand(skillId, window.location.origin, assistant))}>
                          {remediationCopyState[installKey] === 'copied' ? $t('common.actions.copied') : remediationCopyState[installKey] === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
                        </button>
                      </div>

                      <span class="skill-copy-label text-muted">{$t('vulnerabilities.detail.remediation.promptLabel')}</span>
                      <div class="copy-block skill-copy-block">
                        <span class="copy-block-text">{skillPrompt(skillId, r.osvId, r.purl, r.version, fixedVersion, assistant)}</span>
                        <button class="copy-btn" on:click|stopPropagation={() => copyRemediation(promptKey, skillPrompt(skillId, r.osvId, r.purl, r.version, fixedVersion, assistant))}>
                          {remediationCopyState[promptKey] === 'copied' ? $t('common.actions.copied') : remediationCopyState[promptKey] === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
                        </button>
                      </div>
                    </div>
                  {/each}
                </div>
              {/if}

              {#if v.affected?.length}
                <div class="detail-section col">
                  <span class="detail-label">{$t('vulnerabilities.detail.affected')}</span>
                  <div class="affected-list">
                    {#each v.affected as af, ai (ai)}
                      <div class="affected-item">
                        {#if af.package?.purl || af.package?.name}
                          <code class="mono affected-pkg">{af.package?.purl ?? `${af.package?.ecosystem ?? ''}/${af.package?.name ?? ''}`}</code>
                        {/if}
                        {#each af.ranges ?? [] as rng, ri (ri)}
                          <span class="range">
                            {#each rng.events ?? [] as ev, ei (ei)}
                              {#if ev.introduced}<span class="range-ev">≥ {ev.introduced}</span>{/if}
                              {#if ev.fixed}<span class="range-ev fixed">&lt; {ev.fixed}</span>{/if}
                              {#if ev.lastAffected}<span class="range-ev">≤ {ev.lastAffected}</span>{/if}
                            {/each}
                          </span>
                        {/each}
                        {#if af.versions?.length}
                          <div class="versions"><span class="text-muted">{$t('vulnerabilities.detail.versions')}:</span> <span class="mono">{af.versions.join(', ')}</span></div>
                        {/if}
                      </div>
                    {/each}
                  </div>
                </div>
              {/if}

              {#if v.credits?.length}
                <div class="detail-section">
                  <span class="detail-label">{$t('vulnerabilities.detail.credits')}</span>
                  <span class="detail-value">{v.credits.map(c => c.name).filter(Boolean).join(', ') || '—'}</span>
                </div>
              {/if}

              {#if v.details}
                <div class="detail-section col">
                  <span class="detail-label">{$t('vulnerabilities.detail.details')}</span>
                  <pre class="osv-details">{v.details}</pre>
                </div>
              {/if}

              {#if v.databaseSpecific}
                <div class="detail-section col">
                  <span class="detail-label">{$t('vulnerabilities.detail.databaseSpecific')}</span>
                  <pre class="osv-json">{JSON.stringify(v.databaseSpecific, null, 2)}</pre>
                </div>
              {/if}
            {/if}
          </div>
        </td>
      </tr>
    {/if}
  </DataTable>

  <Pagination {total} {page} {limit}
    on:pagechange={onPageChange}
    on:limitchange={onLimitChange} />
</div>

<style>
  td { vertical-align: middle; }
  .nowrap { white-space: nowrap; }
  .pkg-cell { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
  .pkg-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .summary-clamp {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }
  .summary-cell { font-size: 13px; }

  /* Expandable detail row — mirrors the VersionTable.svelte pattern. */
  .vuln-row { cursor: pointer; }
  .expanded-row td { background: var(--surface2); }
  .detail-row td { padding: 0; border-top: none; background: var(--surface2); }

  .detail-panel {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 16px 16px;
    font-size: 13px;
  }
  .detail-status { color: var(--text2); font-style: italic; }
  .detail-error { color: var(--badge-red-text); font-style: normal; }

  .brief-actions { display: flex; justify-content: flex-end; }
  .brief-copy-btn {
    min-height: 0; /* the global button min-height would balloon this compact action */
    padding: 4px 10px;
    font-size: 12px;
  }

  .withdrawn-notice {
    background: var(--badge-warning-bg);
    color: var(--badge-warning-text);
    border-radius: var(--radius);
    padding: 6px 10px;
    font-weight: 600;
  }

  .detail-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 24px;
  }
  .meta-item { display: flex; gap: 8px; align-items: baseline; }

  .detail-summary { margin: 0; color: var(--text); overflow-wrap: anywhere; }

  .detail-section { display: flex; gap: 10px; align-items: baseline; }
  .detail-section.col { flex-direction: column; gap: 4px; }
  .detail-label {
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    flex-shrink: 0;
    min-width: 90px;
  }
  .detail-value { color: var(--text); overflow-wrap: anywhere; }

  .chip-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip {
    background: var(--bg3);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
  }

  .ref-list { margin: 0; padding-left: 0; list-style: none; display: flex; flex-direction: column; gap: 3px; }
  .ref-list li { display: flex; gap: 8px; align-items: baseline; overflow-wrap: anywhere; }
  .ref-type {
    color: var(--text2);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    flex-shrink: 0;
    min-width: 70px;
  }

  .affected-list { display: flex; flex-direction: column; gap: 8px; }
  .affected-item { display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; }
  .affected-pkg { font-size: 12px; }
  .range { display: inline-flex; gap: 4px; }
  .range-ev {
    background: var(--bg3);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
    font-family: var(--font-mono, monospace);
  }
  .range-ev.fixed { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .versions { flex-basis: 100%; font-size: 12px; }

  .osv-details, .osv-json {
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

  .remediation-section { gap: 10px; }
  .fixed-in { display: flex; gap: 8px; align-items: baseline; font-size: 13px; }
  .agent-heading { margin-top: 4px; }
  .agent-heading-row { display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; }
  .assistant-picker { display: flex; gap: 4px; }
  .assistant-chip {
    min-height: 0; /* the global button min-height would balloon these compact chips */
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text2);
    padding: 3px 10px;
    font-size: 12px;
    line-height: 1.4;
    border-radius: 999px;
    cursor: pointer;
  }
  .assistant-chip:hover { background: var(--bg3); color: var(--text); }
  .assistant-chip.active {
    background: var(--accent-soft);
    border-color: var(--accent);
    color: var(--accent);
    font-weight: 600;
  }
  .cwe-list { display: flex; flex-wrap: wrap; gap: 6px; }
  .cwe-entry { display: inline-flex; gap: 4px; align-items: center; }
  .owasp-chip { background: var(--accent-soft); color: var(--accent); }
  .cwe-entry a.chip { text-decoration: none; }

  .skill-block {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .skill-heading { display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: baseline; }
  .skill-name { font-size: 13px; font-weight: 600; }
  .skill-desc { font-size: 12px; }
  .skill-copy-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; margin-top: 2px; }
  .skill-copy-block { font-size: 12px; }
</style>
