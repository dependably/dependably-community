<!--
  Expanded-row panel for one SBOM component: where it came from in the dependency graph, and
  one block per advisory recorded against it.

  Everything rendered here arrives in the analysis payload — severity, CVSS, KEV, EPSS,
  reachability, the policy verdict and the effective-priority bucket are all decided
  server-side. The panel picks badge classes and locale keys; it never recomputes a verdict.

  Uncertainty is rendered, not hidden: an advisory nobody scored says UNSCORED and NO CVSS
  rather than showing a blank cell, and a reachability the SBOM never carried renders as an em
  dash rather than as "unknown" — "nobody told us" and "the analyzer said unknown" are
  different statements and the panel keeps them apart.

  The SSVC and NVD/GHSA band chips render only when the payload carries them. Nothing emits
  them yet; an unconfigured overlay produces no chips at all.

  Props:
    item            one component row from the analysis payload
    showSuppressed  whether suppressed advisories are visible (they render dimmed)
    canEdit         admin/owner — passed through to the triage editor
    savingKey       vulnKey whose triage PUT is in flight, or ''
    saveErrorKey    vulnKey the last failed save belongs to, or ''
    saveError       message from the last failed save
    saveToken       bumped by the parent after a save lands

  Events:
    save  { purlKey, vulnKey, body } — forwarded from the triage editor
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { aliasUrl } from '../advisories.js'
  import { copyToClipboard } from '../clipboard.js'
  import { navigate } from '../store.js'
  import { pathFor, searchFor } from '../routes.js'
  import { remediationSkillIds, resolvedFixedVersion } from '../remediation.js'
  import DependencyPath from './DependencyPath.svelte'
  import VexAnalysisEditor from './VexAnalysisEditor.svelte'
  import { isSuppressed, overlayChips, reachBadge, visibleAdvisories } from './analysis.js'

  /** @type {Record<string, any>} */
  export let item = {}
  export let showSuppressed = false
  export let canEdit = false
  export let savingKey = ''
  export let saveErrorKey = ''
  export let saveError = ''
  export let saveToken = 0

  const dispatch = createEventDispatcher()

  // The analysis row is keyed by the component's PURL; the payload may name it explicitly.
  $: purlKey = item.purlKey ?? item.purl ?? ''
  // The server resolves whether a component is served from this registry and may supply the
  // link itself; the SPA route is the fallback so the anchor always carries a real href.
  $: purlHref = item.registryLink ?? pathFor('version-detail', { ecosystem: item.ecosystem, name: item.name })
  $: advisories = visibleAdvisories(item, showSuppressed)
  // Component-level findings naming no advisory — the licence arm's shape. Every finding
  // naming an advisory already renders inside that advisory's own block below; rendering it
  // again here would duplicate it, so only the vulnKey-less ones surface.
  $: otherViolations = (item.policyViolations ?? []).filter(v => !v.vulnKey)

  function onSave(advisory, e) {
    dispatch('save', { purlKey, vulnKey: advisory.vulnKey, body: e.detail.body })
  }

  function openPurlRegistry(e) {
    e.stopPropagation()
    if (item.ecosystem && item.name) navigate('version-detail', { ecosystem: item.ecosystem, name: item.name })
  }

  // Advisory ids link into our own Vulnerabilities page (scoped to this one OSV id) rather than
  // out to osv.dev — our record carries KEV/EPSS threat intel, blast radius, and remediation
  // guidance the public OSV entry does not.
  function openAdvisory(osvId) {
    navigate('vulnerabilities', { q: osvId })
  }

  // Local to this panel, mirroring `openOsvId`/`openDetail` below rather than reaching into
  // parent state — there is only ever one purl row per expanded panel.
  let purlCopied = false
  async function copyPurl(e) {
    e.stopPropagation()
    purlCopied = await copyToClipboard(item.purl)
    if (purlCopied) setTimeout(() => { purlCopied = false }, 2000)
  }

  // ── Remediation guidance ────────────────────────────────────────────────────
  // The advisory-detail endpoint already resolves "upgrade to X" against the installed version
  // under the ecosystem's native ordering, maps CWE to OWASP, and names curated remediation
  // skills. The component row carries `version`, so passing it through gets the same
  // fixed-version resolution the registry's own vulnerability report gets.
  //
  // Loaded on demand, one advisory at a time: the analysis page renders many advisories per
  // component and fetching them all up front would issue a request per row for guidance most
  // readers never open.
  //
  // Keyed by `${osvId}::${version}` because the server resolves the fixed version against the
  // installed one — the same advisory under another version is a different answer.
  let openOsvId = ''
  /** @type {{ loading: boolean, error: boolean, detail: any }|null} */
  let openDetail = null
  // Deliberately a plain Map: reactivity is driven by `openDetail`, not by this cache.
  // eslint-disable-next-line svelte/prefer-svelte-reactivity
  const detailCache = new Map()

  async function toggleRemediation(advisory) {
    if (!advisory.osvId) return
    if (openOsvId === advisory.osvId) { openOsvId = ''; openDetail = null; return }
    openOsvId = advisory.osvId

    const cacheKey = `${advisory.osvId}::${item.version ?? ''}`
    const cached = detailCache.get(cacheKey)
    if (cached) { openDetail = cached; return }

    openDetail = { loading: true, error: false, detail: null }
    try {
      const detail = await api.getVulnDetail(advisory.osvId, item.version)
      const loaded = { loading: false, error: false, detail }
      detailCache.set(cacheKey, loaded)
      // Ignore a late resolve if the reader collapsed this advisory or opened another meanwhile.
      if (openOsvId === advisory.osvId) openDetail = loaded
    } catch (e) {
      console.error(e)
      if (openOsvId === advisory.osvId) openDetail = { loading: false, error: true, detail: null }
    }
  }
</script>

<div class="advisory-panel">
  <div class="detail-section col">
    <span class="detail-label">{$t('sbomAnalysis.panel.purl')}</span>
    <span class="purl-wrap">
      {#if item.inRegistry}
        <a class="mono" href={purlHref} on:click|preventDefault={openPurlRegistry}>{item.purl}</a>
      {:else}
        <span class="mono" title={item.purl}>{item.purl}</span>
      {/if}
      <button
        type="button"
        class="copy-btn"
        aria-label={$t('sbomAnalysis.copyPurl')}
        title={purlCopied ? $t('common.actions.copied') : $t('sbomAnalysis.copyPurl')}
        on:click={copyPurl}
      >
        <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-{purlCopied ? 'check' : 'copy'}"/></svg>
      </button>
    </span>
  </div>

  {#if item.dependencyPath?.length}
    <div class="detail-section col">
      <span class="detail-label">{$t('sbomAnalysis.panel.dependencyPath')}</span>
      <DependencyPath path={item.dependencyPath} />
    </div>
  {/if}

  {#if otherViolations.length}
    <!-- Findings naming no advisory — the licence arm's shape. Rendered whether or not the
         component carries any advisory, so a licence-only violation is visible on a row the
         advisory-only view would otherwise report as clean. -->
    <div class="detail-section col">
      <span class="detail-label">{$t('sbomAnalysis.panel.otherViolations')}</span>
      {#each otherViolations as v, vi (vi)}
        <p class="verdict">
          <span class="badge danger">{$t('sbomAnalysis.panel.blockedBy', { values: { arm: v.arm } })}</span>
          {#if v.licenseSpdx}<span class="verdict-detail mono">{v.licenseSpdx}</span>{/if}
          {#if v.detail}<span class="verdict-detail">{v.detail}</span>{/if}
        </p>
      {/each}
    </div>
  {/if}

  {#if advisories.length === 0}
    <p class="detail-status">
      {#if (item.advisories ?? []).length > 0}
        {$t('sbomAnalysis.panel.allSuppressed')}
      {:else}
        {$t('sbomAnalysis.panel.noAdvisories')}
      {/if}
    </p>
  {/if}

  {#each advisories as a (a.vulnKey)}
    {@const suppressed = isSuppressed(a)}
    {@const reach = reachBadge(a.reachability)}
    {@const chips = overlayChips(a)}
    <div class="advisory" class:suppressed>
      <div class="advisory-head">
        {#if a.osvId}
          <a class="mono advisory-id" href="{pathFor('vulnerabilities')}{searchFor('vulnerabilities', { q: a.osvId })}" on:click|preventDefault|stopPropagation={() => openAdvisory(a.osvId)}>{a.osvId}</a>
        {:else}
          <span class="mono advisory-id">{a.vulnKey}</span>
        {/if}

        {#if a.unscored}
          <span class="sev sev-unknown" aria-label={$t('sbomAnalysis.panel.unscoredHelp')} title={$t('sbomAnalysis.panel.unscoredHelp')}>{$t('sbomAnalysis.panel.unscored')}</span>
        {:else if a.severity}
          <span class="sev sev-{String(a.severity).toLowerCase()}" aria-label={a.severity}>{a.severity}</span>
        {/if}

        {#if a.isKevRansomware === true}
          <span class="badge kev ransomware" title={$t('sbomAnalysis.panel.kevRansomwareHelp')} aria-label={$t('sbomAnalysis.panel.kevRansomwareHelp')}>{$t('sbomAnalysis.panel.kevRansomware')}</span>
        {:else if a.isKev}
          <span class="badge kev" title={$t('sbomAnalysis.panel.kevHelp')} aria-label={$t('sbomAnalysis.panel.kevHelp')}>{$t('sbomAnalysis.panel.kev')}</span>
        {/if}

        {#if suppressed}
          <span class="badge prio-suppressed" aria-label={$t('sbomAnalysis.priority.suppressed')}>{$t('sbomAnalysis.priority.suppressed')}</span>
        {:else if a.effectivePriority}
          <span class="badge prio-{a.effectivePriority}" title={$t('sbomAnalysis.priority.help')} aria-label={$t(`sbomAnalysis.priority.${a.effectivePriority}`)}>
            {$t(`sbomAnalysis.priority.${a.effectivePriority}`)}
          </span>
        {/if}

        {#each chips as c (c.key)}
          <span class="badge overlay-{c.kind}" title={c.title ?? undefined} aria-label={c.value}>{c.value}</span>
        {/each}
      </div>

      <div class="detail-meta">
        <div class="meta-item">
          <span class="detail-label">{$t('sbomAnalysis.panel.cvss')}</span>
          {#if a.cvss === null || a.cvss === undefined}
            <span class="detail-value text-muted" title={$t('sbomAnalysis.panel.noCvssHelp')}>{$t('sbomAnalysis.panel.noCvss')}</span>
          {:else}
            <span class="detail-value mono">{Number(a.cvss).toFixed(1)}</span>
          {/if}
        </div>
        {#if a.epss !== null && a.epss !== undefined}
          <div class="meta-item">
            <span class="detail-label">{$t('sbomAnalysis.panel.epss')}</span>
            <span class="detail-value mono" title={$t('sbomAnalysis.panel.epssHelp')}>{(Number(a.epss) * 100).toFixed(1)}%</span>
          </div>
        {/if}
        <div class="meta-item">
          <span class="detail-label">{$t('sbomAnalysis.panel.reachability')}</span>
          {#if reach}
            <span class="badge {reach.cls}" aria-label={reach.labelKey ? $t(reach.labelKey) : reach.raw}>
              {reach.labelKey ? $t(reach.labelKey) : reach.raw}
            </span>
          {:else}
            <span class="detail-value text-muted" title={$t('sbomAnalysis.panel.noReachabilityHelp')}>&#8212;</span>
          {/if}
        </div>
        {#if a.confidence !== null && a.confidence !== undefined && a.confidence !== ''}
          <div class="meta-item">
            <span class="detail-label">{$t('sbomAnalysis.panel.confidence')}</span>
            <span class="detail-value mono">{a.confidence}</span>
          </div>
        {/if}
        {#if a.securitySeverity !== null && a.securitySeverity !== undefined}
          <div class="meta-item">
            <span class="detail-label">{$t('sbomAnalysis.panel.securitySeverity')}</span>
            <span class="detail-value mono">{a.securitySeverity}</span>
          </div>
        {/if}
        {#if a.severityOrigin}
          <div class="meta-item">
            <span class="detail-label">{$t('sbomAnalysis.panel.severityOrigin')}</span>
            <span class="detail-value">{a.severityOrigin}</span>
          </div>
        {/if}
        {#if a.sarifSuppressed}
          <div class="meta-item">
            <span class="detail-label">{$t('sbomAnalysis.panel.sarifSuppressed')}</span>
            <span class="detail-value">{$t('sbomAnalysis.panel.sarifSuppressedHelp')}</span>
          </div>
        {/if}
      </div>

      {#if a.aliases?.length}
        <div class="detail-section">
          <span class="detail-label">{$t('sbomAnalysis.panel.aliases')}</span>
          <span class="chip-list">
            {#each a.aliases as alias (alias)}
              {#if aliasUrl(alias)}
                <a class="chip mono" href={aliasUrl(alias)} target="_blank" rel="noreferrer" on:click|stopPropagation>{alias}</a>
              {:else}
                <span class="chip mono">{alias}</span>
              {/if}
            {/each}
          </span>
        </div>
      {/if}

      {#if a.policyViolations?.length}
        <div class="detail-section col">
          <span class="detail-label">{$t('sbomAnalysis.panel.policyVerdict')}</span>
          {#each a.policyViolations as v, vi (vi)}
            <p class="verdict">
              <span class="badge danger">{$t('sbomAnalysis.panel.blockedBy', { values: { arm: v.arm } })}</span>
              {#if v.detail}<span class="verdict-detail">{v.detail}</span>{/if}
            </p>
          {/each}
        </div>
      {/if}

      {#if a.osvId}
        <div class="remediation">
          <button
            type="button"
            class="remediation-toggle"
            aria-expanded={openOsvId === a.osvId}
            on:click|stopPropagation={() => toggleRemediation(a)}
          >
            <svg class="chev" class:open={openOsvId === a.osvId} width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down"/></svg>
            {$t('sbomAnalysis.panel.remediation.toggle')}
          </button>

          {#if openOsvId === a.osvId}
            {@const d = openDetail}
            {#if !d || d.loading}
              <p class="detail-status">{$t('sbomAnalysis.panel.remediation.loading')}</p>
            {:else if d.error}
              <p class="detail-status detail-error">{$t('sbomAnalysis.panel.remediation.error')}</p>
            {:else if d.detail}
              {@const v = d.detail}
              {@const fixedVersion = resolvedFixedVersion(v.remediation, v.affected)}
              {@const skillIds = remediationSkillIds(v.remediation)}
              <div class="remediation-body">
                {#if fixedVersion}
                  <p class="fixed-in">
                    <span class="detail-label">{$t('sbomAnalysis.panel.remediation.fixedIn')}</span>
                    <span class="mono">{fixedVersion}</span>
                  </p>
                {:else}
                  <!-- No fixed version is a real answer, not a missing one: the advisory names
                       no release that resolves it for the version this application ships. -->
                  <p class="detail-status">{$t('sbomAnalysis.panel.remediation.noFixedVersion')}</p>
                {/if}

                {#if v.summary}<p class="detail-summary">{v.summary}</p>{/if}

                {#if v.remediation?.entries?.length}
                  <div class="chip-list">
                    {#each v.remediation.entries as entry, ei (ei)}
                      <a class="chip mono" href={entry.cweUrl} target="_blank" rel="noreferrer" on:click|stopPropagation>{entry.cweId}</a>
                      {#if entry.owaspId}
                        <a class="chip" href={entry.owaspUrl} target="_blank" rel="noreferrer" on:click|stopPropagation>{entry.owaspId} {entry.owaspTitle}</a>
                      {/if}
                    {/each}
                  </div>
                {/if}

                {#if skillIds.length}
                  <p class="detail-label">{$t('sbomAnalysis.panel.remediation.skills')}</p>
                  <div class="chip-list">
                    {#each skillIds as skillId (skillId)}
                      <span class="chip mono">{skillId}</span>
                    {/each}
                  </div>
                {/if}

                {#if v.references?.length}
                  <ul class="ref-list">
                    {#each v.references.slice(0, 5) as ref, ri (ri)}
                      <li><a href={ref.url} target="_blank" rel="noreferrer" on:click|stopPropagation>{ref.url}</a></li>
                    {/each}
                  </ul>
                {/if}
              </div>
            {/if}
          {/if}
        </div>
      {/if}

      <VexAnalysisEditor
        advisory={a}
        {purlKey}
        {canEdit}
        {saveToken}
        saving={savingKey === a.vulnKey}
        error={saveErrorKey === a.vulnKey ? saveError : ''}
        on:save={(e) => onSave(a, e)}
      />
    </div>
  {/each}
</div>

<style>
  .advisory-panel { display: flex; flex-direction: column; gap: 12px; font-size: 13px; }

  /* Detail-row idioms carried over from the Vulnerabilities detail panel. `.detail-panel`,
     `.detail-section`, `.detail-label` and `.detail-value` are global; these are the local
     companions that page also declares for itself. */
  .detail-status { color: var(--text2); font-style: italic; margin: 0; }
  .detail-section.col { flex-direction: column; align-items: flex-start; gap: 4px; }
  .purl-wrap { display: inline-flex; align-items: center; gap: 6px; min-width: 0; }
  .purl-wrap .mono { overflow-wrap: anywhere; }
  /* Compact in-cell button: the global button min-height would balloon this row. */
  .copy-btn {
    min-height: 0;
    padding: 2px 5px;
    background: transparent;
    border: 1px solid transparent;
    color: var(--text2);
    cursor: pointer;
    line-height: 1;
  }
  .copy-btn:hover { background: var(--bg3); color: var(--text); }
  .detail-meta { display: flex; flex-wrap: wrap; gap: 6px 24px; }
  .meta-item { display: flex; gap: 8px; align-items: baseline; }
  .meta-item .detail-value { flex: 0 1 auto; }
  .chip-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip {
    background: var(--bg3);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
  }

  .advisory {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
  }
  /* A suppressed advisory is still readable — dimmed enough to recede, never hidden behind a
     styling choice the reader cannot undo. The "Show suppressed" toggle is what hides it. */
  .advisory.suppressed { opacity: 0.65; }

  .advisory-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .advisory-id { font-size: 13px; font-weight: 600; }

  .verdict { margin: 0; display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }
  .verdict-detail { color: var(--text2); font-size: 12px; overflow-wrap: anywhere; }

  /* Remediation guidance, fetched on demand from the advisory-detail endpoint the registry's own
     vulnerability report already uses. */
  .remediation { display: flex; flex-direction: column; gap: 6px; }
  .remediation-toggle {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    min-height: 26px;
    font-size: 12px;
    background: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text2);
  }
  .remediation-toggle .chev { transform: rotate(-90deg); transition: transform 120ms ease; }
  .remediation-toggle .chev.open { transform: rotate(0deg); }
  .remediation-body { display: flex; flex-direction: column; gap: 6px; }
  .detail-error { color: var(--danger-text); font-style: normal; }
  .fixed-in { margin: 0; display: flex; gap: 8px; align-items: baseline; }
  .detail-summary { margin: 0; color: var(--text2); }
  .ref-list { margin: 0; padding-left: 18px; font-size: 12px; overflow-wrap: anywhere; }
</style>
