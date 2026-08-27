<script>
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import RiskPillars from '../lib/RiskPillars.svelte'
  import VersionTable from '../lib/VersionTable.svelte'
  import { navigate, user } from '../lib/store.js'
  import { overflowCount } from '../lib/blastRadius.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { formatDate } from '../lib/format.js'
  import {
    licenseStateFor,
    resolveStateVersion,
    rowsForVersion,
    versionsBehindFor,
    worstSeverityFor
  } from '../lib/packageRisk.js'

  /**
   * The route params this page was mounted for, supplied by RouteView. Read as a prop rather than
   * from the `route` store because a deferred navigation mounts this page while the store still
   * names the page being left — asking the store would fetch the outgoing package.
   * @type {Record<string, any>}
   */
  export let params = {}

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let pkg = null, versions = [], loading = true, error = ''
  // Claim badge: surface the resolved claim state on the package header. null = no
  // claim row (implicit unclaimed in connected mode, implicit local_only in air-gap).
  let claim = null
  let scanningId = null, scanError = ''
  let vulnsByPurl = new SvelteMap()
  let versionTable
  // Blocklisted SPDX identifiers (uppercased) for the license risk-pillar summary below.
  // Fetched once per page load from the existing license-policy endpoint — no new API surface.
  let licenseBlocklist = new Set()
  // Licences the org marked conditional. Separate from the blocklist because they serve — the
  // pillar reports them as "review", not as blocked.
  let licenseConditional = new Set()
  // Standing compliance notes on this package — including the rationale someone recorded when
  // accepting it under a conditional licence.
  let packageNotes = []
  let newNoteText = '', addingNote = false, noteError = ''
  let editingNoteId = null, editingNoteText = ''
  // "Which of my applications ship this?" — the reverse of the SBOM component cross-link, and the
  // question a quarantine decision on this page immediately raises. Latest project versions only.
  // Supplemental: a failure leaves the affordance unrendered rather than asserting zero.
  let blastRadius = null
  let blastRadiusOpen = false

  $: if (params.ecosystem && params.name) load()
  $: reportPageLoad(pageToken, loading)

  async function load() {
    loading = true
    versionTable?.reset()
    try {
      const data = await api.getPackage(params.ecosystem, params.name)
      pkg = data.package
      versions = data.versions
      // Resolve claim state (admin-only API; ignore on permission failures).
      try {
        claim = await api.getClaim(params.ecosystem, params.name)
      } catch { claim = null }
      // Fetch vulns for this package (supplemental — ignore errors)
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
      // License blocklist for the license risk-pillar summary (supplemental — ignore errors).
      try {
        const policy = await api.getLicensePolicy()
        licenseBlocklist = new Set((policy.blocklist || []).map(e => (e.licenseSpdx ?? '').toUpperCase()))
        licenseConditional = new Set((policy.allowlist || [])
          .filter(e => e.disposition === 'conditional')
          .map(e => (e.licenseSpdx ?? '').toUpperCase()))
      } catch { licenseBlocklist = new Set(); licenseConditional = new Set() }
      // Blast radius over the projects plane (supplemental — ignore errors). `pkg.purlName` is
      // the canonical name the SBOM components are keyed by; the route's `name` may be spelled
      // any way a client wrote it.
      try {
        blastRadius = await api.getBlastRadiusByPackage(
          pkg.ecosystem, pkg.purlName ?? params.name, { limit: 25 })
      } catch { blastRadius = null }
      await loadPackageNotes()
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  // ── Three-pillar risk summary (Security / License / Operational) ─────────────
  // All three describe ONE version — the one the package's state is read off,
  // resolved in packageRisk.js — not the worst value anywhere in the release
  // history. Per-version detail stays in the table below, a row at a time.

  $: stateVersion = resolveStateVersion(pkg, versions)
  $: stateRows = rowsForVersion(versions, stateVersion)
  $: worstSeverity = worstSeverityFor(stateRows, vulnsByPurl)
  $: licenseState = licenseStateFor(stateRows, licenseBlocklist, licenseConditional)
  $: versionsBehind = versionsBehindFor(stateRows)

  // Descriptors for the shared strip. Reactive rather than const so the labels follow a locale
  // change, and so every pillar re-reads its source the moment that source resolves.
  $: riskPillars = [
    {
      key: 'security',
      label: $t('versionDetail.pillars.security'),
      // UNKNOWN is the packageRisk vocabulary for "advisories exist but none carries a score";
      // it renders as the unscored chip rather than as a severity nobody assigned.
      sev: worstSeverity ? (worstSeverity === 'UNKNOWN' ? 'unknown' : worstSeverity.toLowerCase()) : null,
      text: worstSeverity
        ? (worstSeverity === 'UNKNOWN' ? $t('dashboard.unscored') : worstSeverity)
        : $t('versionDetail.pillars.noAdvisories'),
      tone: worstSeverity ? '' : 'clean',
    },
    {
      key: 'license',
      label: $t('versionDetail.pillars.license'),
      text: licenseState === 'blocked' ? $t('versionDetail.pillars.licenseBlocked')
        // No extracted SPDX entry is an unknown licence, not a clean one — the block gate
        // treats the two differently, so the pillar does too.
        : licenseState === 'undeclared' ? $t('versionDetail.pillars.licenseUndeclared')
        // Serves, but the org recorded a condition on the licence. Showing this as clean would
        // hide the org's own note from the person about to depend on it.
        : licenseState === 'review' ? $t('versionDetail.pillars.licenseReview')
        : $t('versionDetail.pillars.licenseClean'),
      tone: licenseState === 'blocked' ? 'warn'
        : licenseState === 'undeclared' ? 'muted'
        : licenseState === 'review' ? 'review'
        : 'clean',
    },
    {
      key: 'operational',
      label: $t('versionDetail.pillars.operational'),
      text: versionsBehind !== null
        ? $t('versionDetail.behindCell.count', { values: { count: versionsBehind } })
        : $t('versionDetail.behindCell.unscored'),
      tone: versionsBehind === null ? 'muted' : versionsBehind > 0 ? 'warn' : 'clean',
    },
  ]

  function buildVulnMap(items) {
    const map = new SvelteMap()
    for (const r of items) {
      if (!r.osvId) continue
      if (!map.has(r.purl)) map.set(r.purl, [])
      const list = map.get(r.purl)
      // Multi-file versions (Maven jar/pom, PyPI wheel/sdist) map several files to one purl, so the
      // vuln report returns the same advisory once per affected file. Collapse to one entry per
      // osvId so the per-version advisory list neither double-counts nor trips Svelte's keyed each.
      if (list.some(x => x.osvId === r.osvId)) continue
      list.push({
        osvId: r.osvId,
        severity: r.severity,
        summary: r.summary,
        cvssScore: r.cvssScore,
        isKev: r.isKev,
        epssScore: r.epssScore
      })
    }
    return map
  }

  async function deleteVersion(ver) {
    if (!confirm($t('versionDetail.deleteTitle', { values: { version: ver.version } }))) return
    await api.deleteVersion(params.ecosystem, params.name, ver.version)
    // Delete acts on the whole release, so drop every file row sharing the version — a multi-file
    // version (Maven jar/pom, PyPI wheel/sdist) otherwise leaves its siblings stranded in the list.
    versions = versions.filter(v => v.version !== ver.version)
  }

  // `ver.file` is set when the event comes from a per-file row in a multi-file version's expanded
  // panel; absent for single-file versions, where the server serves the version's only artifact.
  async function downloadVersion(ver) {
    try {
      await api.downloadVersion(params.ecosystem, params.name, ver.version, ver.file)
    } catch (e) { error = e.message }
  }

  async function rescan(ver) {
    scanningId = ver.id; scanError = ''
    try {
      const res = await api.rescanVersion(params.ecosystem, params.name, ver.version)
      versions = versions.map(v => v.id === ver.id ? { ...v, vulnCheckedAt: res.vuln_checked_at } : v)
      // Refresh vuln data after rescan
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
      await load()
    } catch (e) {
      scanError = e.message
    } finally {
      scanningId = null
    }
  }

  async function blockVersion(ver) {
    try {
      await api.blockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  async function unblockVersion(ver) {
    try {
      await api.unblockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  function scanCooldownRemaining(ver) {
    if (!ver.vulnCheckedAt) return 0
    const elapsed = Date.now() - new Date(ver.vulnCheckedAt).getTime()
    return Math.max(0, 3600000 - elapsed)
  }

  function copy(text) {
    copyToClipboard(text)
  }

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'

  // ── Package notes ───────────────────────────────────────────────────────────
  // Supplemental like the vuln and licence-policy fetches: a failure here must not take the
  // package page down, so the list simply stays empty.
  async function loadPackageNotes() {
    try {
      packageNotes = await api.getPackageNotes(params.ecosystem, params.name)
    } catch { packageNotes = [] }
  }

  async function addNote() {
    const text = newNoteText.trim()
    if (!text) return
    addingNote = true; noteError = ''
    try {
      // version null: a note left from the package page is about the package, not one release.
      const created = await api.addPackageNote(params.ecosystem, params.name, null, text)
      packageNotes = [created, ...packageNotes]
      newNoteText = ''
    } catch (e) { noteError = e.message ?? 'failed to add note' }
    finally { addingNote = false }
  }

  async function saveNoteEdit() {
    const text = editingNoteText.trim()
    if (!text || !editingNoteId) return
    noteError = ''
    try {
      await api.updatePackageNote(editingNoteId, text)
      packageNotes = packageNotes.map(n => (n.id === editingNoteId ? { ...n, note: text } : n))
      editingNoteId = null
    } catch (e) { noteError = e.message ?? 'failed to update note' }
  }

  async function removeNote(id) {
    if (!confirm($t('packageNotes.removeConfirm'))) return
    noteError = ''
    try {
      await api.removePackageNote(id)
      packageNotes = packageNotes.filter(n => n.id !== id)
    } catch (e) { noteError = e.message ?? 'failed to remove note' }
  }
</script>

<div class="page">
  <div class="page-header">
    <div>
      <button on:click={() => {
        // history.state.idx === 0 means we're at the seated initial entry; history.back()
        // would leave the SPA. Anything > 0 means we pushed our way here, so back is safe.
        if ((window.history.state?.idx ?? 0) > 0) window.history.back()
        else navigate('packages', {}, { replace: true })
      }} class="mb-2">{$t('common.actions.back')}</button>
      <!-- Ecosystem and name come from the route, so the title stands before the package
           fetch resolves and the table below it does not shift down when it lands. The
           fetched display name replaces the purl name in place. -->
      <h1 class="page-title">
        <span class="badge {pkg?.ecosystem ?? params.ecosystem}">{pkg?.ecosystem ?? params.ecosystem}</span>
        {pkg?.name ?? params.name}
        {#if claim && (claim.state === 'local_only' || claim.state === 'mixed')}
          <span
            class="badge has-icon state-{claim.state}"
            title={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}
            aria-label={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}>
            {#if claim.state === 'local_only'}
              <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-lock"/></svg>
            {:else}
              <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-exchange"/></svg>
            {/if}
            {$t(`claims.states.${claim.state}`)}
          </span>
        {/if}
      </h1>
      <!-- Rendered in both states and floored at two clamped description lines plus the link
           row, so the risk pillars and table below sit at the same offset before and after
           the fetch resolves. -->
      <div class="pkg-meta">
        {#if pkg?.description}
          <p class="pkg-description">{pkg.description}</p>
        {/if}
        {#if pkg?.homepage || pkg?.repositoryUrl}
          <div class="pkg-links">
            {#if pkg.homepage}
              <a class="pkg-link" href={pkg.homepage} target="_blank" rel="noopener noreferrer">
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-external"/></svg>
                {$t('versionDetail.meta.homepage')}
              </a>
            {/if}
            {#if pkg.repositoryUrl}
              <a class="pkg-link" href={pkg.repositoryUrl} target="_blank" rel="noopener noreferrer">
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-external"/></svg>
                {$t('versionDetail.meta.repository')}
              </a>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>

  <ErrorBanner message={error} />
  {#if scanError}<div class="error-msg">{scanError}</div>{/if}

  <!-- Rendered only when something ships this package: nothing shipping it is a non-event, and a
       "0 applications" line would be noise on every package in a registry with no SBOMs. -->
  {#if blastRadius && blastRadius.total > 0}
    <div class="blast-radius">
      <button
        type="button"
        class="blast-toggle"
        aria-expanded={blastRadiusOpen}
        on:click={() => blastRadiusOpen = !blastRadiusOpen}
      >
        <svg class="chev" class:open={blastRadiusOpen} width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down"/></svg>
        <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-layers"/></svg>
        {$t('versionDetail.blastRadius.summary', { values: { count: blastRadius.projectCount } })}
      </button>
      {#if blastRadiusOpen}
        {@const hiddenApps = overflowCount(blastRadius.total, blastRadius.items.length)}
        <p class="form-hint">{$t('versionDetail.blastRadius.help')}</p>
        <ul class="blast-list">
          {#each blastRadius.items as app, ai (ai)}
            <li>
              <span class="app-name">{app.projectName}</span>
              <span class="mono text-muted">{app.projectVersion}</span>
              <span class="text-muted">{$t('versionDetail.blastRadius.ships', { values: { version: app.componentVersion ?? '—' } })}</span>
            </li>
          {/each}
        </ul>
        {#if hiddenApps > 0}
          <p class="form-hint">{$t('versionDetail.blastRadius.more', { values: { count: hiddenApps } })}</p>
        {/if}
      {/if}
    </div>
  {/if}

  <!-- Three-pillar risk summary: Security / License / Operational, side by side. Signal-display
       only — no composite/weighted score across the pillars. Every pillar reports the state of
       the version named in the caption, so the strip answers "what is this package like today"
       rather than "what is the worst thing in its history" — which described a version nobody
       installs and contradicted the currency banner below it. -->
  {#if loading || (pkg && versions.length > 0)}
    <RiskPillars
      {loading}
      pillars={riskPillars}
      subject={!loading && stateVersion
        ? { label: $t('versionDetail.pillars.subject'), value: stateVersion }
        : null}
    />
  {/if}

  {#if !loading && versions.length === 0}
    <p class="text-muted">{$t('versionDetail.empty')}</p>
  {:else}
    <VersionTable
      bind:this={versionTable}
      {pkg}
      {versions}
      {licenseBlocklist}
      {licenseConditional}
      {vulnsByPurl}
      {isAdmin}
      {scanningId}
      {loading}
      {scanCooldownRemaining}
      {copy}
      on:download={(e) => downloadVersion(e.detail)}
      on:rescan={(e) => rescan(e.detail)}
      on:block={(e) => blockVersion(e.detail)}
      on:unblock={(e) => unblockVersion(e.detail)}
      on:delete={(e) => deleteVersion(e.detail)}
    />
  {/if}

  {#if !loading && (packageNotes.length > 0 || isAdmin)}
    <section class="package-notes">
      <h2 class="section-h">{$t('packageNotes.title')}</h2>
      <p class="text-muted t-sm">{$t('packageNotes.intro')}</p>
      {#if noteError}<div class="error-msg">{noteError}</div>{/if}

      {#if isAdmin}
        <div class="note-add">
          <textarea rows="2" bind:value={newNoteText}
                    aria-label={$t('packageNotes.title')}
                    placeholder={$t('packageNotes.placeholder')}></textarea>
          <button class="primary" disabled={addingNote || !newNoteText.trim()} on:click={addNote}>
            {$t('packageNotes.add')}
          </button>
        </div>
      {/if}

      {#if packageNotes.length === 0}
        <p class="text-muted">{$t('packageNotes.empty')}</p>
      {:else}
        <ul class="note-list">
          {#each packageNotes as n (n.id)}
            <li>
              {#if editingNoteId === n.id}
                <textarea rows="2" bind:value={editingNoteText}
                          aria-label={$t('packageNotes.title')}></textarea>
                <div class="row-actions">
                  <button class="primary btn-sm" on:click={saveNoteEdit}>{$t('common.actions.save')}</button>
                  <button class="btn-sm" on:click={() => editingNoteId = null}>{$t('common.actions.cancel')}</button>
                </div>
              {:else}
                <p class="note-body">{n.note}</p>
                <p class="note-meta text-muted t-sm">
                  {#if n.version}{$t('packageNotes.scopedToVersion', { values: { version: n.version } })}{:else}{$t('packageNotes.scopedToPackage')}{/if}
                  · {n.createdByLabel ?? $t('packageNotes.unknownAuthor')}
                  · {$formatDate(n.createdAt)}
                </p>
                {#if isAdmin}
                  <div class="row-actions">
                    <button class="btn-sm" on:click={() => { editingNoteId = n.id; editingNoteText = n.note }}>
                      {$t('common.actions.edit')}
                    </button>
                    <button class="danger btn-sm" on:click={() => removeNote(n.id)}>{$t('common.actions.remove')}</button>
                  </div>
                {/if}
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}
</div>

<style>
  /* Claim state badge needs a left margin to separate it from the package name in the H1. */
  .badge.has-icon { margin-left: 8px; }

  .package-notes { margin-top: 24px; }
  .note-add { display: flex; gap: 8px; align-items: flex-start; margin-bottom: 12px; }
  .note-add textarea { flex: 1; font: inherit; resize: vertical; }
  .note-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 12px; }
  .note-list li {
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 12px;
  }
  .note-list textarea { width: 100%; font: inherit; resize: vertical; margin-bottom: 6px; }
  .note-body { margin: 0 0 4px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .note-meta { margin: 0 0 6px; }
  .row-actions { display: flex; gap: 6px; align-items: center; }

  /* Package-level metadata (homepage / repository / description) under the title. Floored at
     two clamped description lines plus the link row, and rendered whether or not the fetch has
     landed, so the risk pillars and version table sit at the same offset either way. */
  .pkg-meta { min-height: 62px; }
  .pkg-description {
    margin: 6px 0 8px;
    color: var(--text2);
    max-width: 70ch;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .pkg-links { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 10px; }
  .pkg-link { display: inline-flex; align-items: center; gap: 4px; color: var(--accent); text-decoration: none; font-size: 13px; }
  .pkg-link:hover { text-decoration: underline; }
  .pkg-link svg { flex-shrink: 0; }

  /* Blast radius — which applications ship this package. A disclosure, not a card: the count is
     the answer most readers want and the list is what they open when it is not zero. */
  .blast-radius { display: flex; flex-direction: column; gap: 6px; }
  .blast-toggle {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 10px;
    min-height: 28px;
    font-size: 13px;
    border: 1px solid var(--info-border);
    border-radius: var(--radius);
    background: var(--info-bg);
    color: var(--info-text);
  }
  .blast-toggle .chev { transform: rotate(-90deg); transition: transform 120ms ease; }
  .blast-toggle .chev.open { transform: rotate(0deg); }
  .blast-list { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 2px; font-size: 13px; }
  .blast-list li { display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; }
  .app-name { font-weight: 600; }
</style>
