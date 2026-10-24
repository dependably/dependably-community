<!--
  One OCI image's stored scan detail, inside its expanded version row. Fetched when the row is
  first expanded; every page fetched is kept in the caller's `cache` for the page's lifetime, so
  collapsing and re-expanding does not refetch.

  Coverage comes first: a platform with gaps shows them, verbatim, above everything else. The
  findings view is the default; the full inventory is one toggle away. Without a stored result the
  panel says why (unscanned, with the scan job's state, or no scanner) and renders no table.
  Every decision is made by the helpers in ociScan.js; this component only renders their answer.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import { formatDate } from './format.js'
  import { navigate } from './store.js'
  import { pathFor, searchFor } from './routes.js'
  import {
    advisorySeverity, closureKind, componentsView, moreFindings, ociScanPanel, reachabilityKind, scanTimes,
  } from './ociScan.js'

  /** Repository name, unencoded (e.g. `team/app`). */
  export let name
  /** Manifest digest of the image. */
  export let digest
  /**
   * Responses already fetched for this page, keyed by digest and request. Owned by the caller so
   * it outlives this panel when the row collapses.
   * @type {Map<string, any>}
   */
  export let cache

  /** @type {string | null} null asks the server for its default (the first platform). */
  let platform = null
  let affectedOnly = true
  let offset = 0
  let detail = null
  let loading = false
  let failed = false

  // The repository is part of the key: one digest can live under several repositories, each its
  // own image with its own result.
  const keyFor = (p, a, o) => `${name}|${digest}|${p ?? ''}|${a}|${o}`

  // Request sequence: platform, view and page changes can overlap loads, and a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  async function load() {
    const mine = ++seq
    const key = keyFor(platform, affectedOnly, offset)
    const hit = cache.get(key)
    if (hit) { detail = hit; failed = false; loading = false; return }
    loading = true
    failed = false
    try {
      const res = await api.getOciScan(name, digest, { platform: platform ?? undefined, affectedOnly, offset })
      cache.set(key, res)
      if (mine !== seq) return
      detail = res
    } catch {
      if (mine !== seq) return
      failed = true
    } finally {
      if (mine === seq) loading = false
    }
  }

  onMount(load)

  function choosePlatform(p) {
    platform = p
    offset = 0
    load()
  }

  function chooseView(onlyAffected) {
    if (affectedOnly === onlyAffected) return
    affectedOnly = onlyAffected
    offset = 0
    load()
  }

  function goTo(nextOffset) {
    offset = nextOffset
    load()
  }

  function openAdvisory(e, osvId) {
    e.stopPropagation()
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    navigate('vulnerabilities', { q: osvId })
  }

  $: panel = detail ? ociScanPanel(detail) : null
  $: view = detail ? componentsView(detail, affectedOnly) : { kind: 'none' }
  $: selected = detail?.components?.platform ?? null
  $: selectedPlatform = (detail?.platforms ?? []).find(p => p.platform === selected) ?? null
  $: times = scanTimes(selectedPlatform)
</script>

<div class="oci-scan" aria-busy={loading}>
  <span class="detail-label">{$t('versionDetail.ociScan.title')}</span>

  {#each detail?.pendingHolds ?? [] as hold (hold.tag)}
    <p class="oci-scan-note oci-scan-uncovered" role="note">
      {$t('versionDetail.ociScan.pendingHold', { values: { tag: hold.tag, serving: hold.servingDigest, time: $formatDate(hold.pendingSince) } })}
    </p>
  {/each}

  {#if failed}
    <p class="oci-scan-note">
      {$t('versionDetail.ociScan.loadError')}
      <button class="oci-scan-retry" on:click|stopPropagation={load}>{$t('versionDetail.ociScan.retry')}</button>
    </p>
  {:else if !detail}
    <p class="oci-scan-note text-muted">{$t('versionDetail.ociScan.loading')}</p>
  {:else if panel?.kind === 'noResult'}
    <p class="oci-scan-note oci-scan-uncovered">{$t(`versionDetail.ociScan.${panel.messageKey}`, { values: { count: panel.attempts } })}</p>
  {:else if panel}
    {#each panel.gapPlatforms as gp (gp.platform)}
      <div class="oci-scan-gaps" role="note">
        <strong>{$t('versionDetail.ociScan.gapsTitle', { values: { count: gp.gaps.length, platform: gp.platform } })}</strong>
        <span class="oci-scan-gaps-help">{$t('versionDetail.ociScan.gapsHelp')}</span>
        <ul>
          {#each gp.gaps as gap, i (i)}
            <!-- Scanner text, rendered as text: never markup. -->
            <li>{gap}</li>
          {/each}
        </ul>
      </div>
    {/each}

    <p class="oci-scan-note text-muted">
      {$t('versionDetail.ociScan.platformsScanned', { values: { platforms: panel.platformNames.join(', ') } })}
      {#if times.scannedAt}· {$t('versionDetail.ociScan.scannedAt', { values: { time: $formatDate(times.scannedAt) } })}{/if}
      {#if times.matchedAt}· {$t('versionDetail.ociScan.matchedAt', { values: { time: $formatDate(times.matchedAt) } })}{/if}
    </p>

    {#if panel.clean}
      <p class="oci-scan-note">{$t('versionDetail.ociScan.clean', { values: { platforms: panel.platformNames.join(', '), time: $formatDate(panel.matchedAt) } })}</p>
    {/if}

    {#if (detail.platforms ?? []).length > 1}
      <div class="oci-scan-platforms" role="group">
        {#each detail.platforms as p (p.platform)}
          <button
            class="oci-scan-chip"
            class:active={p.platform === selected}
            aria-pressed={p.platform === selected}
            on:click|stopPropagation={() => choosePlatform(p.platform)}
          >{$t('versionDetail.ociScan.platformTab', { values: { platform: p.platform, count: p.affectedComponentCount } })}</button>
        {/each}
      </div>
    {/if}

    <div class="oci-scan-views" role="group">
      <button class="oci-scan-chip" class:active={affectedOnly} aria-pressed={affectedOnly} on:click|stopPropagation={() => chooseView(true)}>{$t('versionDetail.ociScan.viewFindings')}</button>
      <button class="oci-scan-chip" class:active={!affectedOnly} aria-pressed={!affectedOnly} on:click|stopPropagation={() => chooseView(false)}>{$t('versionDetail.ociScan.viewAll')}</button>
    </div>

    {#if view.kind === 'zeroFindings'}
      <p class="oci-scan-note">{$t('versionDetail.ociScan.zeroFindings', { values: { count: view.componentCount } })}</p>
    {:else if view.kind === 'rows'}
      <div class="table-scroll">
        <table class="oci-scan-table">
          <thead>
            <tr>
              <th>{$t('versionDetail.ociScan.columns.component')}</th>
              <th>{$t('versionDetail.ociScan.columns.layer')}</th>
              <th>{$t('versionDetail.ociScan.columns.findings')}</th>
            </tr>
          </thead>
          <tbody>
            {#each view.items as c, i (`${c.purl}|${i}`)}
              {@const closure = closureKind(c.inEntrypointClosure)}
              <tr>
                <td class="component-cell">
                  <span class="mono">{c.name}</span> <span class="mono text-muted">{c.version}</span>
                  <span class="badge eco-badge">{c.ecosystem}</span>
                  {#if c.sourceName && c.sourceName !== c.name}
                    <div class="text-muted">{$t('versionDetail.ociScan.source', { values: { name: c.sourceName } })}</div>
                  {/if}
                  {#if c.ownedByPurl}
                    <div class="text-muted mono">{$t('versionDetail.ociScan.ownedBy', { values: { purl: c.ownedByPurl } })}</div>
                  {/if}
                  <div class="text-muted closure-{closure}">{$t(`versionDetail.ociScan.closure.${closure}`)}</div>
                </td>
                <td class="layer-cell">
                  {c.layerIndex === null || c.layerIndex === undefined
                    ? $t('versionDetail.ociScan.layerUnknown')
                    : $t('versionDetail.ociScan.layer', { values: { index: c.layerIndex } })}
                  {#if c.layerInstruction}<code class="mono instruction">{c.layerInstruction}</code>{/if}
                </td>
                <td class="findings-cell">
                  {#each c.findings ?? [] as f (f.osvId)}
                    {@const adv = detail.advisories?.[f.osvId]}
                    {@const sev = advisorySeverity(adv)}
                    {@const reach = reachabilityKind(f.reachability)}
                    <div class="finding">
                      {#if sev === 'UNKNOWN'}
                        <span class="sev sev-unknown" title={$t('versionDetail.ociScan.unscoredHelp')}>{$t('versionDetail.ociScan.unscored')}</span>
                      {:else}
                        <span class="sev sev-{sev.toLowerCase()}">{sev}</span>
                      {/if}
                      <a href="{pathFor('vulnerabilities')}{searchFor('vulnerabilities', { q: f.osvId })}" on:click={(e) => openAdvisory(e, f.osvId)}>{f.osvId}</a>
                      <span
                        class="reach reach-{reach}"
                        title={reach === 'not_observed' ? $t('versionDetail.ociScan.notObservedHelp') : null}
                      >{$t(`versionDetail.ociScan.reachability.${reach}`)}</span>
                      {#if reach === 'not_observed' && f.notObservedBasis}
                        <span class="text-muted">{$t('versionDetail.ociScan.notObservedBasis', { values: { basis: f.notObservedBasis } })}</span>
                      {/if}
                      {#if reach === 'not_observed' && f.confidence}
                        <span class="text-muted">{$t('versionDetail.ociScan.confidence', { values: { confidence: f.confidence } })}</span>
                      {/if}
                      {#if adv?.summary}<span class="text-muted finding-summary">{adv.summary}</span>{/if}
                    </div>
                  {:else}
                    <span class="text-muted">—</span>
                  {/each}
                  {#if moreFindings(c) > 0}
                    <div class="text-muted">{$t('versionDetail.ociScan.moreFindings', { values: { count: moreFindings(c) } })}</div>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if view.prevOffset !== null || view.nextOffset !== null}
        <div class="oci-scan-pager">
          <span class="text-muted">{$t('versionDetail.ociScan.range', { values: { from: view.from, to: view.to, total: view.total } })}</span>
          <button disabled={view.prevOffset === null || loading} on:click|stopPropagation={() => goTo(view.prevOffset)}>{$t('versionDetail.ociScan.previous')}</button>
          <button disabled={view.nextOffset === null || loading} on:click|stopPropagation={() => goTo(view.nextOffset)}>{$t('versionDetail.ociScan.next')}</button>
        </div>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .oci-scan { display: flex; flex-direction: column; gap: 8px; margin-bottom: 14px; }
  .oci-scan-note { margin: 0; font-size: 13px; }
  .oci-scan-uncovered { color: var(--warning-text); }
  .oci-scan-retry { margin-left: 8px; padding: 1px 8px; font-size: 12px; min-height: 0; }
  .oci-scan-gaps {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 12px;
    border: 1px solid var(--warning-border);
    border-radius: var(--radius);
    background: var(--warning-bg);
    color: var(--warning-text);
    font-size: 13px;
  }
  .oci-scan-gaps ul { margin: 0; padding-left: 18px; }
  .oci-scan-gaps li { overflow-wrap: anywhere; }
  .oci-scan-gaps-help { font-size: 12px; }
  .oci-scan-platforms,
  .oci-scan-views { display: flex; flex-wrap: wrap; gap: 6px; }
  .oci-scan-chip {
    padding: 2px 10px;
    font-size: 12px;
    min-height: 0;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--bg2);
    color: var(--text2);
  }
  .oci-scan-chip.active { border-color: var(--accent); color: var(--accent); }
  .oci-scan-table { width: 100%; border-collapse: collapse; font-size: 12px; table-layout: auto; }
  .oci-scan-table th {
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.02em;
    padding: 2px 8px;
    border-bottom: 1px solid var(--border);
  }
  .oci-scan-table td { padding: 4px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .component-cell { min-width: 180px; overflow-wrap: anywhere; }
  .layer-cell { min-width: 160px; }
  .findings-cell { min-width: 260px; }
  .instruction { display: block; font-size: 11px; color: var(--text2); white-space: pre-wrap; overflow-wrap: anywhere; }
  .eco-badge { font-size: 10px; margin-left: 4px; }
  .finding { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px; }
  .finding-summary { flex-basis: 100%; }
  .reach { font-size: 11px; padding: 0 6px; border-radius: 999px; border: 1px solid var(--border); }
  /* Reachable is the emphasized verdict. Not observed is neutral, never the clean tone; unknown is
     muted like the unscored chip. */
  .reach-reachable { color: var(--danger); border-color: var(--danger); font-weight: 600; }
  .reach-not_observed { color: var(--text); }
  .reach-unknown { color: var(--sev-unknown-text); background: var(--sev-unknown-bg); }
  .oci-scan-pager { display: flex; align-items: center; gap: 8px; font-size: 12px; }
  .oci-scan-pager button { padding: 2px 10px; font-size: 12px; min-height: 0; }
</style>
