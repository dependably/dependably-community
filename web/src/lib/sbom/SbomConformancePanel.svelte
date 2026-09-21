<!--
  CISA 2026 minimum-elements scorecard for one project version's stored SBOM document.

  Fetches lazily — only once the operator expands the panel — because the score is a per-request
  computation the version detail page does not need on every load. A 404 (no doc_type='sbom' row
  for this version) is rendered as a quiet "nothing to score" note, not an error: a VEX- or
  SARIF-only upload legitimately has no document here.

  Every element renders its state as a named badge (Present / Absent / Explicitly unknown / Not
  applicable / Not assessed) — never collapsed to a percentage. A component-data element also
  shows the present/explicitly-unknown/absent counts, so "which components" stays visible instead
  of a single rolled-up verdict.

  Props:
    projectId
    versionId
-->
<script>
  import { t } from 'svelte-i18n'
  import { api, ApiError } from '../api.js'
  import ErrorBanner from '../ErrorBanner.svelte'

  export let projectId
  export let versionId

  let expanded = false
  let loading = false
  let loaded = false
  let error = ''
  let noDocument = false
  let scorecard = null

  const CATEGORY_ORDER = ['metadata', 'component', 'practice']

  async function load() {
    if (loaded || loading) return
    loading = true
    error = ''
    try {
      scorecard = await api.getSbomConformance(projectId, versionId)
      noDocument = false
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        noDocument = true
      } else {
        error = $t('sbomAnalysis.conformance.loadError')
      }
    } finally {
      loading = false
      loaded = true
    }
  }

  function toggle() {
    expanded = !expanded
    if (expanded) load()
  }

  function stateClass(state) {
    switch (state) {
      case 'present': return 'conformance-present'
      case 'absent': return 'conformance-absent'
      case 'explicitlyUnknown': return 'conformance-explicit-unknown'
      case 'notApplicable': return 'conformance-not-applicable'
      default: return 'conformance-not-assessed'
    }
  }

  $: grouped = scorecard
    ? CATEGORY_ORDER.map((cat) => ({
        cat,
        elements: scorecard.elements.filter((e) => e.category === cat),
      })).filter((g) => g.elements.length > 0)
    : []
</script>

<div class="conformance-panel">
  <button type="button" class="btn-sm" on:click={toggle} aria-expanded={expanded}>
    {expanded ? $t('sbomAnalysis.conformance.hide') : $t('sbomAnalysis.conformance.show')}
  </button>

  {#if expanded}
    <div class="conformance-body">
      <p class="form-hint">{$t('sbomAnalysis.conformance.help')}</p>

      {#if loading}
        <p class="text-muted">{$t('common.loading')}</p>
      {:else if noDocument}
        <p class="text-muted">{$t('sbomAnalysis.conformance.noDocument')}</p>
      {:else}
        <ErrorBanner message={error} />
        {#if scorecard}
          <p class="text-muted">
            {$t('sbomAnalysis.conformance.componentTotal', { values: { count: scorecard.componentTotal } })}
          </p>
          {#each grouped as group (group.cat)}
            <h3 class="conformance-category">{$t(`sbomAnalysis.conformance.category.${group.cat}`)}</h3>
            <ul class="conformance-list">
              {#each group.elements as el (el.elementId)}
                <li class="conformance-row">
                  <span class="conformance-name">{$t(`sbomAnalysis.conformance.element.${el.elementId}`)}</span>
                  <span class="badge {stateClass(el.state)}">{$t(`sbomAnalysis.conformance.state.${el.state}`)}</span>
                  {#if el.total !== null && el.total !== undefined}
                    <span class="conformance-counts text-muted">
                      {$t('sbomAnalysis.conformance.counts', {
                        values: {
                          present: el.presentCount,
                          explicitUnknown: el.explicitUnknownCount,
                          notAssessed: el.notAssessedCount ?? 0,
                          absent: el.absentCount,
                          total: el.total,
                        },
                      })}
                    </span>
                  {:else if el.state === 'notApplicable'}
                    <span class="conformance-counts text-muted">{$t('sbomAnalysis.conformance.reason.notApplicable')}</span>
                  {:else if el.state === 'notAssessed'}
                    <span class="conformance-counts text-muted">{$t('sbomAnalysis.conformance.reason.notAssessed')}</span>
                  {/if}
                </li>
              {/each}
            </ul>
          {/each}
        {/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  .conformance-panel { margin-top: 12px; }
  .conformance-body { margin-top: 8px; }
  .conformance-category { font-size: 13px; font-weight: 600; margin: 16px 0 6px; }
  .conformance-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
  .conformance-row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .conformance-name { min-width: 220px; }
  .conformance-counts { font-size: 12px; }
</style>
