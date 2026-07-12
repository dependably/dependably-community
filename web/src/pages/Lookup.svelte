<!--
  Pre-adoption package lookup — "check a package before you add it". Read-only: submits an
  (ecosystem, name, version?) candidate to GET /api/v1/lookup and renders the verdict with a
  per-check breakdown (malware, vulnerabilities incl. the UNSCORED bucket, license, and which
  metadata-dependent checks could not run). Nothing is downloaded, cached, or installed by this
  page — the backend performs no ingest for a lookup.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { extractErrorMessage } from '../lib/form.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'

  // Only the ecosystems GET /api/v1/lookup accepts — a subset of the full registry vocabulary
  // (RPM and OCI are not OSV-covered and have no wired lookup metadata source).
  const LOOKUP_ECOSYSTEMS = ['npm', 'pypi', 'nuget', 'maven', 'golang', 'cargo']
  const ECO_LABEL = { npm: 'npm', pypi: 'PyPI', nuget: 'NuGet', maven: 'Maven', golang: 'Go', cargo: 'Cargo' }

  const DEFAULTS = { ecosystem: 'npm', name: '', version: '' }
  const init = readQuery(DEFAULTS)

  let ecosystem = init.ecosystem
  let name = init.name
  let version = init.version

  let loading = false
  let error = ''
  let result = null
  // True once a lookup has been attempted, so the empty-state hint only shows before the
  // first submit — a failed lookup shows its own error, not the generic hint.
  let searched = false

  $: mavenShape = ecosystem === 'maven'

  async function submit() {
    if (!name.trim()) return
    loading = true
    error = ''
    result = null
    searched = true
    writeQuery({ ecosystem, name, version }, DEFAULTS)
    try {
      result = await api.lookupPackage(ecosystem, name.trim(), version.trim() || undefined)
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      loading = false
    }
  }

  function unscoredSummary(v) {
    return v.unscored?.length ? `${v.unscored.length}` : '0'
  }
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('lookup.title')}</h1>
  </div>
  <p class="tab-intro">{$t('lookup.intro')}</p>

  <form class="lookup-form" on:submit|preventDefault={submit}>
    <div class="field">
      <label for="lookup-eco">{$t('lookup.form.ecosystem')}</label>
      <select id="lookup-eco" bind:value={ecosystem}>
        {#each LOOKUP_ECOSYSTEMS as eco (eco)}
          <option value={eco}>{ECO_LABEL[eco]}</option>
        {/each}
      </select>
    </div>
    <div class="field field-grow">
      <label for="lookup-name">{$t('lookup.form.name')}</label>
      <input
        id="lookup-name"
        type="text"
        bind:value={name}
        placeholder={mavenShape ? $t('lookup.form.mavenHint') : $t('lookup.form.namePlaceholder')}
        required
      />
    </div>
    <div class="field">
      <label for="lookup-version">{$t('lookup.form.version')}</label>
      <input
        id="lookup-version"
        type="text"
        bind:value={version}
        placeholder={$t('lookup.form.versionPlaceholder')}
      />
    </div>
    <button type="submit" class="primary" disabled={loading}>
      <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-search" /></svg>
      {$t('lookup.form.submit')}
    </button>
  </form>

  <ErrorBanner message={error} />

  {#if loading}
    <p class="text-muted">{$t('common.loading')}</p>
  {:else if result}
    <div class="verdict-panel">
      <div class="verdict-header">
        <span class="badge verdict-{result.verdict}">{$t(`lookup.verdict.${result.verdict}`)}</span>
        <span class="verdict-purl t-mono">{$t('lookup.verdict.evaluated', { values: { purl: result.purl } })}</span>
      </div>
      {#if result.versionInferred}
        <p class="text-muted t-sm">{$t('lookup.verdict.versionInferred')}</p>
      {/if}
      {#if result.airGapped}
        <p class="text-muted t-sm hint-row">
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-plane" /></svg>
          {$t('lookup.airGapped')}
        </p>
      {/if}

      <div class="check-grid">
        <!-- Malware -->
        <div class="check-card" class:check-bad={result.malware.detected}>
          <div class="check-title">
            <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-shield" /></svg>
            {$t('lookup.malware.title')}
          </div>
          {#if result.malware.detected}
            <p class="check-bad-text">{$t('lookup.malware.detected')}</p>
            <ul class="advisory-ids">
              {#each result.malware.advisoryIds as id (id)}<li class="t-mono">{id}</li>{/each}
            </ul>
          {:else}
            <p class="text-muted">{$t('lookup.malware.clean')}</p>
          {/if}
        </div>

        <!-- Vulnerabilities -->
        <div class="check-card" class:check-bad={result.vulnerabilities.scored.length > 0}>
          <div class="check-title">
            <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-bug" /></svg>
            {$t('lookup.vulns.title')}
          </div>
          {#if !result.vulnerabilities.available}
            <p class="check-bad-text">{$t('lookup.vulns.unavailable')}</p>
          {:else if result.vulnerabilities.scored.length === 0 && result.vulnerabilities.unscored.length === 0}
            <p class="text-muted">{$t('lookup.vulns.clean')}</p>
          {:else}
            {#if result.vulnerabilities.scored.length > 0}
              <div class="vuln-group">
                <span class="detail-label">{$t('lookup.vulns.scored')}</span>
                {#each result.vulnerabilities.scored as adv (adv.id)}
                  <div class="vuln-row">
                    <span class="sev sev-{(adv.severity ?? 'unknown').toLowerCase()}">{adv.severity ?? '—'}</span>
                    <span class="t-mono">{adv.id}</span>
                    <span class="text-muted">{adv.cvssScore}</span>
                    {#if adv.isKev}<span class="badge danger has-icon">{$t('lookup.vulns.kev')}</span>{/if}
                    {#if adv.epss !== null && adv.epss !== undefined}<span class="badge">{$t('lookup.vulns.epss', { values: { value: adv.epss.toFixed(2) } })}</span>{/if}
                  </div>
                {/each}
              </div>
            {/if}
            {#if result.vulnerabilities.unscored.length > 0}
              <div class="vuln-group">
                <span class="detail-label" title={$t('lookup.vulns.unscoredHint')}>
                  {$t('lookup.vulns.unscored')} ({unscoredSummary(result.vulnerabilities)})
                </span>
                {#each result.vulnerabilities.unscored as adv (adv.id)}
                  <div class="vuln-row">
                    <span class="sev sev-unknown">{$t('lookup.vulns.unscored')}</span>
                    <span class="t-mono">{adv.id}</span>
                  </div>
                {/each}
              </div>
            {/if}
          {/if}
        </div>

        <!-- License -->
        <div class="check-card" class:check-warn={result.license.allowed === false}>
          <div class="check-title">
            <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-license" /></svg>
            {$t('lookup.license.title')}
          </div>
          <p class="text-muted t-sm">{$t('lookup.license.policy', { values: { mode: result.license.mode } })}</p>
          {#if result.license.spdx.length > 0}
            <p class="t-mono">{result.license.spdx.join(', ')}</p>
          {/if}
          {#if !result.license.available}
            <p class="text-muted">{$t('lookup.license.unavailable')}</p>
          {:else if result.license.mode === 'off'}
            <p class="text-muted">{$t('lookup.license.informational')}</p>
          {:else if result.license.allowed}
            <p class="check-ok-text">{$t('lookup.license.allowed')}</p>
          {:else}
            <p class="check-warn-text">{$t('lookup.license.blocked', { values: { spdx: result.license.blockedLicense ?? '' } })}</p>
          {/if}
        </div>
      </div>

      {#if result.unavailableChecks.length > 0}
        <div class="unavailable-note">
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-info" /></svg>
          <span class="detail-label">{$t('lookup.unavailableChecks.title')}</span>
          <span class="text-muted t-sm">
            {result.unavailableChecks.map((c) => $t(`lookup.unavailableChecks.${c}`)).join(', ')}
          </span>
        </div>
      {/if}
    </div>
  {:else if searched}
    <p class="text-muted">—</p>
  {:else}
    <p class="text-muted">{$t('lookup.empty')}</p>
  {/if}
</div>

<style>
  .lookup-form {
    display: flex;
    align-items: end;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }
  .field { display: flex; flex-direction: column; gap: 4px; }
  .field-grow { flex: 1 1 240px; }
  .field label { font-size: 12px; color: var(--text2); }
  .lookup-form button.primary { display: inline-flex; align-items: center; gap: 6px; height: 34px; }

  .verdict-panel {
    display: flex;
    flex-direction: column;
    gap: 12px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
  }
  .verdict-header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .verdict-purl { color: var(--text2); font-size: 13px; }
  .hint-row { display: flex; align-items: center; gap: 6px; }

  .badge.verdict-allowed { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
  .badge.verdict-warn    { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }
  .badge.verdict-blocked { background: var(--danger-bg);  color: var(--danger);       border: 1px solid var(--danger-border); }

  .check-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 12px;
  }
  .check-card {
    background: var(--bg1);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .check-card.check-bad { border-color: var(--danger-border); }
  .check-card.check-warn { border-color: var(--warning-border); }
  .check-title { display: flex; align-items: center; gap: 6px; font-weight: 600; }
  .check-bad-text { color: var(--danger); margin: 0; }
  .check-warn-text { color: var(--warning-text); margin: 0; }
  .check-ok-text { color: var(--success); margin: 0; }

  .advisory-ids { margin: 0; padding-left: 18px; }
  .vuln-group { display: flex; flex-direction: column; gap: 4px; }
  .vuln-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13px; }

  .detail-label {
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .unavailable-note {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    padding-top: 8px;
    border-top: 1px solid var(--border);
    color: var(--text2);
  }
</style>
