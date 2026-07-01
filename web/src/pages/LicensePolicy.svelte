<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'

  let mode = 'off'
  let allowEntries = []
  let blockEntries = []
  // Hydrated details: { identifier: { name, isOsiApproved, isFsfLibre, copyleft, isDeprecated, referenceUrl } }
  let detail = {}
  let loading = true
  let error = ''

  onMount(async () => {
    try {
      const policy = await api.getLicensePolicy()
      mode = policy.mode ?? 'off'
      allowEntries = policy.allowlist ?? []
      blockEntries = policy.blocklist ?? []

      // Hydrate SPDX reference detail in parallel. Identifiers not in the seeded table
      // (custom or post-bundle) silently fall through to a name-less row — that's fine.
      const ids = [...allowEntries, ...blockEntries].map(e => e.licenseSpdx)
      const uniq = [...new Set(ids)]
      const fetched = await Promise.all(uniq.map(id =>
        api.getSpdx(id).catch(() => null)
      ))
      const map = {}
      for (let i = 0; i < uniq.length; i++) {
        if (fetched[i]) map[uniq[i]] = fetched[i]
      }
      detail = map
    } catch (e) {
      error = e.message ?? 'failed to load license policy'
    } finally {
      loading = false
    }
  })

  function copyleftLabel(c) {
    if (!c || c === 'unclassified') return ''
    return c.replace('-copyleft', ' copyleft')
  }
</script>

<div class="page page-fluid">
  <header class="page-header">
    <h1>{$t('licensePolicy.title')}</h1>
    <div class="mode-line">
      <span class="mode-label">{$t('licensePolicy.mode')}:</span>
      <span class="badge mode-{mode}">{$t(`licensePolicy.modes.${mode}`)}</span>
    </div>
  </header>

  <p class="intro">{$t(`licensePolicy.intro.${mode}`)}</p>

  {#if error}
    <ErrorBanner message={error} />
  {:else if loading}
    <span class="spinner"></span>
  {:else}
    <section>
      <h2 class="section-h">{$t('licensePolicy.allow.title')}</h2>
      {#if allowEntries.length === 0}
        <p class="text-muted empty">{$t('licensePolicy.allow.empty')}</p>
      {:else}
        <table class="list-table">
          <colgroup>
            <col class="col-spdx">
            <col>
            <col class="col-badges">
          </colgroup>
          <thead>
            <tr>
              <th>{$t('licensePolicy.columns.spdx')}</th>
              <th>{$t('licensePolicy.columns.name')}</th>
              <th>{$t('licensePolicy.columns.attributes')}</th>
            </tr>
          </thead>
          <tbody>
            {#each allowEntries as e (e.id)}
              {@const d = detail[e.licenseSpdx]}
              <tr>
                <td class="t-mono">
                  {#if d?.referenceUrl}
                    <a href={d.referenceUrl} target="_blank" rel="noopener noreferrer">{e.licenseSpdx}</a>
                  {:else}
                    {e.licenseSpdx}
                  {/if}
                </td>
                <td>{d?.name ?? '—'}</td>
                <td class="badges">
                  {#if d?.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
                  {#if d?.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
                  {#if d?.copyleft && d.copyleft !== 'unclassified'}
                    <span class="badge cl-{d.copyleft}">{copyleftLabel(d.copyleft)}</span>
                  {/if}
                  {#if d?.isDeprecated}<span class="badge dep">deprecated</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section class="mt-4">
      <h2 class="section-h">{$t('licensePolicy.block.title')}</h2>
      {#if blockEntries.length === 0}
        <p class="text-muted empty">{$t('licensePolicy.block.empty')}</p>
      {:else}
        <table class="list-table">
          <colgroup>
            <col class="col-spdx">
            <col>
            <col class="col-badges">
          </colgroup>
          <thead>
            <tr>
              <th>{$t('licensePolicy.columns.spdx')}</th>
              <th>{$t('licensePolicy.columns.name')}</th>
              <th>{$t('licensePolicy.columns.attributes')}</th>
            </tr>
          </thead>
          <tbody>
            {#each blockEntries as e (e.id)}
              {@const d = detail[e.licenseSpdx]}
              <tr>
                <td class="t-mono">
                  {#if d?.referenceUrl}
                    <a href={d.referenceUrl} target="_blank" rel="noopener noreferrer">{e.licenseSpdx}</a>
                  {:else}
                    {e.licenseSpdx}
                  {/if}
                </td>
                <td>{d?.name ?? '—'}</td>
                <td class="badges">
                  {#if d?.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
                  {#if d?.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
                  {#if d?.copyleft && d.copyleft !== 'unclassified'}
                    <span class="badge cl-{d.copyleft}">{copyleftLabel(d.copyleft)}</span>
                  {/if}
                  {#if d?.isDeprecated}<span class="badge dep">deprecated</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

<style>
  /* Keep the tighter vertical padding, but let the global .page-fluid control width
     (this scoped rule would otherwise out-specify it and re-cap the page at 1100px). */
  .page { padding: 20px 24px; }
  .page-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 12px;
  }
  h1 { margin: 0; font-size: 20px; font-weight: 600; }
  .mode-line { font-size: 13px; color: var(--text2); }
  .mode-label { margin-right: 6px; }
  .intro { color: var(--text2); font-size: 13px; margin: 0 0 20px; max-width: 780px; }
  .section-h { font-size: 14px; font-weight: 600; margin: 0 0 8px; }
  .empty { font-size: 13px; }
  .mt-4 { margin-top: 24px; }
  .badges { display: flex; gap: 4px; flex-wrap: wrap; }
  .col-spdx { width: 200px; }
  .col-badges { width: 220px; }
</style>
