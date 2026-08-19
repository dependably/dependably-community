<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import LicenseTextModal from '../lib/LicenseTextModal.svelte'
  import { reportPageLoad } from '../lib/pageLoad.js'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let mode = 'off'
  let allowEntries = []
  let blockEntries = []
  // The allowlist response carries both non-denied dispositions. An entry from a server that
  // predates the disposition column has none and reads as 'allowed'.
  $: allowedEntries = allowEntries.filter(e => e.disposition !== 'conditional')
  $: conditionalEntries = allowEntries.filter(e => e.disposition === 'conditional')
  // Hydrated details: { identifier: { name, isOsiApproved, isFsfLibre, copyleft, isDeprecated, referenceUrl } }
  let detail = {}
  let loading = true
  let error = ''
  // Identifier of the license whose bundled text popup is open, or null.
  let licenseTextModal = null

  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)

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

<div class="page">
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
      {#if allowedEntries.length === 0}
        <p class="text-muted empty">{$t('licensePolicy.allow.empty')}</p>
      {:else}
        <table class="list-table">
          <colgroup>
            <col class="col-spdx">
            <col>
            <col>
            <col class="col-badges">
          </colgroup>
          <thead>
            <tr>
              <th>{$t('licensePolicy.columns.spdx')}</th>
              <th>{$t('licensePolicy.columns.name')}</th>
              <th>{$t('licensePolicy.columns.note')}</th>
              <th>{$t('licensePolicy.columns.attributes')}</th>
            </tr>
          </thead>
          <tbody>
            {#each allowedEntries as e (e.id)}
              {@const d = detail[e.licenseSpdx]}
              <tr>
                <td class="t-mono">
                  <button class="link t-mono"
                          aria-label={$t('licenseText.open')}
                          title={$t('licenseText.open')}
                          on:click={() => licenseTextModal = e.licenseSpdx}>
                    {e.licenseSpdx}
                  </button>
                </td>
                <td>{d?.name ?? '—'}</td>
                <td class="note-cell">{e.note || '—'}</td>
                <td>
                  <div class="badges">
                    {#if d?.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
                    {#if d?.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
                    {#if d?.copyleft && d.copyleft !== 'unclassified'}
                      <span class="badge cl-{d.copyleft}">{copyleftLabel(d.copyleft)}</span>
                    {/if}
                    {#if d?.isDeprecated}<span class="badge dep">deprecated</span>{/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section class="mt-4">
      <h2 class="section-h">{$t('licensePolicy.conditional.title')}</h2>
      <p class="text-muted">{$t('licensePolicy.conditional.intro')}</p>
      {#if conditionalEntries.length === 0}
        <p class="text-muted empty">{$t('licensePolicy.conditional.empty')}</p>
      {:else}
        <table class="list-table">
          <colgroup>
            <col class="col-spdx">
            <col>
            <col>
            <col class="col-badges">
          </colgroup>
          <thead>
            <tr>
              <th>{$t('licensePolicy.columns.spdx')}</th>
              <th>{$t('licensePolicy.columns.name')}</th>
              <th>{$t('licensePolicy.columns.condition')}</th>
              <th>{$t('licensePolicy.columns.attributes')}</th>
            </tr>
          </thead>
          <tbody>
            {#each conditionalEntries as e (e.id)}
              {@const d = detail[e.licenseSpdx]}
              <tr>
                <td class="t-mono">
                  <button class="link t-mono"
                          aria-label={$t('licenseText.open')}
                          title={$t('licenseText.open')}
                          on:click={() => licenseTextModal = e.licenseSpdx}>
                    {e.licenseSpdx}
                  </button>
                </td>
                <td>{d?.name ?? '—'}</td>
                <!-- The condition is the whole point of this row: it is the part a developer who
                     hits the licence actually needs to read. -->
                <td class="note-cell">{e.note || $t('licensePolicy.conditional.noCondition')}</td>
                <td>
                  <div class="badges">
                    {#if d?.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
                    {#if d?.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
                    {#if d?.copyleft && d.copyleft !== 'unclassified'}
                      <span class="badge cl-{d.copyleft}">{copyleftLabel(d.copyleft)}</span>
                    {/if}
                    {#if d?.isDeprecated}<span class="badge dep">deprecated</span>{/if}
                  </div>
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
            <col>
            <col class="col-badges">
          </colgroup>
          <thead>
            <tr>
              <th>{$t('licensePolicy.columns.spdx')}</th>
              <th>{$t('licensePolicy.columns.name')}</th>
              <th>{$t('licensePolicy.columns.note')}</th>
              <th>{$t('licensePolicy.columns.attributes')}</th>
            </tr>
          </thead>
          <tbody>
            {#each blockEntries as e (e.id)}
              {@const d = detail[e.licenseSpdx]}
              <tr>
                <td class="t-mono">
                  <button class="link t-mono"
                          aria-label={$t('licenseText.open')}
                          title={$t('licenseText.open')}
                          on:click={() => licenseTextModal = e.licenseSpdx}>
                    {e.licenseSpdx}
                  </button>
                </td>
                <td>{d?.name ?? '—'}</td>
                <td class="note-cell">{e.note || '—'}</td>
                <td>
                  <div class="badges">
                    {#if d?.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
                    {#if d?.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
                    {#if d?.copyleft && d.copyleft !== 'unclassified'}
                      <span class="badge cl-{d.copyleft}">{copyleftLabel(d.copyleft)}</span>
                    {/if}
                    {#if d?.isDeprecated}<span class="badge dep">deprecated</span>{/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

{#if licenseTextModal}
  <LicenseTextModal identifier={licenseTextModal}
                     referenceUrl={detail[licenseTextModal]?.referenceUrl}
                     on:close={() => licenseTextModal = null} />
{/if}

<style>
  /* Tighter vertical padding than the global .page gutter. Width is deliberately
     untouched — the page shell is full-bleed and never re-caps itself. */
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
  /* Inline link-style trigger for the SPDX id cells that open LicenseTextModal. */
  .link {
    background: none;
    border: none;
    color: var(--accent);
    padding: 0;
    min-height: 0;
    font-size: inherit;
    cursor: pointer;
  }
  .link:hover { text-decoration: underline; background: none; }
  .col-spdx { width: 200px; }
  /* Notes wrap: a condition is a sentence, not a label, and truncating it would hide the part
     the reader came for. */
  .note-cell { white-space: normal; }
  .col-badges { width: 220px; }
</style>
