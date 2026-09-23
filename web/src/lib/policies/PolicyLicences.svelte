<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { reportPageLoad } from '../pageLoad.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import LicenseTextModal from '../LicenseTextModal.svelte'
  import InfoTip from '../InfoTip.svelte'

  /** The route transition this tab was mounted for, forwarded by Policies.svelte. @type {number | null} */
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

<div class="mode-line">
  <span class="mode-label">{$t('licensePolicy.mode')}:</span>
  <span class="badge mode-{mode}">{$t(`licensePolicy.modes.${mode}`)}</span>
  <InfoTip text={$t(`licensePolicy.intro.${mode}`)} />
</div>

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
                  {#if d?.isOsiApproved}<span class="badge osi" title={$t('spdx.osiApproved')}>OSI</span>{/if}
                  {#if d?.isFsfLibre}<span class="badge fsf" title={$t('spdx.fsfLibre')}>FSF</span>{/if}
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
    <h2 class="section-h">
      {$t('licensePolicy.conditional.title')}
      <InfoTip text={$t('licensePolicy.conditional.intro')} />
    </h2>
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
                  {#if d?.isOsiApproved}<span class="badge osi" title={$t('spdx.osiApproved')}>OSI</span>{/if}
                  {#if d?.isFsfLibre}<span class="badge fsf" title={$t('spdx.fsfLibre')}>FSF</span>{/if}
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
                  {#if d?.isOsiApproved}<span class="badge osi" title={$t('spdx.osiApproved')}>OSI</span>{/if}
                  {#if d?.isFsfLibre}<span class="badge fsf" title={$t('spdx.fsfLibre')}>FSF</span>{/if}
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

{#if licenseTextModal}
  <LicenseTextModal identifier={licenseTextModal}
                     referenceUrl={detail[licenseTextModal]?.referenceUrl}
                     on:close={() => licenseTextModal = null} />
{/if}

<style>
  /* .section-h is global (app.css). */
  .mode-line { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text2); margin: 0 0 20px; }
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
