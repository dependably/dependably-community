<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { ECOSYSTEMS as ecosystems, ECO_LABEL } from '../lib/ecosystems.js'

  let snippets = {}, loading = {}, copyState = {}

  $: org = $currentOrg
  $: if (org) loadAll()

  async function loadAll() {
    for (const eco of ecosystems) {
      loading[eco] = true
      try {
        const d = await api.getSetup( eco)
        snippets[eco] = d.snippet
      } catch { snippets[eco] = null }
      loading[eco] = false
    }
  }

  async function copy(eco) {
    const ok = await copyToClipboard(snippets[eco])
    copyState[eco] = ok ? 'copied' : 'failed'
    setTimeout(() => { copyState[eco] = ''; copyState = copyState }, 2000)
  }
</script>

<div class="page">
  <div class="page-header"><h1 class="page-title">{$t('setup.title')}</h1></div>
  <p class="subtitle text-muted">{$t('setup.subtitle')}</p>

  {#each ecosystems as eco (eco)}
    <h3 class="eco-heading">{ECO_LABEL[eco]}</h3>
    {#if loading[eco]}
      <span class="spinner"></span>
    {:else if snippets[eco]}
      <div class="copy-block snippet-block">
        <span class="copy-block-text">{snippets[eco]}</span>
        <button class="copy-btn" on:click={() => copy(eco)}>
          {copyState[eco] === 'copied' ? $t('common.actions.copied') : copyState[eco] === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
        </button>
      </div>
    {:else}
      <p class="text-muted">{$t('common.notAvailable')}</p>
    {/if}
  {/each}

  <p class="footer-link text-muted t-sm">
    <a href="https://github.com/dependably/dependably-community/tree/main/skills" target="_blank" rel="noreferrer">
      {$t('setup.moreOptions')}
    </a>
  </p>
</div>

<style>
  .subtitle { margin-bottom: 24px; }
  .eco-heading { margin-bottom: 8px; }
  .snippet-block { margin-bottom: 20px; }
  .footer-link { margin-top: 24px; }
</style>
