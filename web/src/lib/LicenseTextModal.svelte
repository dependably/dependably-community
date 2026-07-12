<script>
  import { createEventDispatcher, onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import ErrorBanner from './ErrorBanner.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'

  export let identifier
  export let referenceUrl = null

  const dispatch = createEventDispatcher()

  let name = null
  let licenseText = null
  let loading = true
  let error = ''
  let notFound = false

  onMount(async () => {
    try {
      const data = await api.getSpdxText(identifier)
      name = data?.name ?? null
      licenseText = data?.licenseText ?? null
    } catch (e) {
      if (e.status === 404) {
        notFound = true
      } else {
        error = e.message ?? 'failed to load license text'
      }
    } finally {
      loading = false
    }
  })

  function close() { dispatch('close') }
  function onKeydown(e) { if (e.key === 'Escape') close() }
  function onBackdropClick(e) { if (e.target === e.currentTarget) close() }
</script>

<svelte:window on:keydown={onKeydown} />

<div class="overlay" on:click={onBackdropClick} role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="license-text-title">
    <header>
      <div class="titles">
        <span class="eyebrow">{$t('licenseText.title')}</span>
        <h2 id="license-text-title">{name ? `${name} (${identifier})` : identifier}</h2>
      </div>
      <button class="close" on:click={close} aria-label={$t('licenseText.close')}>×</button>
    </header>

    <div class="body">
      {#if error}
        <ErrorBanner message={error} />
      {:else if loading}
        <LoadingSpinner label={$t('licenseText.loading')} />
      {:else if notFound || licenseText === null}
        <div class="fallback">
          <p>{$t('licenseText.notAvailable')}</p>
          {#if referenceUrl}
            <a href={referenceUrl} target="_blank" rel="noopener noreferrer">{$t('licenseText.viewUpstream')}</a>
          {/if}
        </div>
      {:else}
        <pre class="license-text">{licenseText}</pre>
      {/if}
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 24px;
  }
  .dialog {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: 100%;
    max-width: 760px;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  .titles { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .eyebrow { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text2); }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .close {
    background: transparent;
    border: 0;
    font-size: 22px;
    line-height: 1;
    color: var(--text2);
    cursor: pointer;
    padding: 4px 8px;
    min-height: 0;
  }
  .close:hover { color: var(--text); }
  .body {
    padding: 16px 20px;
    overflow-y: auto;
    flex: 1;
  }
  .fallback {
    color: var(--text2);
    font-size: 13px;
  }
  .fallback p { margin: 0 0 8px; }
  .license-text {
    font-family: var(--mono, 'JetBrains Mono', ui-monospace, monospace);
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
    color: var(--text);
  }
</style>
