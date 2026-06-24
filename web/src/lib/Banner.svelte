<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'

  /** @type {string} */
  export let id
  /** @type {'info'|'warn'|'alert'} */
  export let severity = 'info'
  /** @type {string} */
  export let body
  /** @type {string|null} */
  export let linkUrl = null
  /** @type {string|null} */
  export let linkLabel = null

  const dispatch = createEventDispatcher()

  function dismiss() {
    dispatch('dismiss', { id })
  }
</script>

<div class="banner banner-{severity}" role="alert">
  <span class="banner-body">
    {#if severity === 'alert'}
      <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
    {:else if severity === 'warn'}
      <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
    {:else}
      <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-info"/></svg>
    {/if}
    {body}
    {#if linkUrl && linkLabel}
      <a href={linkUrl} rel="noopener noreferrer" class="banner-link">{linkLabel}</a>
    {/if}
  </span>
  <button class="banner-close" on:click={dismiss} aria-label={$t('banner.dismiss')}>&#215;</button>
</div>

<style>
  .banner {
    display: flex;
    align-items: center;
    padding: 8px 40px 8px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    position: relative;
  }

  .banner-info {
    background: var(--info-bg);
    border-bottom-color: var(--info-border);
    color: var(--info-text);
  }

  .banner-warn {
    background: var(--warning-bg);
    border-bottom-color: var(--warning-border);
    color: var(--warning-text);
  }

  .banner-alert {
    background: var(--danger-bg);
    border-bottom-color: var(--danger-border);
    color: var(--danger-text);
  }

  .banner-body {
    flex: 1;
    text-align: center;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }

  .banner-link {
    color: inherit;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .banner-close {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: inherit;
    font-size: 20px;
    line-height: 1;
    padding: 2px 6px;
    cursor: pointer;
    opacity: 0.7;
    min-height: 0;
  }
  .banner-close:hover { opacity: 1; }
</style>
