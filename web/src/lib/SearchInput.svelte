<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'

  export let value = ''
  export let placeholder = ''
  export let ariaLabel = ''
  export let debounce = 300
  // `class` is a reserved word in script context — forward it under an alias so
  // callers keep their page-level sizing classes (.toolbar-search, .table-search).
  let klass = ''
  export { klass as class }

  const dispatch = createEventDispatcher()
  let timer
  let inputEl

  // type="text" (not type="search") so WebKit's native cancel button never renders
  // alongside the component's own clear button.
  function onInput() {
    clearTimeout(timer)
    timer = setTimeout(() => dispatch('search', value), debounce)
  }

  function clear() {
    clearTimeout(timer)
    value = ''
    dispatch('search', value)
    inputEl?.focus()
  }
</script>

<span class="search-input-wrap {klass}">
  <input
    type="text"
    bind:this={inputEl}
    bind:value
    {placeholder}
    aria-label={ariaLabel || undefined}
    on:input={onInput}
  />
  {#if value !== ''}
    <button type="button" class="search-clear" aria-label={$t('common.clearSearch')} on:click={clear}>
      <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-x"/></svg>
    </button>
  {/if}
</span>

<style>
  .search-input-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
  }
  .search-input-wrap input {
    width: 100%;
    padding-right: 28px;
  }
  .search-clear {
    position: absolute;
    right: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    /* The global button rule sets min-height: 36px, which overrides height and
       makes the button taller than the input, painting over its borders on hover. */
    min-height: 0;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text2);
    cursor: pointer;
  }
  .search-clear:hover {
    color: var(--text);
    background: var(--bg2);
  }
</style>
