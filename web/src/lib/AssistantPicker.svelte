<script>
  /**
   * Which AI assistant an install one-liner and prompt target. The choice is a property of
   * the developer, not of the surface they are on, so it is persisted once and every
   * surface that offers a skill reads the same value.
   */
  import { t } from 'svelte-i18n'
  import { ASSISTANTS, readStoredAssistant, storeAssistant } from './skills.js'

  /** The selected assistant id, bound by the parent so it can build commands with it. */
  export let assistant = readStoredAssistant()
  /** Accessible name for the group — surfaces differ in what they are picking an assistant for. */
  export let label = ''

  function select(id) {
    assistant = id
    storeAssistant(id)
  }
</script>

<div class="assistant-picker" role="group" aria-label={label || $t('skills.assistantLabel')}>
  {#each ASSISTANTS as a (a.id)}
    <button
      type="button"
      class="assistant-chip"
      class:active={assistant === a.id}
      on:click|stopPropagation={() => select(a.id)}
    >{a.label}</button>
  {/each}
</div>

<style>
  .assistant-picker { display: flex; gap: 4px; flex-wrap: wrap; }

  .assistant-chip {
    /* The global button min-height would balloon these compact chips. */
    min-height: 0;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text2);
    padding: 3px 10px;
    font-size: 12px;
    line-height: 1.4;
    border-radius: 999px;
    cursor: pointer;
  }
  .assistant-chip:hover { background: var(--bg3); color: var(--text); }
  .assistant-chip.active {
    background: var(--accent-soft);
    border-color: var(--accent);
    color: var(--accent);
    font-weight: 600;
  }
</style>
