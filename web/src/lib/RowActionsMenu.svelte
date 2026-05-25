<!--
  Per-row kebab "…" actions menu. Pattern extracted from VersionTable.svelte; reused by any
  table that wants a popover of row-scoped actions (delete, disable, edit, …).

  Usage:
    <RowActionsMenu id={row.id} bind:openId={openActionsId} ariaLabel={$t('foo.actionsMenu.open')}>
      <button class="popover-item" on:click|stopPropagation={() => doThing(row)}>Thing</button>
      <div class="popover-divider"></div>
      <button class="popover-item danger" on:click|stopPropagation={() => del(row)}>Delete</button>
    </RowActionsMenu>

  The component owns the kebab button + popover positioning + click-outside dismiss. The
  consumer supplies the menu items via the default slot and closes the menu by either
  binding `openId` (set to null in the click handler) or letting click-outside handle it.

  Items use the global `.popover-item`/`.popover-divider`/`.popover-item.danger` classes
  defined below — they intentionally cascade through Svelte's scoping because the slot
  content renders in the parent's scope. (Same trade-off VersionTable.svelte already makes.)
-->
<script>
  /** Row id used to match this button against the currently-open popover. */
  export let id
  /** Two-way binding: the id of the row whose popover is open, or null. */
  export let openId = null
  /** Aria-label for the kebab button — required so screen readers identify the trigger. */
  export let ariaLabel = 'Open actions menu'

  let popoverPos = { top: 0, left: 0 }

  function toggle(e) {
    e.stopPropagation()
    if (openId === id) { openId = null; return }
    const rect = e.currentTarget.getBoundingClientRect()
    const POPOVER_WIDTH = 180
    popoverPos = {
      top: rect.bottom + 4,
      left: Math.max(8, rect.right - POPOVER_WIDTH),
    }
    openId = id
  }

  function handleWindowClick(e) {
    if (openId !== id) return
    if (e.target?.closest && (e.target.closest('.actions-popover') || e.target.closest('.kebab-btn'))) return
    openId = null
  }
</script>

<svelte:window on:click={handleWindowClick} />

<button
  type="button"
  class="kebab-btn"
  on:click={toggle}
  aria-label={ariaLabel}
  aria-haspopup="true"
  aria-expanded={openId === id}
>⋯</button>

{#if openId === id}
  <div class="actions-popover" style:top="{popoverPos.top}px" style:left="{popoverPos.left}px" role="menu">
    <slot />
  </div>
{/if}

<style>
  .kebab-btn {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 16px;
    line-height: 1;
    cursor: pointer;
    color: var(--text2);
  }
  .kebab-btn:hover { background: var(--bg3); color: var(--text); }

  /* :global so the slotted items rendered in the parent scope still pick up these styles. */
  :global(.actions-popover) {
    position: fixed;
    z-index: 1000;
    min-width: 180px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 4px 0;
  }
  :global(.popover-item) {
    display: block;
    width: 100%;
    text-align: left;
    background: transparent;
    border: none;
    padding: 6px 12px;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }
  :global(.popover-item:hover:not(:disabled)) { background: var(--bg3); }
  :global(.popover-item:disabled) { color: var(--text2); cursor: not-allowed; }
  :global(.popover-item.danger) { color: var(--badge-red-text); }
  :global(.popover-divider) {
    height: 1px;
    margin: 4px 0;
    background: var(--border);
  }
</style>
