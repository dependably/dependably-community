<!--
  Per-row kebab "…" actions menu. Pattern extracted from VersionTable.svelte; reused by any
  table that wants a popover of row-scoped actions (delete, disable, edit, …).

  Usage:
    <RowActionsMenu id={row.id} bind:openId={openActionsId} ariaLabel={$t('foo.actionsMenu.open')}>
      <button class="popover-item" on:click|stopPropagation={() => doThing(row)}>Thing</button>
      <div class="popover-divider"></div>
      <button class="popover-item danger" on:click|stopPropagation={() => del(row)}>Delete</button>
    </RowActionsMenu>

  The component owns the kebab button + popover positioning (flipping above the trigger when
  there is no room below and clamping to the right viewport edge — it is position:fixed, so an
  overflowing menu is unreachable rather than merely clipped), click-outside dismiss, and
  close-on-scroll (a fixed popover does not follow its row, so it closes rather than floating
  detached). The consumer supplies the menu items via the default slot and closes the menu by
  either binding `openId` (set to null in the click handler) or letting click-outside handle it.

  Items use the global `.popover-item`/`.popover-divider`/`.popover-item.danger` classes
  defined below — they intentionally cascade through Svelte's scoping because the slot
  content renders in the parent's scope. (Same trade-off VersionTable.svelte already makes.)
-->
<script>
  import { tick } from 'svelte'

  /** Row id used to match this button against the currently-open popover. */
  export let id
  /** Two-way binding: the id of the row whose popover is open, or null. */
  export let openId = null
  /** Aria-label for the kebab button — required so screen readers identify the trigger. */
  export let ariaLabel = 'Open actions menu'

  let popoverPos = { top: 0, left: 0 }
  let popoverEl

  /** Gap between the trigger and the popover, and the minimum margin off a viewport edge. */
  const GAP = 4
  const EDGE = 8

  async function toggle(e) {
    e.stopPropagation()
    if (openId === id) { openId = null; return }
    const rect = e.currentTarget.getBoundingClientRect()
    // First guess from the popover's min-width; corrected below once it has rendered.
    const POPOVER_MIN_WIDTH = 180
    popoverPos = {
      top: rect.bottom + GAP,
      left: Math.max(EDGE, rect.right - POPOVER_MIN_WIDTH),
    }
    openId = id

    // The popover is position:fixed, so a `top` past the viewport bottom puts it somewhere no
    // amount of scrolling can reach — the menu is simply unreachable for any row low enough on a
    // long list. Its size depends on the slotted items (a long translated label widens it past
    // its min-width), so it is measured once rendered: flipped above the trigger when it does
    // not fit below, and pulled back inside the right viewport edge when it does not fit beside.
    await tick()
    if (!popoverEl || openId !== id) return
    const { width, height } = popoverEl.getBoundingClientRect()
    let top = popoverPos.top
    if (top + height > window.innerHeight - EDGE) top = Math.max(EDGE, rect.top - height - GAP)
    const left = Math.max(EDGE, Math.min(rect.right - width, window.innerWidth - width - EDGE))
    popoverPos = { top, left }
  }

  // A fixed popover does not move with its row, so any scroll — the document, the sidebar, or a
  // table's own horizontal scroller (capture, because scroll does not bubble) — closes it rather
  // than leaving it floating detached from the row it belongs to.
  function handleScroll() {
    if (openId === id) openId = null
  }

  function handleWindowClick(e) {
    if (openId !== id) return
    if (e.target?.closest && (e.target.closest('.actions-popover') || e.target.closest('.kebab-btn'))) return
    openId = null
  }
</script>

<svelte:window on:click={handleWindowClick} on:scroll|capture={handleScroll} />

<button
  type="button"
  class="kebab-btn"
  on:click={toggle}
  aria-label={ariaLabel}
  aria-haspopup="true"
  aria-expanded={openId === id}
>⋯</button>

{#if openId === id}
  <div
    class="actions-popover"
    bind:this={popoverEl}
    style:top="{popoverPos.top}px"
    style:left="{popoverPos.left}px"
    role="menu"
  >
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
