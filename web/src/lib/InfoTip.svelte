<!--
  Small "i" info icon that reveals help text in a lightweight popover. Used in the settings
  forms to replace the inline `.form-hint` text under each field — the help is one hover (or
  click) away instead of always on screen, keeping the forms compact. The bubble shows instantly
  on hover/focus (no native `title` delay) and toggles on click so it works on touch too.
  `aria-label` carries the same text for screen readers.

  The bubble is `position: fixed`, placed from the icon's viewport rect, so an ancestor that
  clips overflow (a `.table-scroll` wrapper, whose `overflow-x: auto` also clips vertically)
  cannot hide it. It sits above the icon, flips below when there is no room above, and is
  clamped to the viewport horizontally. Scrolling or resizing hides it rather than leaving it
  detached from the icon.
-->
<script>
  import { tick } from 'svelte'

  export let text = ''

  const GAP = 6
  const MARGIN = 8

  let open = false
  let hovered = false
  let button
  let bubble
  let top = 0
  let left = 0

  $: visible = open || hovered
  $: if (visible) place()

  async function place() {
    await tick()
    if (!button || !bubble) return
    const icon = button.getBoundingClientRect()
    const { width, height } = bubble.getBoundingClientRect()
    const above = icon.top - GAP - height
    top = above >= MARGIN ? above : icon.bottom + GAP
    const centred = icon.left + icon.width / 2 - width / 2
    left = Math.max(MARGIN, Math.min(centred, window.innerWidth - width - MARGIN))
  }

  function toggle() {
    open = !open
  }

  function hide() {
    open = false
    hovered = false
  }
</script>

<svelte:window on:click={() => (open = false)} on:scroll|capture={hide} on:resize={hide} />

<span class="info-tip-wrap">
  <button
    bind:this={button}
    type="button"
    class="info-tip"
    class:open
    aria-label={text}
    aria-expanded={open}
    tabindex="0"
    on:click|preventDefault|stopPropagation={toggle}
    on:mouseenter={() => (hovered = true)}
    on:mouseleave={() => (hovered = false)}
    on:focus={() => (hovered = true)}
    on:blur={() => (hovered = false)}
  >
    <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-info"/></svg>
  </button>
  <span
    bind:this={bubble}
    class="info-tip-bubble"
    class:visible
    role="tooltip"
    style:top="{top}px"
    style:left="{left}px"
  >{text}</span>
</span>

<style>
  .info-tip-wrap {
    display: inline-flex;
    vertical-align: middle;
  }
  .info-tip {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    margin: 0;
    border: none;
    background: none;
    color: var(--text2);
    cursor: pointer;
    line-height: 0;
  }
  .info-tip:hover,
  .info-tip:focus-visible,
  .info-tip.open { color: var(--accent); }

  .info-tip-bubble {
    position: fixed;
    z-index: 1000;
    width: max-content;
    max-width: 280px;
    padding: 6px 9px;
    border-radius: var(--radius);
    background: var(--bg2);
    color: var(--text);
    border: 1px solid var(--border);
    font-size: 12px;
    font-weight: 400;
    line-height: 1.4;
    text-align: left;
    white-space: normal;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
  }
  .info-tip-bubble.visible {
    opacity: 1;
    visibility: visible;
  }
</style>
