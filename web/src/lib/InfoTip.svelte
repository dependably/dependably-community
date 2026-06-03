<!--
  Small "i" info icon that reveals help text in a lightweight popover. Used in the settings
  forms to replace the inline `.form-hint` text under each field — the help is one hover (or
  click) away instead of always on screen, keeping the forms compact. The bubble shows instantly
  on hover/focus (no native `title` delay) and toggles on click so it works on touch too.
  `aria-label` carries the same text for screen readers.
-->
<script>
  export let text = ''

  let open = false

  function toggle() {
    open = !open
  }

  function close() {
    open = false
  }
</script>

<svelte:window on:click={close} />

<span class="info-tip-wrap">
  <button
    type="button"
    class="info-tip"
    class:open
    aria-label={text}
    aria-expanded={open}
    tabindex="0"
    on:click|preventDefault|stopPropagation={toggle}
  >
    <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-info"/></svg>
  </button>
  <span class="info-tip-bubble" class:open role="tooltip">{text}</span>
</span>

<style>
  .info-tip-wrap {
    position: relative;
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
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    z-index: 10;
    width: max-content;
    max-width: 240px;
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
  .info-tip-wrap:hover .info-tip-bubble,
  .info-tip:focus-visible + .info-tip-bubble,
  .info-tip-bubble.open {
    opacity: 1;
    visibility: visible;
  }
</style>
