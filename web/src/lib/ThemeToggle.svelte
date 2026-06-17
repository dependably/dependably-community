<script>
  import { t } from 'svelte-i18n'
  import { theme } from './store.js'

  // Binary light/dark: a single switch that flips on any click, rather than a
  // segmented control where each side selects its own value. Clicking anywhere on
  // the track toggles to the other theme.
  function toggle() {
    theme.set($theme === 'dark' ? 'light' : 'dark')
  }
</script>

<button
  type="button"
  class="theme-toggle"
  class:dark={$theme === 'dark'}
  role="switch"
  aria-checked={$theme === 'dark'}
  aria-label={$t('profile.rows.themeTitle')}
  title={$theme === 'dark' ? $t('profile.theme.dark') : $t('profile.theme.light')}
  on:click={toggle}
>
  <svg class="ico" width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-sun"/></svg>
  <span class="knob" aria-hidden="true"></span>
  <svg class="ico" width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-moon"/></svg>
</button>

<style>
  .theme-toggle {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: space-between;
    width: 50px;
    height: 28px;
    padding: 0 7px;
    border: 1px solid var(--border);
    border-radius: 99px;
    background: var(--bg2);
    cursor: pointer;
    color: var(--text2);
  }
  .theme-toggle:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .theme-toggle .ico { flex: none; }
  /* The knob is a filled disc that sits over the inactive icon: it covers the
     moon in light mode and the sun in dark mode, so the exposed icon always
     names the current theme. */
  .knob {
    position: absolute;
    top: 50%;
    left: calc(100% - 25px);
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--accent);
    transform: translateY(-50%);
    transition: left 0.15s ease;
    z-index: 1;
  }
  .theme-toggle.dark .knob {
    left: 3px;
  }
</style>
