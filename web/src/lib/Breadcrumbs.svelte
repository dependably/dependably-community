<!--
  Breadcrumb trail for the projects plane: Projects / <containing folders…> / <project> / <version>.

  Every crumb but the last is a real anchor carrying the SPA path, so middle-click and copy-link
  behave; the click handler calls navigate() to keep the transition client-side. The last crumb is
  the page you are on and renders as plain text — a link back to the current page is a dead
  control, and marking it aria-current is what tells a screen reader where the trail ends.

  Consumers pass fully-formed crumbs rather than ids, because only the page knows which of them
  it is currently sitting on and how each label is translated.
-->
<script>
  import { navigate } from './store.js'
  import { pathFor } from './routes.js'

  /**
   * The trail, root first. Each entry is `{ label, page?, params? }`; an entry with no `page`
   * renders as plain text (used for the trailing current-page crumb, and for a folder the reader
   * has no permission to open).
   * @type {Array<{ label: string, page?: string, params?: Record<string, any> }>}
   */
  export let crumbs = []

  /** Accessible name for the nav landmark — the caller supplies it translated. */
  export let ariaLabel = 'Breadcrumb'

  function go(crumb, e) {
    if (!crumb.page) return
    // Let the browser handle modified clicks (new tab/window) — the href is already correct.
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    navigate(crumb.page, crumb.params ?? {})
  }
</script>

{#if crumbs.length > 0}
  <nav class="breadcrumbs" aria-label={ariaLabel}>
    <ol>
      {#each crumbs as crumb, i (i)}
        <li>
          {#if crumb.page && i < crumbs.length - 1}
            <a href={pathFor(crumb.page, crumb.params ?? {})} on:click={(e) => go(crumb, e)}>{crumb.label}</a>
          {:else}
            <span aria-current={i === crumbs.length - 1 ? 'page' : undefined}>{crumb.label}</span>
          {/if}
          {#if i < crumbs.length - 1}
            <span class="sep" aria-hidden="true">/</span>
          {/if}
        </li>
      {/each}
    </ol>
  </nav>
{/if}

<style>
  .breadcrumbs { margin: 0 0 6px; }
  .breadcrumbs ol {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: 12px;
  }
  .breadcrumbs li { display: flex; align-items: center; gap: 4px; min-width: 0; }
  .breadcrumbs a { color: var(--text2); text-decoration: none; }
  .breadcrumbs a:hover { color: var(--text); text-decoration: underline; }
  .breadcrumbs span[aria-current='page'] { color: var(--text2); }
  .sep { color: var(--border); }
</style>
