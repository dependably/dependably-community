<!--
  SBOM/VEX export options dialog — shared by the project-version and collection export surfaces.
  Follows the ProjectEditModal.svelte modal pattern: mounted unconditionally, `open` controls
  visibility so the parent's export state (busy/error handling) is not torn down between opens.

  Every option states its effect in a sentence beside it — a filtered or downgraded document is a
  narrower one, and an operator choosing it should be able to tell what changed without exporting
  first (see DESIGN-sbom-vex-sarif-projects and the disclosure properties the server writes into
  the document itself).

  Props:
    open     {boolean}                     controls visibility.
    surface  {'version'|'collection'}      'version' also offers the VEX variant; a collection has
                                            no per-project VEX (the vdr variant already carries the
                                            effective analysis state for the whole subtree).
    busy     {boolean}                     disables the Export button and swaps its label while the
                                            parent's own export request is in flight.

  Events:
    on:export  detail: { variant, format, specVersion, scope }
    on:close   Escape, backdrop, or Cancel. Ignored while busy.
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'

  export let open = false
  export let surface = 'version'
  export let busy = false

  const dispatch = createEventDispatcher()

  let variant = 'inventory'
  const format = 'cyclonedx-json'
  let specVersion = '1.7'
  // The same all|prod|dev vocabulary the component table's own scope filter reads
  // (SbomAnalysisProjection.ScopeFilters) — not a parallel spelling for the export surface.
  let scope = 'all'

  // Reset to the defaults each time the dialog opens rather than carrying a stale selection
  // from a previous export forward — a reopened dialog should read as a fresh choice, not a
  // continuation of the last one.
  $: if (open) {
    variant = 'inventory'
    specVersion = '1.7'
    scope = 'all'
  }

  $: isVex = variant === 'vex'

  function submit() {
    if (busy) return
    // A VEX document has no components, so the scope fieldset is hidden while variant is vex —
    // but the underlying value survives a variant switch (so it reappears if the operator flips
    // back to inventory/vdr), which would otherwise let a stale 'prod'/'dev' selection ride
    // along into a VEX export's filename even though nothing was filtered. The dispatched detail
    // reports 'all' whenever nothing was actually offered.
    dispatch('export', { variant, format, specVersion, scope: isVex ? 'all' : scope })
  }

  function close() { if (!busy) dispatch('close') }
  function onKeydown(e) { if (open && e.key === 'Escape') close() }
  function onBackdropClick(e) { if (e.target === e.currentTarget) close() }
</script>

<svelte:window on:keydown={onKeydown} />

{#if open}
  <div class="overlay" on:click={onBackdropClick} role="presentation">
    <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="sbom-export-title">
      <header>
        <h2 id="sbom-export-title">{$t('sbomExport.title')}</h2>
        <button class="close" on:click={close} disabled={busy} aria-label={$t('common.actions.cancel')}>×</button>
      </header>

      <div class="body">
        <!-- Reuses the two pre-existing export hints rather than a new key: same wording the
             popover menus showed before the dialog replaced them. -->
        <p class="dialog-hint">
          {surface === 'collection' ? $t('projects.detail.exportHint') : $t('sbomAnalysis.export.hint')}
        </p>

        <fieldset>
          <legend>{$t('sbomExport.variant.label')}</legend>
          <label class="option-row">
            <input type="radio" name="sbom-export-variant" value="inventory" bind:group={variant} disabled={busy} />
            <span>
              <span class="option-title">{$t('sbomExport.variant.inventory')}</span>
              <span class="option-help">{$t('sbomExport.variant.inventoryHelp')}</span>
            </span>
          </label>
          <label class="option-row">
            <input type="radio" name="sbom-export-variant" value="vdr" bind:group={variant} disabled={busy} />
            <span>
              <span class="option-title">{$t('sbomExport.variant.vdr')}</span>
              <span class="option-help">{$t('sbomExport.variant.vdrHelp')}</span>
            </span>
          </label>
          {#if surface === 'version'}
            <label class="option-row">
              <input type="radio" name="sbom-export-variant" value="vex" bind:group={variant} disabled={busy} />
              <span>
                <span class="option-title">{$t('sbomExport.variant.vex')}</span>
                <span class="option-help">{$t('sbomExport.variant.vexHelp')}</span>
              </span>
            </label>
          {/if}
        </fieldset>

        {#if !isVex}
          <fieldset>
            <legend>{$t('sbomExport.format.label')}</legend>
            <label class="option-row">
              <input type="radio" name="sbom-export-format" value="cyclonedx-json" checked disabled />
              <span>
                <span class="option-title">{$t('sbomExport.format.cyclonedxJson')}</span>
                <span class="option-help">{$t('sbomExport.format.cyclonedxJsonHelp')}</span>
              </span>
            </label>
          </fieldset>
        {/if}

        <fieldset>
          <legend>{$t('sbomExport.specVersion.label')}</legend>
          <label class="option-row">
            <input type="radio" name="sbom-export-spec-version" value="1.7" bind:group={specVersion} disabled={busy} />
            <span>
              <span class="option-title">{$t('sbomExport.specVersion.v17')}</span>
              <span class="option-help">{$t('sbomExport.specVersion.v17Help')}</span>
            </span>
          </label>
          <label class="option-row">
            <input type="radio" name="sbom-export-spec-version" value="1.6" bind:group={specVersion} disabled={busy} />
            <span>
              <span class="option-title">{$t('sbomExport.specVersion.v16')}</span>
              <span class="option-help">{$t('sbomExport.specVersion.v16Help')}</span>
            </span>
          </label>
        </fieldset>

        {#if !isVex}
          <fieldset>
            <!-- Titles reuse sbomAnalysis.scopeFilter.* verbatim — the same labels the component
                 table's own scope chips render (SCOPE_CHIPS) — so the two surfaces cannot drift
                 on what a given word means. -->
            <legend>{$t('sbomExport.scope.label')}</legend>
            <label class="option-row">
              <input type="radio" name="sbom-export-scope" value="all" bind:group={scope} disabled={busy} />
              <span>
                <span class="option-title">{$t('sbomAnalysis.scopeFilter.all')}</span>
                <span class="option-help">{$t('sbomExport.scope.allHelp')}</span>
              </span>
            </label>
            <label class="option-row">
              <input type="radio" name="sbom-export-scope" value="prod" bind:group={scope} disabled={busy} />
              <span>
                <span class="option-title">{$t('sbomAnalysis.scopeFilter.prod')}</span>
                <span class="option-help">{$t('sbomExport.scope.prodHelp')}</span>
              </span>
            </label>
            <label class="option-row">
              <input type="radio" name="sbom-export-scope" value="dev" bind:group={scope} disabled={busy} />
              <span>
                <span class="option-title">{$t('sbomAnalysis.scopeFilter.dev')}</span>
                <span class="option-help">{$t('sbomExport.scope.devHelp')}</span>
              </span>
            </label>
          </fieldset>
        {/if}
      </div>

      <footer>
        <button type="button" on:click={close} disabled={busy}>{$t('common.actions.cancel')}</button>
        <button type="button" class="primary" on:click={submit} disabled={busy}>
          {busy ? $t('sbomExport.exporting') : $t('sbomExport.submit')}
        </button>
      </footer>
    </div>
  </div>
{/if}

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
    max-width: 520px;
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
  .body { padding: 8px 20px 4px; overflow-y: auto; }
  .dialog-hint { margin: 0 0 16px; font-size: 12px; color: var(--text2); }

  fieldset {
    border: 0;
    padding: 0;
    margin: 0 0 16px;
  }
  fieldset:last-child { margin-bottom: 4px; }
  legend {
    padding: 0;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text2);
    margin-bottom: 8px;
  }
  .option-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 6px 0;
    cursor: pointer;
  }
  .option-row input {
    margin-top: 3px;
    width: auto;
    cursor: pointer;
    flex-shrink: 0;
  }
  .option-row input:disabled { cursor: default; }
  .option-title { display: block; font-size: 13px; font-weight: 500; }
  .option-help { display: block; font-size: 12px; color: var(--text2); margin-top: 1px; }

  footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
</style>
