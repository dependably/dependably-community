<!--
  Namespaces tab — dependency-confusion defense in two layers: reserved namespaces
  (the passive lock — names that are never fetched from upstream) followed by Claims
  (the active grant workflow — who has been granted a namespace). Reserved first so
  the page reads "what is locked" before "who holds the grant".

  Reserved-namespace list state is parent-owned; Claims is self-contained.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsNamespaces from './SettingsNamespaces.svelte'
  import Claims from '../../pages/Claims.svelte'

  export let reservedEntries = []
  export let reservedLoaded = false
  /** @type {() => void} */
  export let onAddReserved = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveReserved = () => {}
</script>

<div class="page-header list-header">
  <h3 class="section-h">{$t('settings.proxy.reservedSection')}</h3>
</div>
<p class="form-hint">{$t('settings.proxy.reservedHint')}</p>
<SettingsNamespaces
  entries={reservedEntries}
  loading={!reservedLoaded}
  onAdd={onAddReserved}
  onRemove={onRemoveReserved} />

<div class="claims-section">
  <Claims />
</div>

<style>
  /* Claims renders as a bare section (no page wrapper); restore the gap that
     separates it from the reserved-namespaces table above. */
  .claims-section { margin-top: 28px; }
</style>
