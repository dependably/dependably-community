<!--
  Reserved namespaces section of the Proxy tab — the explicit half of the
  dependency-confusion guard. Same parent-owns-state shape as SettingsList (which renders
  the allow/blocklist), but with an ecosystem column: each entry reserves a per-ecosystem
  name pattern that never consults upstream.
-->
<script>
  import { t } from 'svelte-i18n'
  import { formatDateShort } from '../format.js'
  import DataTable from '../DataTable.svelte'

  export let entries = []
  export let loading = false
  /** @type {() => void} */
  export let onAdd = () => {}
  /** @type {(id: string) => void} */
  export let onRemove = () => {}

  $: columns = [
    { key: 'ecosystem', label: $t('reservedNamespaces.columns.ecosystem'), sortable: true,  width: '110px' },
    { key: 'pattern',   label: $t('reservedNamespaces.columns.pattern'),   sortable: true },
    { key: 'createdAt', label: $t('reservedNamespaces.columns.added'),     sortable: true,  width: '110px' },
    { key: 'actions',   label: '',                                         sortable: false, width: '90px' },
  ]

  const comparators = {
    ecosystem: (a, b) => (a.ecosystem ?? '').localeCompare(b.ecosystem ?? ''),
    pattern:   (a, b) => (a.pattern ?? '').localeCompare(b.pattern ?? ''),
  }
</script>

<div class="page-header list-header">
  <span></span>
  <button class="primary" on:click={onAdd}>{$t('reservedNamespaces.addEntry')}</button>
</div>

<DataTable
  {columns}
  rows={entries}
  {comparators}
  {loading}
  initialSort={{ key: 'pattern', dir: 'asc' }}
  emptyText={$t('reservedNamespaces.empty')}
  tableClass="list-table"
  let:row={e}
>
  <tr>
    <td><span class="badge {e.ecosystem}">{e.ecosystem}</span></td>
    <td class="t-mono">{e.pattern}</td>
    <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
    <td><button class="danger btn-sm" on:click={() => onRemove(e.id)}>{$t('common.actions.remove')}</button></td>
  </tr>
</DataTable>
