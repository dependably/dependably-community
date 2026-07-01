<!--
  Shared component used by both the Allowlist and Blocklist tabs of OrgSettings.
  Both lists have the same shape — ecosystem badge, pattern column, added date, remove
  action — so the only per-list differences are:
    - the i18n key prefix ('allowlist' or 'blocklist')
    - the entry shape's pattern field name ('purlPattern' vs 'pattern')
    - the modal placeholder/hint copy

  Parent owns the list state + API calls; this component handles sort + render.
-->
<script>
  import { t } from 'svelte-i18n'
  import { formatDateShort } from '../format.js'
  import DataTable from '../DataTable.svelte'

  export let entries = []
  export let loading = false
  /** i18n prefix: 'allowlist' or 'blocklist' */
  export let i18nPrefix = 'allowlist'
  /** Field on each entry that holds the pattern string ('purlPattern' or 'pattern'). */
  export let patternField = 'purlPattern'
  /** @type {() => void} */
  export let onAdd = () => {}
  /** @type {(id: string) => void} */
  export let onRemove = () => {}

  $: columns = [
    { key: 'patternCol',   label: $t(`${i18nPrefix}.columns.${patternField === 'purlPattern' ? 'purlPattern' : 'pattern'}`), sortable: true },
    { key: 'createdAt',    label: $t(`${i18nPrefix}.columns.added`),        sortable: true, width: '110px' },
    { key: 'actions',      label: '',                                       sortable: false, width: '90px' },
  ]

  const comparators = {
    patternCol: (a, b) => (a[patternField] ?? '').localeCompare(b[patternField] ?? ''),
  }
</script>

<div class="page-header list-header">
  <span></span>
  <button class="primary" on:click={onAdd}>{$t(`${i18nPrefix}.addEntry`)}</button>
</div>

<DataTable
  {columns}
  rows={entries}
  {comparators}
  {loading}
  initialSort={{ key: 'patternCol', dir: 'asc' }}
  emptyText={$t(`${i18nPrefix}.empty`)}
  tableClass="list-table"
  let:row={e}
>
  <tr>
    <td class="t-mono">{e[patternField]}</td>
    <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
    <td><button class="danger btn-sm" on:click={() => onRemove(e.id)}>{$t('common.actions.remove')}</button></td>
  </tr>
</DataTable>

<style>
  /* .list-header margin-bottom is global — see app.css */
</style>
