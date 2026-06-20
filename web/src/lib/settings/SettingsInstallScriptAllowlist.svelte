<!--
  Install-script allowlist section — packages exempt from the install-script block-gate arm.
  When block_install_scripts='block', packages on this list are served normally regardless.
  Same parent-owns-state shape as SettingsNamespaces: each entry is (ecosystem, name,
  optional version_pattern). NULL version_pattern = all versions exempt.
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
    { key: 'ecosystem',       label: $t('installScriptAllowlist.columns.ecosystem'),       sortable: true,  width: '110px' },
    { key: 'name',            label: $t('installScriptAllowlist.columns.name'),            sortable: true },
    { key: 'versionPattern',  label: $t('installScriptAllowlist.columns.versionPattern'),  sortable: true,  width: '140px' },
    { key: 'createdAt',       label: $t('installScriptAllowlist.columns.added'),           sortable: true,  width: '110px' },
    { key: 'actions',         label: '',                                                   sortable: false, width: '90px' },
  ]

  const comparators = {
    ecosystem: (a, b) => (a.ecosystem ?? '').localeCompare(b.ecosystem ?? ''),
    name:      (a, b) => (a.name ?? '').localeCompare(b.name ?? ''),
  }
</script>

<div class="page-header list-header">
  <span></span>
  <button class="primary" on:click={onAdd}>{$t('installScriptAllowlist.addEntry')}</button>
</div>

<DataTable
  {columns}
  rows={entries}
  {comparators}
  {loading}
  initialSort={{ key: 'name', dir: 'asc' }}
  emptyText={$t('installScriptAllowlist.empty')}
  tableClass="list-table"
  let:row={e}
>
  <tr>
    <td><span class="badge {e.ecosystem}">{e.ecosystem}</span></td>
    <td class="t-mono">{e.name}</td>
    <td class="t-mono text-muted">{e.versionPattern ?? $t('installScriptAllowlist.allVersions')}</td>
    <td class="text-muted">{$formatDateShort(e.createdAt)}</td>
    <td>
      <button class="danger btn-sm" on:click={() => onRemove(e.id)}>{$t('common.actions.remove')}</button>
    </td>
  </tr>
</DataTable>
