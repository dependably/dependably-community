<!--
  Empty-state panel for list views with zero items. List-page tables already render their
  own empty row inside <tbody>; this component is for page-level "no data" panels
  (e.g. dashboard widgets, modal pickers). Pass `title` + optional `subtitle`; use the
  default slot for action buttons.
-->
<script>
  export let title = ''
  export let subtitle = ''
</script>

<div class="empty-state">
  {#if title}<div class="empty-title">{title}</div>{/if}
  {#if subtitle}<div class="empty-subtitle">{subtitle}</div>{/if}
  {#if $$slots.default}<div class="empty-actions"><slot /></div>{/if}
</div>

<style>
  .empty-state {
    padding: 32px 16px;
    text-align: center;
    color: var(--text2);
  }
  .empty-title { font-weight: 600; margin-bottom: 4px; color: var(--text); }
  .empty-subtitle { font-size: 13px; margin-bottom: 12px; }
  .empty-actions { display: inline-flex; gap: 8px; }
</style>
