<!--
  Minimal loading indicator for non-table loading states. Table pages keep their own
  skeleton-row loading; this is for forms, modal contents, and panel-level loads.
-->
<script>
  export let label = ''
</script>

<div class="loading" role="status" aria-live="polite">
  <span class="spinner" aria-hidden="true"></span>
  {#if label}<span class="loading-label">{label}</span>{/if}
</div>

<style>
  .loading {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: var(--text2);
  }
  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
