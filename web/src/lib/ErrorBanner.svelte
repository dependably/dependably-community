<!--
  Page-level error banner. Wraps the existing `.page-error` style so every page renders
  errors identically. Pass the message as the `message` prop, or use the default slot for
  richer content. Renders nothing when `message` is falsy and no slot content is provided.
-->
<script>
  export let message = ''
</script>

{#if message || $$slots.default}
  <div class="page-error" role="alert">
    {#if $$slots.default}<slot />{:else}{message}{/if}
  </div>
{/if}
