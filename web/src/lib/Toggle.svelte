<!--
  Reusable pill switch for boolean settings — a real checkbox input (visually hidden)
  wrapped in a label, plus a .track span whose ::after is the knob. Visual design ported
  from the .auth-tab .toggle rules; every boolean on/off SETTINGS control uses this
  component so the widget appearance is consistent across tabs.
-->
<script>
  export let checked = false
  export let disabled = false
  export let ariaLabel = ''
  export let id = undefined
  // Forwarded to the real checkbox's data-testid — lets e2e specs target the
  // underlying input the same way they would a bare <input type="checkbox">.
  export let testId = undefined
</script>

<label class="toggle" class:disabled>
  <input
    {id}
    type="checkbox"
    bind:checked
    {disabled}
    aria-label={ariaLabel || undefined}
    data-testid={testId}
    on:change
  />
  <span class="track"></span>
</label>

<style>
  .toggle {
    --w: 38px; --h: 22px;
    position: relative; display: inline-block;
    width: var(--w); height: var(--h);
    flex-shrink: 0;
    min-height: 0;
    cursor: pointer;
  }
  .toggle.disabled { cursor: not-allowed; }
  .toggle input {
    opacity: 0; width: 0; height: 0; position: absolute;
  }
  .toggle .track {
    position: absolute; inset: 0;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 99px;
    cursor: pointer;
    transition: .15s;
  }
  .toggle .track::after {
    content: "";
    position: absolute; top: 2px; left: 2px;
    width: 16px; height: 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 50%;
    transition: .15s;
  }
  .toggle input:checked + .track {
    background: var(--accent);
    border-color: var(--accent);
  }
  .toggle input:checked + .track::after {
    left: calc(100% - 18px);
    background: var(--on-accent);
    border-color: var(--on-accent);
  }
  .toggle input:focus-visible + .track {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .toggle input:disabled + .track {
    opacity: .45; cursor: not-allowed;
  }
</style>
