<script>
  /**
   * Step 2 — which package manager.
   *
   * The only free choice among the four axes: the other three are constrained by what the
   * server emitted for it. Operation sits in step 1 because it selects the token's preset;
   * scope and variant sit in step 3 because they reshape the configuration and nothing else.
   * This step binds neither, so it stands alone.
   */
  import { t } from 'svelte-i18n'
  import { ECOSYSTEMS, ECO_LABEL } from '../ecosystems.js'

  export let ecosystem = 'npm'
</script>

<div class="step">
  <div class="num">2</div>
  <div>
    <h4>{$t('setup.step.choose.title')}</h4>

    <div class="axis">
      <label class="axis-label" for="setup-ecosystem">{$t('setup.axis.ecosystem')}</label>
      <select id="setup-ecosystem" class="eco-select" bind:value={ecosystem}>
        {#each ECOSYSTEMS as eco (eco)}
          <option value={eco}>{ECO_LABEL[eco]}</option>
        {/each}
      </select>
    </div>
  </div>
</div>

<style>
  .axis { margin-bottom: 0; }

  .axis-label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text2);
    margin-bottom: 6px;
  }
</style>
