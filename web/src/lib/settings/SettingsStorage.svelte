<!--
  Storage tab — upload caps and retention in two labeled sections with independent
  Save buttons. Upload limits hit /settings via updateOrgSettings; retention hits
  /retention via updateRetention. The parent retains sole ownership of both objects.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsUpload from './SettingsUpload.svelte'
  import SettingsRetention from './SettingsRetention.svelte'
  import InfoTip from '../InfoTip.svelte'

  export let settings
  export let retention
  export let instanceMax = null
  export let saving = false
  export let onSaveUpload = () => {}
  export let onSaveRetention = () => {}
</script>

<h3 class="section-h">
  {$t('settings.storage.uploadTitle')}
  <InfoTip text={$t('settings.storage.uploadHint')} />
</h3>
<SettingsUpload {settings} {instanceMax} {saving} onSave={onSaveUpload} />

<h3 class="section-h mt-4">
  {$t('settings.storage.retentionTitle')}
  <InfoTip text={$t('settings.storage.retentionHint')} />
</h3>
<SettingsRetention {retention} {saving} onSave={onSaveRetention} />

<style>
  .mt-4 { margin-top: 24px; }
</style>
