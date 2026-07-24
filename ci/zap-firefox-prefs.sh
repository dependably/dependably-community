#!/usr/bin/env sh
# Prints the value for zap-full-scan.py's -z flag: -config overrides that seed the
# ZAP daemon's selenium.firefoxPrefs list at startup. The selenium add-on exposes
# no runtime API for browser preferences (only browser arguments), so -config at
# daemon startup is the only way to set them — this is the direct equivalent of
# the firefoxUserPrefs block in web/e2e/playwright.config.ts, applied to the AJAX
# spider's fresh-profile Firefox headless instead of the e2e project's Firefox.
#
# services.settings.server=<empty> is the pref that matters most, but on its own
# it does nothing: Firefox's release/ESR channels (this image ships firefox-esr)
# silently ignore config overrides of that pref outside Nightly/tests — see
# allowServerURLOverride in Firefox's own services/settings/Utils.sys.mjs (visible
# by extracting omni.ja from the image). The zap-full job sets
# MOZ_DISABLE_NONLOCAL_CONNECTIONS=1 (that same code checks for it by name) to let
# the override take effect; without it, every pref below still reduces some
# background egress, but Remote Settings itself keeps syncing from the real
# Mozilla server regardless of what this pref says.
#
# Verified with tcpdump against a throwaway local target, one continuous browser
# context held open past 30 seconds — long enough to cross Firefox's own
# update-timer first-poll window (UpdateTimerManager.sys.mjs schedules Remote
# Settings' periodic sync no sooner than ~30s after profile-after-change, so a
# shorter session can look artificially clean): with every pref below plus
# MOZ_DISABLE_NONLOCAL_CONNECTIONS=1 set, firefox.settings.services.mozilla.com and
# firefox-settings-attachments.cdn.mozilla.net are absent entirely — zero bytes,
# not just reduced. That is the claim this file makes; a specific overall
# byte-reduction percentage from a synthetic single-target reproduction does not
# generalize to this job's real multi-page, multi-context crawl and is not stated
# here — see .gitlab-ci.yml's zap-full job for where the real number needs to come
# from (CI's own egress accounting).
#
# Once the server override is actually honored, Utils.sys.mjs's
# baseAttachmentsURL() fails identically for every collection (it queries
# ${SERVER_URL}/, and SERVER_URL is now empty) — that is a property of the
# override itself, not of any specific collection's feature flag. On that basis
# the two security.remote_settings.* entries below are a redundant safety net,
# not the primary mechanism, kept in case a future Firefox version changes the
# override-enforcement behavior again. The telemetry/safebrowsing/update/
# captive-portal entries gate separate, non-Remote-Settings channels the server
# override was never going to reach, so they stay regardless.
#
# This script only touches Firefox's own preferences. It does not address (and
# was never measured against) ZAP's own JVM-side addon-marketplace traffic —
# zap-full-scan.py adds -addonupdate and two -addoninstall flags whenever -silent
# is absent from -z, which this job's -z never sets — a separate, pre-existing
# egress source outside what Firefox preferences can reach.
#
# Add a pref: append a "name=value" line below. An empty value (e.g. "foo=") sets
# the empty string, which is what services.settings.server needs to go inert.
set -eu

prefs='
services.settings.server=
app.update.enabled=false
extensions.blocklist.enabled=false
datareporting.healthreport.uploadEnabled=false
datareporting.policy.dataSubmissionEnabled=false
toolkit.telemetry.enabled=false
toolkit.telemetry.unified=false
network.captive-portal-service.enabled=false
browser.safebrowsing.malware.enabled=false
browser.safebrowsing.phishing.enabled=false
browser.safebrowsing.downloads.enabled=false
browser.safebrowsing.downloads.remote.enabled=false
browser.safebrowsing.provider.mozilla.updateURL=
browser.safebrowsing.provider.google4.updateURL=
browser.safebrowsing.provider.google.updateURL=
privacy.trackingprotection.enabled=false
privacy.trackingprotection.pbmode.enabled=false
privacy.trackingprotection.annotate_channels=false
browser.contentblocking.database.enabled=false
extensions.systemAddon.update.enabled=false
security.remote_settings.crlite_filters.enabled=false
security.remote_settings.intermediates.enabled=false
'

out=''
i=0
for line in $prefs; do
  name="${line%%=*}"
  value="${line#*=}"
  out="$out -config selenium.firefoxPrefs.pref($i).name=$name -config selenium.firefoxPrefs.pref($i).value=$value -config selenium.firefoxPrefs.pref($i).enabled=true"
  i=$((i + 1))
done

printf '%s\n' "${out# }"
