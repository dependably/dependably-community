// Masked placeholder for a write-only secret input whose value is already stored server-side.
//
// Write-only secrets (Slack webhook URL, SMTP password, webhook signing secret, upstream
// registry credentials) are never echoed back from the server — the input is always bound to an
// empty string so that submitting it empty preserves the existing secret. That left a stored
// secret looking identical to an unconfigured one: an empty box. `secretPlaceholder(isSet)`
// returns the masked placeholder to render when the server reports a value is set (hasSlackWebhook
// / hasEmailSmtpPassword / hasWebhook / hasPassword / hasSecret / …) and '' otherwise, so the
// field reads as "configured — type to replace" without ever exposing or pre-filling the secret.
// Standard SaaS convention (GitHub, Stripe, Vercel all show masked dots for a stored secret).
//
// The bullet is U+2022 (typographic), not an emoji codepoint — kept in this .js module rather
// than inline in the .svelte files so it is a single design token and stays clear of the
// dependably/no-emoji ESLint rule (which only applies to *.svelte). See DESIGN.md §10.
const MASK = '••••••••'

export function secretPlaceholder(isSet) {
  return isSet ? MASK : ''
}
