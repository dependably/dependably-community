/**
 * Selection logic for the Setup page's configuration recipes.
 *
 * Pure and synchronous — the server payload is a parameter rather than a store read — so
 * every axis is unit-testable without a Svelte render harness, the same shape as
 * `installCommand.js` and `sbom/curlSnippet.js`.
 *
 * The page selects across four axes (ecosystem, operation, scope, variant). The server
 * emits only the cells that exist, so "which options do I show" is a question about the
 * recipe list rather than a second hardcoded matrix on this side — an ecosystem that gains
 * a Gradle variant or loses a publish path needs no change here.
 */

/** @typedef {{ path: string, locationHint: string|null, language: string, body: string, secretBearing: boolean }} SetupFile */
/** @typedef {{ kind: 'envVar'|'literal'|'command', envVar: string|null, command: string|null }} TokenDelivery */
/** @typedef {{ variant: string, operation: string, scope: string, capabilityPreset: string, files: SetupFile[], tokenDelivery: TokenDelivery, verify: string|null, caveats: string[] }} SetupRecipe */
/** @typedef {{ ecosystem: string, variants: { id: string, label: string }[], recipes: SetupRecipe[] }} SetupPayload */

export const OPERATIONS = Object.freeze(['install', 'publish'])
export const SCOPES = Object.freeze(['project', 'global'])

/** Token preset each operation needs, mirroring `capabilityPreset` on the server's recipes. */
export const OPERATION_PRESET = Object.freeze({ install: 'pull', publish: 'push' })

/**
 * The recipe list, or an empty one for a payload that is absent or malformed — every
 * selector below reads through this rather than indexing the payload directly, so a failed
 * fetch renders an empty step 3 instead of throwing.
 *
 * @param {SetupPayload|null|undefined} payload
 * @returns {SetupRecipe[]}
 */
function recipesOf(payload) {
  return Array.isArray(payload?.recipes) ? payload.recipes : []
}

/**
 * The operations this ecosystem actually supports. Go, apk and Terraform are proxy-only and
 * so offer no publish path; the page disables the control rather than offering a selection
 * that resolves to nothing.
 *
 * @param {SetupPayload|null|undefined} payload
 * @returns {string[]} in OPERATIONS order
 */
export function availableOperations(payload) {
  const present = new Set(recipesOf(payload).map((r) => r.operation))
  return OPERATIONS.filter((op) => present.has(op))
}

/**
 * The scopes available for one operation. Docker has no project scope — the Distribution
 * Spec puts the registry host in the image reference, so there is no per-repository file.
 *
 * @param {SetupPayload|null|undefined} payload
 * @param {string} operation
 * @returns {string[]} in SCOPES order
 */
export function availableScopes(payload, operation) {
  const present = new Set(
    recipesOf(payload).filter((r) => r.operation === operation).map((r) => r.scope),
  )
  return SCOPES.filter((s) => present.has(s))
}

/**
 * The variants available for one operation and scope, in the server's declared order (which
 * is display order — `pip` before `poetry` before `uv`), filtered to those that actually
 * have a recipe in this cell.
 *
 * @param {SetupPayload|null|undefined} payload
 * @param {string} operation
 * @param {string} scope
 * @returns {{ id: string, label: string }[]}
 */
export function availableVariants(payload, operation, scope) {
  const present = new Set(
    recipesOf(payload)
      .filter((r) => r.operation === operation && r.scope === scope)
      .map((r) => r.variant),
  )
  const declared = Array.isArray(payload?.variants) ? payload.variants : []
  return declared.filter((v) => present.has(v.id))
}

/**
 * The recipe for an exact selection, or null when that cell does not exist.
 *
 * @param {SetupPayload|null|undefined} payload
 * @param {string} operation
 * @param {string} scope
 * @param {string} variant
 * @returns {SetupRecipe|null}
 */
export function selectRecipe(payload, operation, scope, variant) {
  return (
    recipesOf(payload).find(
      (r) => r.operation === operation && r.scope === scope && r.variant === variant,
    ) ?? null
  )
}

/**
 * Move a selection onto the nearest cell that exists, preferring to keep what the reader
 * already chose. Switching ecosystem or operation routinely invalidates one of the lower
 * axes — picking Publish under Docker has no project scope, picking Go has no publish at
 * all — and silently rendering an empty step 3 is the failure this exists to prevent.
 *
 * Returns the same shape it takes, so a caller can assign it straight back.
 *
 * @param {SetupPayload|null|undefined} payload
 * @param {{ operation: string, scope: string, variant: string }} selection
 * @returns {{ operation: string, scope: string, variant: string }}
 */
export function reconcileSelection(payload, selection) {
  const operations = availableOperations(payload)
  if (operations.length === 0) return selection

  const operation = operations.includes(selection.operation) ? selection.operation : operations[0]

  const scopes = availableScopes(payload, operation)
  const scope = scopes.includes(selection.scope) ? selection.scope : scopes[0]

  const variants = availableVariants(payload, operation, scope).map((v) => v.id)
  const variant = variants.includes(selection.variant) ? selection.variant : variants[0]

  return { operation, scope, variant }
}

/**
 * The command that puts the token where the recipe expects it — an export line for an
 * `envVar` recipe, the tool's own login command for a `command` one, and nothing for a
 * `literal` recipe, whose token is already written into the file body.
 *
 * The real secret is substituted only here, never into a file body: a config file is
 * commonly committed, and this line is not.
 *
 * @param {TokenDelivery|null|undefined} delivery
 * @param {string|null} token the just-minted secret, or null when none is available yet
 * @returns {string|null}
 */
export function tokenCommand(delivery, token) {
  const value = token || '<token>'
  if (!delivery) return null
  if (delivery.kind === 'envVar' && delivery.envVar) return `export ${delivery.envVar}=${value}`
  if (delivery.kind === 'command' && delivery.command) return delivery.command.replaceAll('<token>', value)
  return null
}

/**
 * A file body with the real token substituted, for the `literal` recipes whose token has
 * nowhere else to live. Returns the body unchanged when no token is available, so the
 * placeholder stays visible rather than resolving to an empty string that would read as a
 * working config.
 *
 * @param {SetupFile} file
 * @param {string|null} token
 * @returns {string}
 */
export function fileBody(file, token) {
  if (!file?.secretBearing || !token) return file?.body ?? ''
  return file.body.replaceAll('<token>', token)
}
