/**
 * Builds the copyable curl snippet shown in SbomUploadModal — the equivalent
 * CI invocation for the three upload PUTs, reflecting the operator's current form values.
 * Pure and synchronous (takes `origin` as a parameter rather than reading `window.location`)
 * so it is unit-testable without a Svelte render harness.
 *
 * `parentId` is included whenever the modal was opened from a folder: without it the server
 * resolves the project name in the ROOT scope, so a copied command would file the project at the
 * top level while the modal it was copied from files it into the folder — the snippet has to be
 * the same request, not a similar one.
 *
 * @param {{ origin: string, projectName: string, projectVersion: string,
 *           autoCreate: boolean, isLatest: boolean, parentId?: string | null }} opts
 * @returns {string}
 */
export function buildCurlSnippet(opts) {
  const { origin, projectName, projectVersion, autoCreate, isLatest, parentId } = opts
  const name = projectName?.trim() || '<project-name>'
  const version = projectVersion?.trim() || '<project-version>'
  const encName = encodeURIComponent(name)
  const encVersion = encodeURIComponent(version)

  const auth = '-H "Authorization: Bearer $DEPENDABLY_TOKEN"'
  const contentType = '-H "Content-Type: application/json"'

  const parent = parentId ? `&parentId=${encodeURIComponent(parentId)}` : ''
  const sbomQuery =
    `projectName=${encName}&projectVersion=${encVersion}&autoCreate=${autoCreate}&isLatest=${isLatest}${parent}`
  const vexSarifQuery = `projectName=${encName}&projectVersion=${encVersion}${parent}`

  return [
    `# SBOM (required first — VEX/SARIF 404 on an unknown project version)`,
    `curl -X PUT ${auth} ${contentType} \\`,
    `  --data-binary @sbom.json \\`,
    `  "${origin}/api/v1/sbom?${sbomQuery}"`,
    ``,
    `# VEX (optional)`,
    `curl -X PUT ${auth} ${contentType} \\`,
    `  --data-binary @vex.json \\`,
    `  "${origin}/api/v1/vex?${vexSarifQuery}"`,
    ``,
    `# SARIF (optional — reachability from sbom-reach)`,
    `curl -X PUT ${auth} ${contentType} \\`,
    `  --data-binary @results.sarif.json \\`,
    `  "${origin}/api/v1/sarif?${vexSarifQuery}"`,
  ].join('\n')
}
