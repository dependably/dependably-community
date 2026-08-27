import { APIRequestContext, expect } from '@playwright/test'
import { fileURLToPath } from 'url'
import { createHash, randomUUID } from 'crypto'
import fs from 'fs'
import path from 'path'

/**
 * Seeds one project version with a real SBOM + VEX + SARIF trio, so a spec asserting the
 * version-detail page never depends on data another spec created.
 *
 * The three documents are the committed backend fixtures, which share component purls and
 * advisory ids on purpose (`tests/Dependably.Tests/Fixtures/sbom/README.md`): the SBOM lists 13
 * components, the VEX carries one statement per advisory across the whole analysis-state
 * vocabulary, and the SARIF supplies the reachability and the dev/runtime split. Uploading all
 * three is what makes the scope chips assertable — `dependency_scope` is SARIF-owned, so a
 * version without one has every component at `unknown`.
 *
 * Every seeded project carries a fresh random name, so two specs (or two runs against the same
 * local database) never share a version, and a mutation one spec makes is invisible to the next.
 */

const SBOM_FIXTURES = ['cyclonedx-1.6-inventory.json', 'cyclonedx-1.6-vex.json', 'sarif-2.1.0-sbom-reach.json'] as const

export type SbomFixtureName = typeof SBOM_FIXTURES[number]

/** Absolute path of the shared SBOM/VEX/SARIF fixture directory. */
export function sbomFixturesRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '../../../tests/Dependably.Tests/Fixtures/sbom')
}

/** The exact bytes of one fixture document — the same bytes the upload sends. */
export function readSbomFixture(name: SbomFixtureName): Buffer {
  return fs.readFileSync(path.join(sbomFixturesRoot(), name))
}

export function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}

export interface SeededProjectVersion {
  projectName: string
  versionLabel: string
  projectId: string
  versionId: string
  /** Document ids returned by the three uploads, keyed by doc type. */
  documentIds: { sbom: string; vex: string; sarif: string }
  /** SPA path of this version's detail page, with an optional query string. */
  detailPath(query?: string): string
}

/**
 * Uploads the fixture trio against a freshly named project version and returns its identifiers.
 * `sbom:upload` is carried by the admin session the caller is already holding.
 */
export async function seedProjectVersion(
  authed: APIRequestContext,
  label: string,
  overrides: { projectName?: string; versionLabel?: string } = {},
): Promise<SeededProjectVersion> {
  const projectName = overrides.projectName ?? `e2e-${label}-${randomUUID()}`
  const versionLabel = overrides.versionLabel ?? '1.0.0'
  const target = `projectName=${encodeURIComponent(projectName)}&projectVersion=${versionLabel}`
  const json = { 'Content-Type': 'application/json' }

  const sbom = await authed.put(
    `/api/v1/sbom?${target}&autoCreate=true&isLatest=true`,
    { headers: json, data: readSbomFixture('cyclonedx-1.6-inventory.json') },
  )
  expect(sbom.status(), `sbom upload failed: ${await sbom.text()}`).toBe(200)
  const sbomBody = await sbom.json()

  const vex = await authed.put(
    `/api/v1/vex?${target}`,
    { headers: json, data: readSbomFixture('cyclonedx-1.6-vex.json') },
  )
  expect(vex.status(), `vex upload failed: ${await vex.text()}`).toBe(200)
  const vexBody = await vex.json()

  const sarif = await authed.put(
    `/api/v1/sarif?${target}`,
    { headers: json, data: readSbomFixture('sarif-2.1.0-sbom-reach.json') },
  )
  expect(sarif.status(), `sarif upload failed: ${await sarif.text()}`).toBe(200)
  const sarifBody = await sarif.json()

  const projectId: string = sbomBody.project.id
  const versionId: string = sbomBody.projectVersion.id

  return {
    projectName,
    versionLabel,
    projectId,
    versionId,
    documentIds: { sbom: sbomBody.documentId, vex: vexBody.documentId, sarif: sarifBody.documentId },
    detailPath: (query = '') => `/project/${projectId}/version/${versionId}${query}`,
  }
}

/**
 * Seeds two versions of one project so the second's manual triage row is genuinely inherited:
 * a decision made on the first version is carried forward onto the second by
 * `ProjectRepository.CarryForwardManualTriageAsync`, preserving the decision's original
 * `updated_by`/`updated_at` rather than restamping it — which is exactly the condition
 * `SbomAnalysisProjection.IsInherited` reads (the statement's own timestamp predates the version
 * it is now rendered against).
 *
 * `qs`/`CVE-2022-24999` is the coordinate: the fixture SBOM lists it directly (both versions
 * upload the same inventory), and the fixture VEX already carries an `in_triage` statement on it,
 * so the PUT below is a real triage decision rather than a first-ever one.
 */
export async function seedInheritedTriage(
  authed: APIRequestContext, label: string,
): Promise<{ first: SeededProjectVersion; second: SeededProjectVersion }> {
  const projectName = `e2e-${label}-${randomUUID()}`
  const first = await seedProjectVersion(authed, label, { projectName, versionLabel: '1.0.0' })

  const triage = await authed.put(
    `/api/v1/projects/${first.projectId}/versions/${first.versionId}/analysis`,
    {
      headers: { 'Content-Type': 'application/json' },
      // 'exploitable' rather than a suppressing state (not_affected/false_positive/resolved):
      // a suppressed advisory is hidden by default, and this seed exists so a caller can find
      // the carried-forward statement without also having to flip "Show suppressed" first.
      data: { purlKey: 'pkg:npm/qs', vulnKey: 'CVE-2022-24999', vexState: 'exploitable' },
    },
  )
  expect(triage.status(), `triage PUT failed: ${await triage.text()}`).toBe(200)

  // The carried-forward statement's updated_at must strictly predate the second version's own
  // created_at, and both columns are stamped through UtcTimestamp.ToUtcIso() at SECOND
  // precision (Format = "yyyy-MM-ddTHH:mm:ssZ") — not millisecond, as a first pass at this wait
  // assumed, which is what made it flaky: a few hundred ms is nowhere near enough to guarantee
  // landing in a different whole second, so the two timestamps tied on an unlucky run and
  // IsInherited's strict "<" read false. Any fixed wait longer than 1000ms guarantees crossing a
  // second boundary regardless of where in the current second the triage PUT landed; 1200ms
  // leaves clock-granularity/CI-jitter headroom on top of that guarantee.
  await new Promise(resolve => setTimeout(resolve, 1200))

  const second = await seedProjectVersion(authed, label, { projectName, versionLabel: '2.0.0' })

  return { first, second }
}
