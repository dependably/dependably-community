import { test, expect } from '@playwright/test'
import { loginAsAdmin } from '../../helpers/api-client.js'
import { readSbomFixture, seedProjectVersion, sha256, SbomFixtureName } from '../../helpers/sbom-seed.js'

/**
 * `GET /api/v1/sbom-documents/{id}/original` is the receipts endpoint: it hands back the exact
 * bytes an uploader sent, digest and all, as opposed to the export endpoints which re-render a
 * fresh document from the database. "Exact" is the whole contract, so it is asserted on the
 * sha256 of the response body against the sha256 of the file on disk — a re-serialization that
 * only reorders keys or reflows whitespace would still parse as the same document and would still
 * pass any structural assertion, while breaking every signature and attestation over those bytes.
 *
 * Each doc type is checked, because the three take different ingest paths (component merge, VEX
 * statement binding, SARIF result binding) and each stages its own blob.
 */

const UPLOADED: Array<{ docType: 'sbom' | 'vex' | 'sarif'; fixture: SbomFixtureName }> = [
  { docType: 'sbom', fixture: 'cyclonedx-1.6-inventory.json' },
  { docType: 'vex', fixture: 'cyclonedx-1.6-vex.json' },
  { docType: 'sarif', fixture: 'sarif-2.1.0-sbom-reach.json' },
]

test.describe('API: SBOM original-document download', () => {
  test('every uploaded document downloads back byte-identical', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const seeded = await seedProjectVersion(authed, 'documents')

      // The version's document list is what the page's Documents card reads; the digest it
      // reports has to be the digest of the bytes that arrived, not of anything re-rendered.
      const listRes = await authed.get(
        `/api/v1/projects/${seeded.projectId}/versions/${seeded.versionId}/documents`)
      expect(listRes.status(), await listRes.text()).toBe(200)
      const documents: Array<Record<string, string>> = (await listRes.json()).items
      expect(documents.length).toBe(3)

      for (const { docType, fixture } of UPLOADED) {
        const uploaded = readSbomFixture(fixture)
        const expectedSha = sha256(uploaded)

        const listed = documents.find(d => d.docType === docType)
        expect(listed, `no ${docType} document in the version's document list`).toBeTruthy()
        expect(listed!.sha256, `${docType} listed digest`).toBe(expectedSha)
        expect(listed!.id).toBe(seeded.documentIds[docType])

        const res = await authed.get(`/api/v1/sbom-documents/${listed!.id}/original`)
        expect(res.status(), `${docType} download: ${await res.text()}`).toBe(200)
        const served = await res.body()
        expect(sha256(served), `${docType} served digest`).toBe(expectedSha)
        expect(served.equals(uploaded), `${docType} served bytes`).toBe(true)

        // The ETag is the full 64-char digest of those same bytes, and a conditional re-request
        // on it is a 304 rather than a second copy of the document.
        expect(res.headers()['etag']).toBe(`"${expectedSha}"`)
        const conditional = await authed.get(
          `/api/v1/sbom-documents/${listed!.id}/original`,
          { headers: { 'If-None-Match': `"${expectedSha}"` } })
        expect(conditional.status(), `${docType} conditional GET`).toBe(304)
      }

      // The adversarial twin: a well-formed id nobody uploaded is a 404, so the three passes
      // above are the endpoint resolving real rows rather than serving whatever it is handed.
      const bogus = await authed.get('/api/v1/sbom-documents/00000000000000000000000000000000/original')
      expect(bogus.status()).toBe(404)
    } finally {
      await authed.dispose()
    }
  })
})
