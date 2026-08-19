# Diagnosing a blocked package

A package manager reports `403 Forbidden` and a build fails. This page tells you whether your own
policy did it, which policy, and what to do next.

## Is it policy, or is it auth?

Check the response header:

```console
$ curl -sS -o /dev/null -D - -u user:$TOKEN \
    https://registry.example.com/packages/idna-3.19-py3-none-any.whl
HTTP/1.1 403 Forbidden
X-Dependably-Block-Reason: release_age
```

`X-Dependably-Block-Reason` is present **only** when a block-gate arm refused the request. A 403
without it is not a policy decision — it is an authentication or authorization failure, and the
remedy is a token, not a setting.

The header names the arm and nothing else. Your configured thresholds and the advisory IDs behind
them stay out of the response, because an error body travels further than the request did — into CI
logs, screenshots and support tickets.

## What each reason means

| Reason | What happened | What to do |
|---|---|---|
| `release_age` | The version is newer than the org's `min_release_age_hours` cooldown. | Wait — the hold expires on its own. Or pin an older version. |
| `manual` | An operator blocked this version by hand. | Ask why; unblock from **Packages → the version → Manual block** if it was wrong. |
| `deprecated` | Upstream marked the version deprecated or yanked. | Move to a supported version. |
| `revoked` | Upstream withdrew the version entirely. | Move off it. It is not coming back. |
| `malicious` | An OSV `MAL-` advisory names this version. | Do not bypass. Treat any machine that already installed it as suspect. |
| `kev` | A CISA Known Exploited Vulnerability affects it. | Upgrade. This is being exploited in the wild. |
| `epss` | Its exploit-likelihood score exceeds the org's tolerance. | Upgrade, or raise the tolerance deliberately. |
| `vuln_score` | Its CVSS score exceeds `max_osv_score_tolerance`. | Upgrade, or raise the tolerance deliberately. |
| `provenance` | Signature or attestation verification did not produce a `verified` result. | Check the trust anchors under **Settings → Trust Anchors**. |
| `install_script` | The package ships install or lifecycle scripts, which the org blocks. | Add it to the install-script allowlist if it is known-good. |
| `license` | Its license is outside the org's allowlist. | Use a differently-licensed package, or amend the policy. |

## Why the version was offered at all

It should not have been. A registry must never advertise a version its download path will refuse,
and every listing surface filters against the same gate the download uses.

Two cases are genuine exceptions rather than bugs, and both come down to what a listing can know:

- **A version nobody has fetched yet.** Only the arms decidable from upstream metadata apply —
  release-age where the upstream publishes a timestamp, and deprecation where it publishes a marker.
  The vulnerability, provenance, install-script and licence arms need the artifact itself, so they
  are enforced on the first fetch instead. A build can therefore meet one of those reasons on a
  coordinate the index listed.
- **Alpine `apk`.** Its index is upstream bytes the client itself signature-verifies, so rewriting
  it would invalidate that signature. `apk` is gated at download only.

If you meet a *different* reason on a version the index advertised, that is a bug worth reporting —
it means a listing surface and its download path disagree.

## Finding it after the fact

Every refusal writes an activity row. **Activity** in the dashboard, filtered by event type
`blocked`, shows every arm's refusals with the package, the actor, and the source IP.

An automatic block also opens a **quarantine review** entry, so a refusal you disagree with has a
place to be approved rather than needing the policy turned off. Release-age holds age out of that
queue on their own.

## Making a hold less surprising

If developers hit `release_age` often, the cooldown is doing its job but arriving too late to be
useful. Two things help more than lowering it:

- Pin dependencies. A pinned build resolves to a version that is already past the window.
- Watch the quarantine queue rather than waiting for a failed build to surface the hold.
