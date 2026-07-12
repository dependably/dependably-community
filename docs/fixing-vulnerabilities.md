# Fixing a vulnerability with dependably

This is the developer walkthrough for going from "the Vulnerabilities page says my package is
affected" to a merged fix — including the OWASP context behind each advisory and the curated
remediation skills you can hand to an AI coding assistant.

## Reading the report

**Vulnerabilities** (in the sidebar) lists every affected version in your org, across both
uploaded packages and proxy-cached artifacts. Columns worth understanding:

- **Severity** — the advisory's CVSS band (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`). An advisory with
  no CVSS classification shows no band and never meets an alert threshold; treat it as
  *unscored*, not as safe.
- **Score** — the CVSS 3.x base score, taken from the advisory or computed from its vector.
- **EPSS** — FIRST.org's Exploit Prediction Scoring System: the probability the vulnerability
  is exploited in the wild within the next 30 days, shown as a percentage. Refreshed daily by
  the threat-feed job. Use it to rank *which* HIGH you fix first.
- **KEV** badge — an advisory alias is in the
  [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  confirmed exploited, independent of CVSS score. Fix these first regardless of severity band.
- **MALICIOUS** — an OSV `MAL-` report. This is a verdict, not a score: remove the package;
  there is no "fixed version" to upgrade to.
- **revoked** — the version disappeared from the upstream registry. A lifecycle signal, not a
  vulnerability; a takedown can indicate a compromised release.

Click a row to expand the advisory detail: summary, aliases (linked to their home databases —
GHSA to the GitHub Advisory Database, CVE to NVD), references, affected ranges, and the
remediation section.

## The remediation section

- **Fixed in** — the version to upgrade to. When you expanded a row, dependably resolves the
  fix of the affected range *containing your installed version* under the ecosystem's native
  version ordering (npm semver, PEP 440, NuGet, Maven). For other ecosystems it falls back to
  the first `fixed` event in the advisory.
- **CWE chips** — the weakness classes the advisory carries (linked to cwe.mitre.org), each
  mapped to its [OWASP Top 10:2025](https://owasp.org/Top10/2025/) category. The OWASP page is
  the background reading: what the vulnerability class is, how it is exploited, and how to
  prevent it structurally.
- **Fix with your AI agent** — curated remediation skills, served by this instance.

## The curated skills

A skill is a markdown playbook an AI coding assistant follows. dependably ships six, chosen by
what the advisory carries:

| Skill | Applies when |
| --- | --- |
| `fix-vulnerable-dependency` | Any advisory with a fixed version — the lockfile-aware upgrade recipe (direct + transitive), per ecosystem |
| `fix-injection` | Injection-class CWEs (SQL/command/code injection, input validation) |
| `fix-xss` | Cross-site-scripting CWEs |
| `fix-path-traversal` | Path traversal / link-following CWEs |
| `fix-ssrf` | Server-side request forgery CWEs |
| `fix-unsafe-deserialization` | Untrusted deserialization / mass assignment CWEs |

The skill markdown is assistant-neutral. Pick your assistant in the remediation section and the
install command and prompt adapt:

| Assistant | Installs to | Invoked |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/<id>/SKILL.md` | discovered by name |
| OpenAI Codex | `~/.codex/prompts/<id>.md` | `/<id>` |
| GitHub Copilot | `.github/prompts/<id>.prompt.md` (in your repo) | `/<id>` |

The **Install skill** one-liner fetches from `GET /api/v1/remediation/skills/{id}` — the
endpoint is anonymous and tenant-agnostic, so it works from any shell with no token. The
**Prompt** is pre-filled with the advisory id, the affected purl, your installed version, and
the resolved fixed version — paste it into the assistant after installing.

No assistant? The skills are plain markdown — open the same URL and follow the recipe by hand.

## Scripting it

Both read surfaces accept a personal access token carrying `read:packages`:

- `GET /api/v1/vuln-report` — the affected-versions report (filter with `ecosystem`/`name`,
  sort with `sort=severity|score|epss|kev|published|…`).
- `GET /api/v1/vulnerabilities/{osvId}?version=<installed>` — full advisory detail including
  `remediation` (CWE/OWASP entries, applicable skills, `fixedVersion`) and `threatIntel`
  (`isKev`, `epssScore`).

The interactive spec is served at `/api/v1/docs/`.
