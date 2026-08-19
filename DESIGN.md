# Dependably — Design Reference

## Contents

- [0. Principles](#0-principles)
- [1. Brand mark](#1-brand-mark)
- [2. Color tokens](#2-color-tokens)
- [3. Typography](#3-typography)
- [4. Layout](#4-layout)
- [5. Components](#5-components)
- [6. Iconography](#6-iconography)
- [7. Voice & copy](#7-voice--copy)
- [8. Accessibility](#8-accessibility)
- [9. Dark mode](#9-dark-mode)
- [10. Conventions](#10-conventions)
- [11. Time & timezone](#11-time--timezone)
- [12. Don'ts](#12-donts)

---

## 0. Principles

1. **Quiet, not loud.** Security UI earns trust by feeling considered.
   No decoration, no gradients, no illustrations.
2. **Receipts everywhere.** Every "verified", "signed", "policy passed"
   claim links to a viewable artifact one click away.
3. **Monospace is a primary typeface.** Package names, versions, hashes,
   PURLs, tokens — treat them like code.
4. **Density beats whitespace.** Default to compact, information-dense
   surfaces. Reserve generous whitespace for marketing/onboarding.
5. **One accent.** Teal is the only chromatic UI color. Used for:
   verified state, primary action, links, focus rings. Nothing else.

---

## 1. Brand mark

The Dependably mark is a verified hub linked to three satellite nodes —
literal dependency graph, trusted center.

- Master files (committed): `web/public/favicon.svg`, plus
  `brand/dependably-mark.svg` (and `brand/dependably-mark-mono.svg`,
  `brand/dependably-mark-inverse.svg`, `brand/dependably-lockup.svg`) —
  see `brand/README.md`
- Construction: 64-unit viewBox · 4-unit edge stroke · 9-unit hub
  radius · 5-unit satellite radius · 2.5-unit hub-check stroke
- Variants: duo (default), `currentColor` mono, inverse for dark surfaces
- Lockup: mark + Inter 700 wordmark, gap = `0.36 × markSize`
- Clear space: ≥ `0.25 × markSize` margin
- Minimum size: 14px (favicon/tab); below that the hub check disappears
- **Brand text in navbar:** still allowed (`.brand-text`), but pair with
  the mark via a small inline SVG to its left (16–18px). No text-only
  mark anymore.

---

## 2. Color tokens

All colors live as CSS custom properties in `web/src/app.css`. **Never
hardcode hex values in components — always use variables.**

### 2.1 Surface + text + accent

| Token             | Light                                                        | Dark                                                         | Usage                                                                                 |
| ----------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `--bg`            | `#ffffff`                                                    | `#0f0f0f`                                                    | Page background                                                                       |
| `--bg2`           | `#f5f5f5`                                                    | `#1a1a1a`                                                    | Navbar, cards, table headers                                                          |
| `--bg3`           | `#e8e8e8`                                                    | `#2a2a2a`                                                    | Hover states, code/token blocks                                                       |
| `--surface2`      | same as `--bg3` (`#e8e8e8`)                                  | `#222222` (between `--bg2` and `--bg3`)                      | Recessed panels, expanded-row drawers — use instead of `--bg2` for nested surfaces   |
| `--border`        | `#d0d0d0`                                                    | `#3a3a3a`                                                    | All borders                                                                           |
| `--text`          | `#1a1a1a`                                                    | `#f0f0f0`                                                    | Primary text                                                                          |
| `--text2`         | `#555555`                                                    | `#a0a0a0`                                                    | Labels, secondary text, inactive nav                                                  |
| `--accent`        | `oklch(0.55 0.10 165)` ≈ `#1f6f5c`                          | `oklch(0.72 0.10 165)` ≈ `#3aa88f`                          | Links, active states, focus rings, primary buttons                                    |
| `--accent-hover`  | `oklch(0.48 0.10 165)` ≈ `#175747`                          | `oklch(0.62 0.10 165)` ≈ `#2a8a73`                          | Primary button hover                                                                  |
| `--accent-soft`   | `oklch(0.94 0.03 165)` ≈ `#dff0ea`                          | `oklch(0.22 0.04 165)` ≈ `#0e2620`                          | Verified-state surface (chips, banners)                                               |
| `--danger`        | `#dc2626`                                                    | (same)                                                       | Danger buttons, error text, signature mismatch                                        |
| `--danger-soft`   | `color-mix(in oklch, var(--danger) 8%, var(--bg2))`          | (same pattern)                                               | Alert/hot card backgrounds — always mix from the token, never from a raw hex literal  |
| `--warning`       | `#d97706`                                                    | (same)                                                       | Warning indicators, pending state                                                     |
| `--warning-soft`  | `color-mix(in oklch, var(--warning) 8%, var(--bg2))`         | (same pattern)                                               | Warning surfaces                                                                      |
| `--success`       | `#16a34a`                                                    | (same)                                                       | Passing-build state distinct from verified (rare — prefer `--accent` for trust signals) |
| `--success-soft`  | `color-mix(in oklch, var(--success) 8%, var(--bg2))`         | (same pattern)                                               | Success surfaces                                                                      |
| `--radius`        | `6px`                                                        | —                                                            | All `border-radius`                                                                   |
| `--shadow`        | `0 1px 3px rgba(0,0,0,0.1)`                                  | —                                                            | Elevated surfaces only — dropdowns, popovers. **Not on `.card`** (border is enough)   |
| `--error-bg`      | `#fee2e2`                                                    | `#3b0c0c`                                                    | Inline form errors                                                                    |

### Severity palette

Used exclusively by `.sev` chips (§5.5) and the dashboard vuln table.
All light/dark pairs pass WCAG AA 4.5:1. **Never define severity colors
per-component — use these tokens and `.sev`.**

**Hybrid model:** `critical` and `high` are loud (solid bg, inverse
text) — the eye-magnet exception to "Quiet, not loud" that the highest-
risk rows need. `medium` and `low` stay soft (tinted bg, dark text) to
keep dense scan tables readable.

| Token                 | Light      | Dark      |
| --------------------- | ---------- | --------- |
| `--sev-critical-bg`   | `#7c3aed`  | `#2e1065` |
| `--sev-critical-text` | `#ffffff`  | `#e9d5ff` |
| `--sev-high-bg`       | `#dc2626`  | `#450a0a` |
| `--sev-high-text`     | `#ffffff`  | `#fecaca` |
| `--sev-medium-bg`     | `#fef3c7`  | `#451a03` |
| `--sev-medium-text`   | `#92400e`  | `#fde68a` |
| `--sev-low-bg`        | `#e0f2fe`  | `#082f49` |
| `--sev-low-text`      | `#075985`  | `#bae6fd` |

### Ecosystem chart tokens

The donut chart must use these tokens so chart segments and legend swatches
always agree. Eco colors are optimized for chart readability (distinct, vivid)
and are independent of the badge palette.

| Token         | Value     | Usage                         |
| ------------- | --------- | ----------------------------- |
| `--eco-pypi`  | `#3b82f6` | Donut segment + legend swatch |
| `--eco-npm`   | `#f59e0b` | Donut segment + legend swatch |
| `--eco-nuget` | `#8b5cf6` | Donut segment + legend swatch |
| `--eco-maven` | `#ef4444` | Donut segment + legend swatch |
| `--eco-rpm`   | `#14b8a6` | Donut segment + legend swatch |
| `--eco-oci`   | `#0ea5e9` | Donut segment + legend swatch |

### 2.2 Badge palettes

Eight ecosystem/status palettes provide semantic color for npm, PyPI,
NuGet, hosted, and status states. Keep `--badge-*-bg` / `--badge-*-text`
pairs, both modes.

The **`vuln-scan`** badge variant is used by the Activity feed to surface
"scan completed" events. It follows the same `--badge-*-bg` /
`--badge-*-text` pattern; treat it as a status badge, not a severity
badge (use `.sev` for severity).

### 2.3 Rules

- Define accent colors in `oklch()` first; the hex is a fallback
  comment.
- **Never** add a second hue. State variation goes through the existing
  badge palettes (semantic) or lightness/chroma on accent.
- No gradients in product chrome.
- Body text on `--bg` is `--text`. `--text2` is for metadata, labels,
  secondary lines only.
- **Enforcement:** `stylelint color-no-hex` runs on `web/src/**/*.svelte`
  with a single allowlist entry (`app.css`). New hex literals in
  components fail CI.

---

## 3. Typography

### 3.1 Families

- **Sans:** `Inter` — UI, headings, body, wordmark, navbar
- **Mono:** `JetBrains Mono` — package names, versions, hashes, PURLs,
  tokens, `.copy-block`, eyebrow labels, table cells with version data

System fallbacks: `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`
for sans; `'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace` for mono.

Add to `index.html`:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
```

Do **not** introduce a third family.

### 3.2 Scale

| Role           | Size / weight / use                                                    |
| -------------- | ---------------------------------------------------------------------- |
| `.page-title`  | 20 / 700 — page H1                                                     |
| Modal title    | 16 / 700                                                               |
| `.stat-value`  | 28 / 700 — KPI number on stat/alert cards; line-height 1.1; tabular-nums |
| Body           | 14 / 400 — `--text`, base                                              |
| Secondary      | 13 / 400 — `--text2`, table cells, nav links                           |
| Form label     | 13 / 500 — `--text2`                                                   |
| Hint           | 12 / 400 — `.form-hint`                                                |
| Badge          | 11 / 600                                                               |
| Eyebrow        | 11 / 500 / +0.12em / UPPERCASE — mono, `--text2`, section headers in dense forms |

Tabular numerals (`font-variant-numeric: tabular-nums`) apply to every
table column with versions, counts, durations, or timestamps.

### 3.3 Rules

- Inter feature settings: `"cv11", "ss01"` for cleaner numerals.
- `text-wrap: balance` on `.page-title` and h2; `text-wrap: pretty` on
  long-form body copy.
- Never use Inter italic in UI.
- Inline code in prose: `<code>` with mono, 0.92em, 1px `--bg2`
  background, 1px `--border`, 4px radius.

---

## 4. Layout

```
┌─────────────────────────────────────────────┐
│ .navbar (sticky, 48px, --bg2)               │
├─────────────────────────────────────────────┤
│ .main-content                               │
│   .page (full-bleed, padding: 24px)         │
│     .page-header (flex, space-between)      │
│       .page-title          [action buttons] │
│     [content]                               │
└─────────────────────────────────────────────┘
```

Forms width-constrained ≤ 480px. Full-width tables live directly inside
`.page`.

**Page width** — there is exactly one page wrapper, `.page`, and it is
full-bleed and left-aligned. It sets the 24px gutter and nothing else: no
`max-width`, no `margin: 0 auto`. Every page therefore starts at the same
x-offset, so moving between a form page and a data-table page does not shift
the content edge.

**Readable measure is capped on the inner element, never on the shell.** A page
whose content would be unreadable at full width constrains the specific element
that needs it — a form, a prose block, a dropzone — with a plain `max-width` and
no auto margins, which keeps it left-aligned inside the page. `OrgSettings` is
the reference: a full-bleed `.page` with 480/540/640px caps on the forms inside
it. A scoped `.page { max-width: … }` override in a page's own `<style>` block
re-introduces the centred well and is the one thing this rule forbids.

**The wrapper belongs once, at the route root.** A component that is embedded as
a sub-section of another page — e.g. a settings-tab panel — renders bare
(heading via `.section-h`, tables directly); it must not re-wrap itself in
`.page`, or the gutters stack and the section is inset from its siblings.
Separate stacked sub-sections with `margin-top: 24px`, not nested wrappers.

### 4.1 Navbar contract

The navbar has four zones, left → right:

| Zone            | Element                    | Notes                                                        |
| --------------- | -------------------------- | ------------------------------------------------------------ |
| `.nav-brand`    | Mark + wordmark button     | Links to dashboard                                           |
| `.nav-org`      | `<select>` org switcher    | Only rendered when ≥ 1 org is accessible to the user         |
| `.nav-links`    | Primary nav (`flex: 1`)    | Overview · Packages · Vulnerabilities · Activity · Settings  |
| `.nav-actions`  | Locale · theme · sign-out  | Right-aligned; instance-admin link lives here, not `.nav-links` |

Active state: `.nav-link.active { color: var(--accent); background: var(--bg); }`

Instance-admin links go in `.nav-actions` (not `.nav-links`) so
org-scoped and instance-scoped navigation are visually distinct clusters.

---

## 5. Components

All global classes live in `web/src/app.css`. Use them as-is; do not
redefine them in component `<style>` blocks.

| Section | Class(es)                                                  | Purpose                                         | Used in                         |
| ------- | ---------------------------------------------------------- | ----------------------------------------------- | ------------------------------- |
| §5.1    | `.brand`, `.brand-text`                                    | Mark + wordmark lockup                          | App.svelte navbar               |
| §5.2    | `.eyebrow`                                                 | Uppercase mono caption                          | Auth pages, dashboard, tables   |
| §5.3    | `.badge.verified`, `.badge.signed`                         | Trust signal chips                              | VersionDetail, receipts panel   |
| §5.4    | `.login-card`                                              | Auth page card                                  | Login.svelte                    |
| §5.5    | `.sev`, `.sev-critical/high/medium/low`                    | Vulnerability severity chip                     | Packages, VersionDetail, Dashboard |
| §5.6    | `.stat-card`, `.alert-card`, `.stat-grid`, `.stat-value`   | Dashboard KPI and alert surfaces                | Dashboard.svelte                |
| §5.6    | `.alert-card.hot`, `.alert-card.warn`                      | Danger / warning alert card variants            | Dashboard.svelte                |
| §5.6    | `.title-row`, `.ribbon`, `.ribbon.hot`                     | Page-title row with inline status ribbon        | Dashboard.svelte                |
| §5.6    | `.eco-name-cell`, `.eco-bar.{eco}`                         | Ecosystem table name cell (donut legend proxy)  | Dashboard.svelte                |
| §5.7    | `.detail-panel`, `.detail-section`, `.detail-label`, `.detail-value` | Expanded-row receipts drawer      | VersionDetail.svelte            |
| §5.8    | `DataTable` + `th.sortable`, `.page-toolbar` filters, `Pagination`     | Data table: sortable headers, toolbar filters, paging | All list pages |
| —       | `.card`                                                    | Generic surface card                            | Multiple                        |
| —       | `.badge` + ecosystem modifiers                             | Ecosystem and status labels                     | Multiple                        |
| —       | `.badge.state-{unclaimed,local_only,mixed}`                | Claims state badges                             | Claims.svelte, VersionDetail.svelte |
| —       | `.badge.state-{approved,denied}`                           | Quarantine decision badges                      | Quarantine.svelte               |
| —       | `.badge.mode-{off,warn,block}`                             | License policy mode pills                       | LicensePolicy.svelte            |
| —       | `.badge.{osi,fsf,dep,cl-*}`                                | License attribute badges                        | LicensePolicy.svelte            |
| —       | `.badge.outcome-{accepted,rejected,would_accept,would_reject}` | Upload outcome badges                       | Upload.svelte                   |
| —       | `.badge.has-icon`                                          | Badge with inline icon gap                      | VersionDetail.svelte            |
| —       | `.modal.scrollable`                                        | Scrollable modal variant                        | Claims.svelte, Upload.svelte    |
| —       | `.modal-flex`                                              | Width + flex-column modal body layout           | Claims.svelte, Upload.svelte    |
| —       | `.warning-card`, `.info-card`                              | Inline tinted note cards inside modal bodies    | Claims.svelte, Upload.svelte    |
| —       | `.list-header`                                             | Section sub-header above per-section lists      | Settings panels, OrgSettings    |
| —       | `.page-toolbar`                                            | Search + filter row above tables                | All list pages                  |
| —       | `.tabs` / `.tab`                                           | Tab navigation                                  | Multiple                        |
| —       | `.form-row` / `.form-hint`                                 | Form layout                                     | Multiple                        |
| —       | `button`, `button.primary`, `button.danger`                | Actions                                         | Multiple                        |
| —       | `input` / `select` / `textarea`                            | Form inputs                                     | Multiple                        |
| —       | `table` / `th` / `td`                                      | Data tables                                     | Multiple                        |
| —       | `.copy-block`, `.copy-btn`                                 | Copyable code/hash blocks                       | Multiple                        |
| —       | `.modal`, `.modal-backdrop`, `.modal-actions`              | Modal dialogs                                   | Multiple                        |
| —       | `.spinner`                                                 | Loading state (mid-flight actions, modal submit)| Multiple                        |
| —       | `.skeleton`                                                | Shimmer placeholder for initial table fetch     | Tables (Packages, VersionDetail, Vulnerabilities) |
| `Skeleton.svelte` | —                                                | Reserves the loaded box for a card, panel, header, or stat tile | Multiple |
| —       | `.nav-progress`                                            | Navigation held past its grace period           | App.svelte, SystemApp.svelte    |
| —       | `.error-msg`                                               | Inline form-field validation error              | Forms                           |
| —       | `.page-error`                                              | Top-of-page fetch failure banner                | All data pages                  |
| —       | `.page-header`, `.page-title`                              | Page chrome                                     | All pages                       |
| —       | `.first-fetch-row`                                         | Amber highlight for first-seen packages         | Packages.svelte                 |
| —       | `.expanded-row`                                            | Table row expanded state                        | VersionDetail.svelte            |
| —       | `.btn-row`                                                 | Compact in-row action button (28–32px tall)     | VersionDetail.svelte            |

**`.skeleton`** — shimmer placeholder for table rows / single text
lines during the initial fetch. Do not mix with `.spinner` on the same
view. `.spinner` stays for mid-flight actions like modal submit and
inline retry.

A placeholder is for a wait the reader can feel, not for every wait.
Most navigations resolve in well under the time a loading state takes to
read as one, and a shimmer that appears and vanishes inside a few frames
is a flicker, not information. Two rules keep them off screen:

- **Navigation commits late.** `navigate()` does not swap the page on
  click. The incoming page mounts in a detached container, runs its
  initial fetch, and `route` flips only once that page reports its data
  has landed — `reportPageLoad(pageToken, loading)`, with the token
  arriving as a `RouteView` slot prop — or once the 400 ms budget
  expires. Until then the loaded page the reader is already looking at
  stays on screen and the URL still names it, so the two never
  disagree; the clicked sidebar link lights up immediately
  (`activeRoute`), which is what makes the hold read as responsive.
  Past 150 ms the `.nav-progress` strip turns on; past the budget the
  swap happens and the arriving page shows its own placeholders,
  because by then the wait is real. Redirects (`{ replace: true }` —
  the initial landing, guard bounces, post-logout) commit immediately:
  there is no loaded page worth holding. See `RouteView`, `RouteHost`,
  and the deferred-commit block in `store.js`.
- **A table that already has rows keeps them.** `DataTable` and
  `VersionTable` draw placeholders only when they have nothing to show,
  so paging, sorting, and filtering leave the current rows up while the
  next set is in flight.

When a placeholder *is* drawn it reserves the box its real content will
occupy, so the page does not collapse and then re-expand when the data
lands: a body that shrinks below one viewport also retracts the document
scrollbar, which shifts the whole layout sideways. The reserve comes from
what that table actually held last time (`memoryKey` on `DataTable`,
recorded per session by `tableSize.js`) — a page size is a guess that
overstates every table holding fewer rows than its limit, and fifty
placeholder rows collapsing to four moves more than reserving nothing
would have. `loadingRows` is the first-visit estimate until a real count
is known, `loadingRowHeight` matches rows that stack two lines, and the
count is capped at a viewport's worth: rows arriving below the fold grow
the document without moving anything the reader can see. A loading page
renders its real chrome — header, toolbar, tabs, pagination — and swaps
only the values it is waiting on.

**`.page-error`** — full-width banner used at the top of a page when a
fetch fails. Distinct from `.error-msg`, which is reserved for inline
form-field validation: form errors live next to the offending input;
page errors block the whole view.

### 5.1 `.brand`

Replaces text-only navbar brand. Renders the mark + wordmark inline:

```html
<div class="brand">
  <svg viewBox="0 0 64 64" width="18" height="18" aria-hidden="true">
    <path d="M32 32L14 14M32 32L50 14M32 32L32 54"
          stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
    <circle cx="14" cy="14" r="5" fill="currentColor"/>
    <circle cx="50" cy="14" r="5" fill="currentColor"/>
    <circle cx="32" cy="54" r="5" fill="currentColor"/>
    <circle cx="32" cy="32" r="9" fill="var(--accent)"/>
  </svg>
  <span class="brand-text">Dependably</span>
</div>
```

```css
.brand { display: inline-flex; align-items: center; gap: 8px; color: var(--text); }
.brand-text { font-weight: 700; font-size: 16px; letter-spacing: -0.01em; }
```

### 5.2 `.eyebrow`

Mono caption used above section headings, stat-card labels, alert-card
labels, table-eyebrow rows, and auth pages.

```css
.eyebrow {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 11px; font-weight: 500; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--text2);
}
```

Use `.eyebrow` for **every** uppercase mono caption in the product. Do
not redefine this recipe in component `<style>` blocks (as `.section-title`,
`.stat-label`, `.alert-label`, etc.) — those are duplicates that belong on
this class.

### 5.3 `.badge.verified` / `.badge.signed`

Add to the badge palette. Use for "signature verified", "SLSA L3",
"provenance attached" — any positive trust signal.

```css
.badge.verified, .badge.signed {
  background: var(--accent-soft);
  color: var(--accent);
}
```

Version rows should lead with trust state, not the version string:

```
[verified ✓] 1.4.2 · sha256 a1f9c4d · 12m ago
```

Each `.badge.verified` / `.badge.signed` chip is a link to its receipt
(signature page, SBOM, policy result), not just a label.

### 5.4 Login card (`.login-card`)

The existing `Login.svelte` card stays — only typography and the brand
mark above the heading change. Add the mark + eyebrow above `<h1>`:

```svelte
<div class="login-card card">
  <div class="login-brand">
    <svg ...><!-- mark, 32px --></svg>
  </div>
  <h1 class="login-title">{$t('auth.login.title')}</h1>
  ...
</div>
```

```css
.login-brand  { display: flex; justify-content: center; margin-bottom: 18px; }
.login-title  { text-align: center; }
```

Do not use inline `style` attributes on login-card elements — apply
layout via the classes above.

### 5.5 `.sev` — Severity chip

The only severity-color surface in the product. Use for vuln counts,
scan results, and advisory chips. **Always carry an `aria-label`**
(e.g. `aria-label="3 critical vulnerabilities"`) — color alone is not
sufficient. Do not introduce per-page or per-component severity classes.

```css
.sev {
  display: inline-block;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 11px; font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
}
.sev-critical { background: var(--sev-critical-bg); color: var(--sev-critical-text); }
.sev-high     { background: var(--sev-high-bg);     color: var(--sev-high-text); }
.sev-medium   { background: var(--sev-medium-bg);   color: var(--sev-medium-text); }
.sev-low      { background: var(--sev-low-bg);      color: var(--sev-low-text); }
```

### 5.6 Stat card & alert card

Used by Dashboard for KPI metrics and active-alert surfaces. Reusable
across Activity, Vulnerabilities, OrgSettings wherever summary counts
are needed.

```css
.stat-card, .alert-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
  display: flex; flex-direction: column; gap: 4px;
}
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 12px;
}
.stat-value        { font-size: 28px; font-weight: 700; line-height: 1.1; }
.stat-value.warn   { color: var(--warning); }
.stat-value.danger { color: var(--danger); }

/* Hot variant — use when the stat requires immediate attention */
.alert-card.hot {
  border-color: var(--danger);
  background: var(--danger-soft);
}
.alert-card.hot .stat-value { color: var(--danger); }
```

Label above the value: `.eyebrow`.

### 5.6b Status ribbon (`.ribbon`)

An inline pill placed in `.title-row` (flex row alongside `<h1>`) to
surface live status without a dedicated section. Currently used on the
Dashboard page for new-vulnerability counts.

```css
/* Container — replaces .page-header when a ribbon is present */
.title-row { display: flex; align-items: center; gap: 14px; margin-bottom: 18px; }

.ribbon {
  display: inline-flex; align-items: center; gap: 10px;
  padding: 6px 12px 6px 10px; border-radius: 99px; font-size: 12px;
  background: var(--bg2); border: 1px solid var(--border); color: var(--text2);
}
/* Hot variant — shown when the stat requires immediate attention */
.ribbon.hot {
  background: var(--danger-soft);
  border-color: color-mix(in srgb, var(--danger) 25%, var(--border));
  color: var(--danger);
}
.ribbon .dot    { width: 8px; height: 8px; border-radius: 99px; background: var(--text2); }
.ribbon.hot .dot { background: var(--danger);
  box-shadow: 0 0 0 4px color-mix(in srgb, var(--danger) 20%, transparent); }
.ribbon .label  { font-weight: 600; }
.ribbon .splits { display: flex; gap: 10px; padding-left: 8px;
  border-left: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
.ribbon .split  { font-family: var(--mono); font-size: 11px; letter-spacing: 0.04em; }
.ribbon .split b { font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 700; margin-right: 2px; }
```

### 5.6c Ecosystem table as donut legend (`.eco-bar`)

The donut chart has no standalone legend. The ecosystem table doubles as
the legend: each row's name cell leads with a 6 px vertical bar in the
same `--eco-{eco}` color the donut slice uses.

```css
.eco-name-cell { display: flex; align-items: center; gap: 10px; }
.eco-bar       { width: 6px; align-self: stretch; min-height: 18px; border-radius: 3px; flex-shrink: 0; }
.eco-bar.pypi  { background: var(--eco-pypi); }
.eco-bar.npm   { background: var(--eco-npm); }
.eco-bar.nuget { background: var(--eco-nuget); }
.eco-bar.maven { background: var(--eco-maven); }
.eco-bar.rpm   { background: var(--eco-rpm); }
.eco-bar.oci   { background: var(--eco-oci); }
```

**When adding a new ecosystem** (Cargo, etc.), three things must
be updated in lockstep: `--eco-{name}` token in all three theme blocks,
`.badge.{name}` background/color rule, and `.eco-bar.{name}` background
rule.

### 5.7 Receipts panel (`.detail-panel`)

The expanded-row drawer in the version table is the primary "receipts"
surface — where principle 2 is delivered. It must contain, in order:

1. PURL (copyable, mono)
2. SHA-256 checksum (copyable, mono)
3. Vulnerability summary (`.sev` chips if present)
4. SBOM link
5. Signature artifact link
6. Policy result

Surface spec:
- Background: `var(--surface2)`
- Top border: `1px solid var(--border)`
- Bottom border: `2px solid var(--accent)`

Label / value layout:

```css
.detail-section { margin-bottom: 10px; }
.detail-label   {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.05em;
  color: var(--text2); min-width: 90px;
}
.detail-value   { font-family: 'JetBrains Mono', ui-monospace, monospace; }
```

Every `detail-value` with copyable content carries an inline `.copy-btn`.

### 5.8 Data tables

All data tables use `table-layout: fixed`. This prevents column widths from shifting when sort indicators appear and avoids content-driven layout thrash.

**Build every list table out of `DataTable.svelte`.** It owns the sort state, the header row, the `<colgroup>`, the loading placeholders, and the empty row; the page supplies `columns` and one `<tr>` per row through the default slot. A page that hand-rolls `<thead>` re-implements all five and drifts from the rest of the site — that is how a table ends up unsortable. Two shapes are exempt, and only these two:

- a table that groups several source rows into one visible row (`VersionTable.svelte` — Maven jar/pom, PyPI wheel/sdist), which the one-slot-per-array-element contract cannot express. Copy `VersionTable`'s use of the shared `sortIndicator`/`tableSize` helpers rather than inventing new ones.
- a fixed-row table where sort is meaningless (see **Skip list** below).

**Every list table is sortable, filterable, and paged the same way**

| Concern | Where it lives | Never |
|---|---|---|
| Sort | Clickable `<th>` via `DataTable` `columns[].sortable` | A sort control outside the header |
| Filters | `.page-toolbar` above the table — `SearchInput`, then selects, then chips/toggles | A filter widget inside a `<th>` |
| Paging | `Pagination` below the table | An unpaged table with a server-side row cap |
| State | The URL query string via `readQuery`/`writeQuery` (`tableState.js`) | Component-local state that dies on navigation |

Filters belong in the toolbar, not in the column headers: the header's whole job is sort, the toolbar is where every other list page puts its filters, and a per-header dropdown would need a popover primitive the design system deliberately does not have. Column labels always come from `$t('<page>.columns.<key>')` in a **reactive** `$: columns = [...]` — a `const` freezes the labels in whichever locale was active at mount.

**A page of a queue is not the queue**

Once a table is paged, its filters and sort must be server-side. A client-side filter over the current page narrows the page rather than the result set, and silently disagrees with the `total` the pager is drawn from — the table then offers pages that hold nothing. The two go together: pick client-side sort/filter only for a table that loads all of its rows at once.

Client-side sort with server-side paging is spelled with `NOOP_CMP` comparators (see Packages, Quarantine): the server returns the page in order, and returning `0` for every comparator lets `DataTable`'s stable sort preserve it.

**Never render a bare id where a name exists.** A `user_id`, `actor_id`, or `decided_by` column resolves to an email in the query — `LEFT JOIN users u ON u.id = <col> AND u.tenant_id = <org column>`, keeping both the id and the resolved email on the row. The join is tenant-bound so a stale or cross-tenant id resolves to null instead of another tenant's address, and the display falls back id-wards: `{row.email ?? row.id ?? '—'}`, since an erased account leaves the id behind. Precedents: `AuditRepository`, `QuarantineRepository`.

**Sortable header class**

Use `class="sortable"` on any `<th>` that triggers sort. `DataTable` applies it for you; author it by hand only in the grouped-row exemption above. Do not use `style="cursor:pointer"` on `<th>` — that is a §10 violation.

```css
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text); }
```

**Action-column width**

Empty `<th></th>` (actions-only columns) receive `width: 90px` automatically:

```css
th:empty { width: 90px; }
```

**Sort indicator**

Append `{sortIndicator('col')}` to the column label text. Returns ` ↑` (ascending), ` ↓` (descending), or `''` when inactive.

**Standard shape**

```javascript
const DEFAULTS = { q: '', eco: '', page: 1, limit: 50, sort: 'updated', dir: 'desc' }
const init = readQuery(DEFAULTS)
let search = init.q, page = init.page, limit = init.limit, total = 0
let sortCol = init.sort, sortDir = init.dir

function sync() { writeQuery({ q: search, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS) }
function onPageChange(e) { page = e.detail.page; sync(); load() }
function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }
function onFilterChange() { page = 1; sync(); load() }   // every filter control

const NOOP_CMP = () => 0        // server-sorted: preserve the order it returned
$: columns = [
  { key: 'name',    label: $t('page.columns.name'),    sortable: true },
  { key: 'updated', label: $t('page.columns.updated'), sortable: true, width: '150px', defaultDir: 'desc' },
  { key: 'actions', label: '',                         sortable: false, width: '180px' },
]
```

Sorting, paging, and filtering all reset `page` to 1 — page 4 of the old result set is rarely a page of the new one.

When a component has two independent tables (e.g. Users.svelte members and invites, OrgSettings.svelte allowlist and blocklist), give each its own `memoryKey` (`users:members`, `users:invites`); `DataTable` holds the sort state per instance, so the prefixed `memberSortCol`-style variables are only needed by the hand-rolled exemption.

**Client-side vs. server-side sort**

- **Server-side sort + server-side filters + pagination** (the default for a table that can outgrow one page): Packages, Quarantine.
- **Client-side sort** (in-memory, all rows loaded at once): Vulnerabilities, VersionDetail, Users, Tokens, SettingsServiceTokens, OrgSettings allowlist/blocklist, Claims (server-filtered, client-sorted).
- **Client-side sort on current page only** (acceptable for admin/audit tables): AdminOrgs, Activity.

The server's accepted `sort=` values are a whitelist, and it should equal the set of sortable headers — keeping the two in step is what makes the accepted surface reviewable. An unrecognised value falls back to the default rather than erroring, so a stale bookmark still renders.

**Skip list**

Dashboard.svelte's ecosystem table has one fixed row per ecosystem — sort is meaningless, do not add sort controls.

---

## 6. Iconography

- Stroke-based, **1.5px** stroke on a 16/20/24 grid
- Rounded caps and joins, `currentColor` always
- Lives in `web/public/icons.svg`; reference via
  `<svg><use href="/icons.svg#icon-name"/></svg>`
- If a concept needs a new icon, draw it on the same grid and add it to
  the sprite. Do not pull random icon-pack SVGs.

Required sprite IDs (all must exist in `web/public/icons.svg`):

| ID                  | Used for                                          |
| ------------------- | ------------------------------------------------- |
| `#icon-sun`         | Theme toggle (light mode) — replaces ☀️ emoji     |
| `#icon-moon`        | Theme toggle (dark mode) — replaces 🌙 emoji      |
| `#icon-copy`        | `.copy-btn` affordance on copyable values         |
| `#icon-check`       | Verified / signed receipt chips                   |
| `#icon-shield`      | Vulnerabilities nav item                          |
| `#icon-chevron-down`| Sort indicator in table headers                   |
| `#icon-external`    | Links to osv.dev, signature artifacts, SBOM       |
| `#icon-search`      | Search bar leading icon                           |

---

## 7. Voice & copy

- **Plain, declarative, security-confident.** "Signature verified."
  not "Looks like everything checks out!"
- Use second person sparingly. Prefer the artifact as subject:
  *"This release was built from `a1f9c4d` 12 minutes ago."*
- Never use 🎉 ✅ ❌ in product UI — use the badge system.
- Numbers always with units; durations as `12m`, `2h`, `3d`.
- Bytes formatted via `$formatBytes` only — never `.toLocaleString()` +
  `'B'`. Use binary prefixes (KiB / MiB / GiB).
- Errors name the constraint, not the user:
  *"Policy `core/internal-only` blocked this version."*
- The product is **Dependably** (capitalized). The CLI is **`dpb`**.
- **Every user-visible string goes through `$t()`** — including
  empty-state copy, chart labels, and unit suffixes. Glyphs used for
  decoration (`!`, `▲`, `●`) are not user-visible strings; their
  accessible name lives in `aria-label`.

---

## 8. Accessibility

- Body text on `--bg` ≥ 4.5:1 against background. `--text2` is the
  smallest token that passes for body.
- Focus rings: 2px `--accent` outline, `outline-offset: -1px` on inputs. Never remove.
- Hit targets:
  - **≥ 36px** for primary actions, page-level buttons, and any control
    on a full-page surface.
  - **≥ 28px** for in-row table actions (`.btn-row`), where row density
    would otherwise be sacrificed.
  - **≥ 44px** on touch.
- Every badge carries a `title` attribute and an `aria-label` (state
  isn't only color). Example: `aria-label="3 critical vulnerabilities"`.

---

## 9. Dark mode

- Auto-detects via `@media (prefers-color-scheme: dark)`
- `data-theme="dark|light"` on `<html>` forces a mode
- Manual toggle cycles `auto → dark → light → auto`, persisted to
  localStorage via `web/src/lib/store.js` → `theme`
- Both accent values are pre-defined (`--accent` swaps in `[data-theme="dark"]`
  and the prefers-dark media block)
- Badge dark variants defined for all eight palettes

Themed tokens are declared once via the CSS `light-dark()` function;
`[data-theme="light"]` and `[data-theme="dark"]` flip `color-scheme` to
override OS preference. Adding a new themed token: write
`--name: light-dark(<light-value>, <dark-value>);` once in `:root`.

---

## 10. Conventions

- **No hardcoded hex** — every color references a CSS variable
- **No component-scoped CSS for shared patterns** — use globals from
  `app.css`
- **Svelte `<style>` blocks** — only for layout-specific structural
  rules (flex direction, grid) that don't belong in global CSS
- **No inline `style` attributes for typography, color, or padding.**
  Inline `style` is reserved for: (a) one-off instance positioning
  (margin, position offsets), and (b) computed values from data (chart
  bar height, a width from a number). Anything that recurs — alignment,
  font-family, color, padding, cursor — must be a class. If a CSS value
  appears three times, it is a class.
- **No gratuitous animation** — only the `spin` keyframe and the 0.15s
  button background transition
- **New UI patterns** — add them to `app.css` as global classes rather
  than scoping to one component
- **Write-only secret inputs signal a stored value.** A secret field
  (webhook URL, SMTP password, signing secret, upstream credential) is
  never pre-filled from the server — it binds to an empty string so an
  empty submit preserves the existing secret. When the server reports a
  value is already set (`hasSlackWebhook`, `hasPassword`, `hasSecret`, …),
  render `secretPlaceholder(isSet)` from `lib/secretField.js` as the
  input's `placeholder` so the field reads as configured (masked dots),
  not empty/unconfigured. Never put the secret itself in `value` or
  `placeholder`.

---

## 11. Time & timezone

Dependably is a forensic tool: a first-fetch time, a revocation time, and
an audit timestamp are evidence. A time rendered without its zone is not
evidence — it is a guess about which machine formatted it.

### 11.1 The storage invariant

**Every instant is stored in UTC, in one format, regardless of the
timezone of the frontend, the backend host, or the database server.**
The wire format is ISO 8601 with an explicit `Z`:

```
yyyy-MM-ddTHH:mm:ssZ        2026-07-25T12:00:00Z
```

Rules that keep the invariant true:

- **Instants are normalized before they are formatted.** Call
  `.ToUniversalTime()` on any `DateTimeOffset` that did not come from
  `TimeProvider.GetUtcNow()` — anything parsed from upstream registry
  metadata, an X.509 certificate, a SAML assertion, or a request body
  carries the offset it arrived with.
- **`Z` in a .NET custom format string is a literal, not a conversion.**
  `dto.ToString("yyyy-MM-ddTHH:mm:ssZ")` on a `+02:00` value writes the
  `+02:00` wall-clock time and labels it `Z`. The value is then wrong by
  the offset, and nothing downstream can detect it. Normalize first.
- **Never bind a `DateTimeOffset` straight into a timestamp column.**
  Dapper/`Microsoft.Data.Sqlite` renders it as
  `2026-07-25 14:00:00+02:00` — space-separated, offset preserved, not
  UTC. That collates differently from every `Z` value in the same
  column, so the lexicographic `TEXT` comparisons these columns rely on
  (`WHERE starts_at <= @now`) silently stop working. Bind the
  normalized string.
- **Client-supplied instants are normalized at the edge**, in the
  controller, before they reach a repository — parse, convert to UTC,
  re-format, and persist *that*. Validating that a string parses and
  then storing the original string leaves the client's offset (or no
  offset at all) in the database.

Timestamp columns are `TEXT` in both `Schema.sql` and `Schema.pg.sql`.
Do not introduce `TIMESTAMPTZ` for new columns — a provider-native type
on one side and `TEXT` on the other means the two schemas no longer
round-trip the same string.

### 11.2 The display rule

**Every rendered timestamp carries an explicit zone.** A bare
`14:32` is never shipped. The zone is resolved once, server-side, in
this order:

1. The user's profile timezone preference (`users.timezone`)
2. The org default (`org_settings.default_timezone`), set by an admin in
   Settings → General
3. `UTC`

The chain ends on `UTC`, not on the browser's zone: `default_timezone`
is `NOT NULL DEFAULT 'UTC'`, so a tenant that never chose one is
indistinguishable from a tenant that deliberately chose UTC, and
guessing the viewer's zone for a forensic timestamp is the wrong default
to guess. A tenant that wants something else sets it once, for everyone.

The user half mirrors the language preference exactly (`users.language`
→ `org_settings.default_language`): a nullable per-user column whose
`NULL` means *inherit*, never a duplicated default, so a later change to
the org default reaches every user who never chose a zone.

Both preferences are **display only**. Every instant is stored in UTC
regardless of either (§11.1); this decides how a stored instant is
rendered, never what is written.

A step of this chain that the runtime cannot honour is dropped, not
approximated: an identifier the tz database does not recognise falls
through to the next step. The runtime image must therefore ship
`tzdata` — without it every IANA zone is unrecognised and the whole
chain collapses to `UTC` while the browser-built picker still lists
every zone. Both Dockerfiles install it and probe
`/usr/share/zoneinfo` at build time so the image cannot regress.

Formatting rules:

- **Absolute times name their zone.** `25 Jul 2026, 14:32 EDT`. Pass an
  explicit `timeZone` and `timeZoneName: 'short'` to
  `Intl.DateTimeFormat` — the resolved zone from above, never the
  implicit browser default.
- **Relative times are for recency only** — "3 minutes ago" is legible
  where a clock time is not. Use it under ~24h; past that, show the
  absolute time. A relative time never stands alone as evidence: it
  carries the absolute time in a `title` tooltip.
- **The tooltip is always the full UTC instant.** Hovering any rendered
  time shows `2026-07-25T18:32:04Z` — the stored value, unconverted, so
  an operator can correlate against a log line without doing arithmetic.
- **Tables sort on the raw ISO string, never the formatted one.**
- **Log and export surfaces stay UTC.** Audit CSV exports, SIEM
  payloads, and `@timestamp` log fields are machine-read and are not
  localized to the viewer's zone.

### 11.3 The profile preference

A **Timezone** row in Profile, directly below Language, using the same
`settings-row` shape: a title, help text naming the inherited org
default, and a `<select>`. Options come from
`Intl.supportedValuesOf('timeZone')`, with the browser-detected zone
offered first as the default choice. Selecting the org default is
expressed by an explicit "Use organization default" option that writes
`NULL` — not by picking the matching zone by hand, which would pin the
user and silently ignore a later change to the org default.

---

## 12. Don'ts

- Don't add a second accent hue (badge palettes don't count).
- Don't use emoji for status — use the badge system.
- Don't use emoji in chrome — even the theme toggle uses `#icon-sun` /
  `#icon-moon` from the sprite, not ☀️ / 🌙.
- Don't use `text-shadow`, glow effects, or animated gradients.
- Don't use rounded-corner cards with a left-border accent stripe.
- Don't draw decorative SVG illustrations.
- Don't introduce a third typeface — JetBrains Mono is the answer to
  "this needs to feel different".
- Don't break the existing class API. New patterns are additive.
- Don't define severity colors in component `<style>` blocks — use `.sev`
  and the `--sev-*` tokens.
- Don't pass severity through glyphs alone (`!` `▲` `●` `▼`). Always
  pair with `aria-label`.
- Don't put the shadow on `.card` — `--shadow` is for elevated surfaces
  (dropdowns, popovers) only. The card border is sufficient.
