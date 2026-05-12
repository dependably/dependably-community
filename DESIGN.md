# Dependably — Design Reference

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
  `web/src/assets/brand/dependably-mark.svg` (and `-mono.svg`,
  `-inverse.svg`, `-lockup.svg` if needed)
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

All colors live as CSS custom properties in `src/app.css`. **Never
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
│   .page (max-width: 1100px, padding: 24px)  │
│     .page-header (flex, space-between)      │
│       .page-title          [action buttons] │
│     [content]                               │
└─────────────────────────────────────────────┘
```

Forms width-constrained ≤ 480px. Full-width tables live directly inside
`.page`.

Data-dense pages (Dashboard, Vulnerabilities, Packages, Audit,
AdminSettings) add `.page-wide` (1320px). 1100 for forms, 1320 for
data-dense tables; no other widths.

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

All global classes live in `src/app.css`. Use them as-is; do not
redefine them in component `<style>` blocks.

| Section | Class(es)                                                  | Purpose                                         | Used in                         |
| ------- | ---------------------------------------------------------- | ----------------------------------------------- | ------------------------------- |
| §5.1    | `.brand`, `.brand-text`                                    | Mark + wordmark lockup                          | App.svelte navbar               |
| §5.2    | `.eyebrow`                                                 | Uppercase mono caption                          | Auth pages, dashboard, tables   |
| §5.3    | `.badge.verified`, `.badge.signed`                         | Trust signal chips                              | VersionDetail, receipts panel   |
| §5.4    | `.login-card`                                              | Auth page card                                  | Login.svelte                    |
| §5.5    | `.sev`, `.sev-critical/high/medium/low`                    | Vulnerability severity chip                     | Packages, VersionDetail, Dashboard |
| §5.6    | `.stat-card`, `.alert-card`, `.stat-grid`, `.stat-value`   | Dashboard KPI and alert surfaces                | Dashboard.svelte                |
| §5.6    | `.title-row`, `.ribbon`, `.ribbon.hot`                     | Page-title row with inline status ribbon        | Dashboard.svelte                |
| §5.6    | `.eco-name-cell`, `.eco-bar.{eco}`                         | Ecosystem table name cell (donut legend proxy)  | Dashboard.svelte                |
| §5.7    | `.detail-panel`, `.detail-section`, `.detail-label`, `.detail-value` | Expanded-row receipts drawer      | VersionDetail.svelte            |
| §5.8    | `th.sortable`                                                          | Sortable column header (cursor + indicator) | All data tables        |
| —       | `.card`                                                    | Generic surface card                            | Multiple                        |
| —       | `.badge` + ecosystem modifiers                             | Ecosystem and status labels                     | Multiple                        |
| —       | `.tabs` / `.tab`                                           | Tab navigation                                  | Multiple                        |
| —       | `.form-row` / `.form-hint`                                 | Form layout                                     | Multiple                        |
| —       | `button`, `button.primary`, `button.danger`                | Actions                                         | Multiple                        |
| —       | `input` / `select` / `textarea`                            | Form inputs                                     | Multiple                        |
| —       | `table` / `th` / `td`                                      | Data tables                                     | Multiple                        |
| —       | `.copy-block`, `.copy-btn`                                 | Copyable code/hash blocks                       | Multiple                        |
| —       | `.modal`, `.modal-backdrop`, `.modal-actions`              | Modal dialogs                                   | Multiple                        |
| —       | `.spinner`                                                 | Loading state (mid-flight actions, modal submit)| Multiple                        |
| —       | `.skeleton`                                                | Shimmer placeholder for initial table fetch     | Tables (Packages, VersionDetail, Vulnerabilities) |
| —       | `.search-bar`                                              | Search input                                    | Packages.svelte                 |
| —       | `.error-msg`                                               | Inline form-field validation error              | Forms                           |
| —       | `.page-error`                                              | Top-of-page fetch failure banner                | All data pages                  |
| —       | `.page-header`, `.page-title`                              | Page chrome                                     | All pages                       |
| —       | `.first-fetch-row`                                         | Amber highlight for first-seen packages         | Packages.svelte                 |
| —       | `.expanded-row`                                            | Table row expanded state                        | VersionDetail.svelte            |
| —       | `.btn-row`                                                 | Compact in-row action button (28–32px tall)     | VersionDetail.svelte            |

**`.skeleton`** — shimmer placeholder for table rows / single text
lines during the initial fetch. Use 3-5 placeholder rows per table; do
not mix with `.spinner` on the same view. `.spinner` stays for
mid-flight actions like modal submit and inline retry.

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
```

**When adding a new ecosystem** (Maven, Cargo, etc.), three things must
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

### 5.8 Sortable tables

All data tables use `table-layout: fixed`. This prevents column widths from shifting when sort indicators appear and avoids content-driven layout thrash.

**Sortable header class**

Use `class="sortable"` on any `<th>` that triggers sort. Do not use `style="cursor:pointer"` on `<th>` — that is a §10 violation.

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

**Standard sort helpers**

```javascript
let sortCol = 'email', sortDir = 'asc'
$: sorted = [...items].sort((a, b) => {
  let av = a[sortCol] ?? '', bv = b[sortCol] ?? ''
  if (av < bv) return sortDir === 'asc' ? -1 : 1
  if (av > bv) return sortDir === 'asc' ? 1 : -1
  return 0
})
function toggleSort(col) {
  if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
  else { sortCol = col; sortDir = 'asc' }
}
function sortIndicator(col) {
  if (sortCol !== col) return ''
  return sortDir === 'asc' ? ' ↑' : ' ↓'
}
```

When a component has two independent tables (e.g. Users.svelte members and invites, OrgSettings.svelte allowlist and blocklist), prefix the variable names: `memberSortCol`, `alSortCol`, etc.

**Client-side vs. server-side sort**

- **Server-side sort** (API params, paginated across all pages): Packages.
- **Client-side sort** (in-memory, all rows loaded at once): Vulnerabilities, VersionDetail, Users, Tokens, CicdTokens, OrgSettings allowlist/blocklist.
- **Client-side sort on current page only** (acceptable for admin/audit tables): AdminOrgs, Activity.

**Skip list**

Dashboard.svelte's ecosystem table has three fixed rows (pypi, npm, nuget) — sort is meaningless, do not add sort controls.

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

---

## 11. Don'ts

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
- Don't reference `--surface2` until it is declared in `app.css`. Until
  then, use `--bg2` and file the token addition.
- Don't pass severity through glyphs alone (`!` `▲` `●` `▼`). Always
  pair with `aria-label`.
- Don't put the shadow on `.card` — `--shadow` is for elevated surfaces
  (dropdowns, popovers) only. The card border is sufficient.
