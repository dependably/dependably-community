// Pure helpers behind the Dashboard's trend sparklines/deltas. Extracted from Dashboard.svelte
// so this arithmetic is unit-testable — Svelte pages themselves have no component test harness
// in this repo (see the Playwright suite for page-level coverage), but plain lib modules do.

/** The dashboard's own headline trend figures — see OrgStatsHistoryPoint on the backend. */
export const TREND_METRICS = [
  { key: 'totalVulnerabilities', labelKey: 'dashboard.trends.vulnerabilities' },
  { key: 'blockedPulls30d', labelKey: 'dashboard.trends.blockedPulls' },
  { key: 'totalDownloads30d', labelKey: 'dashboard.trends.downloads' },
]

/**
 * Builds a small SVG polyline's `points` attribute (0 0 60 20 viewBox) normalized to the
 * series' own min/max. A flat series (every value equal, including a single point) draws a
 * level line rather than dividing by a zero range. Returns '' for an empty series.
 */
export function sparklinePoints(values) {
  if (!values || values.length === 0) return ''
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1
  const stepX = values.length > 1 ? 60 / (values.length - 1) : 0
  return values
    .map((v, i) => {
      const x = i * stepX
      const y = 20 - ((v - min) / range) * 18 - 1
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}

/**
 * Delta between the latest value and the value exactly 7 days earlier, matched by calendar day
 * (in `days`, parallel to `values`) rather than by array offset — a gap in the history (a
 * refresh pass that never ran) must not silently compare against the wrong day. Returns null
 * when that day is not present in the window, or when there is no data at all.
 */
export function deltaVs7d(values, days) {
  if (!values || values.length === 0) return null
  const latestDay = days[days.length - 1]
  // A fresh Date per subtraction rather than mutating one in place: this is a one-shot
  // calculation with nothing to react to, so there is no reactive-state case to make for
  // SvelteDate here.
  const targetMs = new Date(latestDay + 'T00:00:00Z').getTime() - 7 * 86_400_000
  const targetDay = new Date(targetMs).toISOString().slice(0, 10)
  const idx = days.indexOf(targetDay)
  if (idx === -1) return null
  return values[values.length - 1] - values[idx]
}

/**
 * Builds the per-metric view model the Dashboard's trend cards render: the raw series, the
 * sparkline points, the latest value, and the 7-day delta. `trend` is the OrgStats.trend array
 * (oldest first) — possibly null/empty/short, all handled by the helpers above.
 */
export function buildTrendMetrics(trend) {
  const points = trend ?? []
  const days = points.map(p => p.day)
  return TREND_METRICS.map(m => {
    const values = points.map(p => p[m.key] ?? 0)
    return {
      ...m,
      values,
      points: sparklinePoints(values),
      latest: values[values.length - 1] ?? 0,
      delta: deltaVs7d(values, days),
    }
  })
}
