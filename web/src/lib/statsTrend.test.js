import { describe, it, expect } from 'vitest'
import { sparklinePoints, deltaVs7d, buildTrendMetrics } from './statsTrend.js'

describe('sparklinePoints', () => {
  it('returns an empty string for an empty series', () => {
    expect(sparklinePoints([])).toBe('')
    expect(sparklinePoints(null)).toBe('')
  })

  it('draws a level line for a flat series rather than dividing by a zero range', () => {
    // The mutant here is `range = max - min` with no `|| 1` fallback: for [5, 5, 5] that
    // divides by zero and every y becomes NaN, which is not a rendering SVG can recover from.
    const points = sparklinePoints([5, 5, 5]).split(' ')
    expect(points).toHaveLength(3)
    for (const p of points) {
      expect(p).not.toContain('NaN')
    }
    // Every y-coordinate is identical for a flat series.
    const ys = points.map(p => p.split(',')[1])
    expect(new Set(ys).size).toBe(1)
  })

  it('draws a single point at x=0 without dividing by a zero step', () => {
    const points = sparklinePoints([42])
    expect(points).not.toContain('NaN')
    expect(points.split(',')[0]).toBe('0.0')
  })

  it('spans the full x range and orders low values below high values (SVG y grows downward)', () => {
    const points = sparklinePoints([0, 10]).split(' ')
    expect(points).toHaveLength(2)
    const [, y0] = points[0].split(',').map(Number)
    const [, y1] = points[1].split(',').map(Number)
    // The lower value (0) must sit further down the viewBox (larger y) than the higher value.
    expect(y0).toBeGreaterThan(y1)
  })
})

describe('deltaVs7d', () => {
  const days = ['2026-06-08', '2026-06-09', '2026-06-14', '2026-06-15']
  const values = [10, 12, 18, 25]

  it('returns null for an empty series', () => {
    expect(deltaVs7d([], [])).toBeNull()
    expect(deltaVs7d(null, null)).toBeNull()
  })

  it('computes the delta against the point exactly 7 calendar days before the latest one', () => {
    // Latest day is 2026-06-15; 7 days earlier is 2026-06-08, present in the window.
    expect(deltaVs7d(values, days)).toBe(25 - 10)
  })

  it('returns null when the 7-days-ago day is missing from the window (a gap in history)', () => {
    // The mutant here is comparing by array offset (values.length - 8) instead of by calendar
    // day: with only 4 points that offset is negative and would silently read undefined/wrong
    // data instead of recognizing the gap. Dropping the day that IS 7 days back proves the
    // real day-based lookup, not an offset that happens to still land on some index.
    const gappedDays = ['2026-06-09', '2026-06-14', '2026-06-15']
    const gappedValues = [12, 18, 25]
    expect(deltaVs7d(gappedValues, gappedDays)).toBeNull()
  })

  it('a negative delta stays a real negative number, not clamped to zero', () => {
    expect(deltaVs7d([25, 10], ['2026-06-08', '2026-06-15'])).toBe(-15)
  })
})

describe('buildTrendMetrics', () => {
  it('returns one entry per known metric, all null-delta and empty-points for no history', () => {
    const metrics = buildTrendMetrics([])
    expect(metrics.map(m => m.key)).toEqual([
      'totalVulnerabilities', 'blockedPulls30d', 'totalDownloads30d',
    ])
    for (const m of metrics) {
      expect(m.delta).toBeNull()
      expect(m.latest).toBe(0)
    }
  })

  it('reads each metric out of the right field and reports the latest value', () => {
    const trend = [
      { day: '2026-06-08', totalVulnerabilities: 1, blockedPulls30d: 2, totalDownloads30d: 3 },
      { day: '2026-06-15', totalVulnerabilities: 4, blockedPulls30d: 5, totalDownloads30d: 6 },
    ]
    const metrics = buildTrendMetrics(trend)
    const byKey = Object.fromEntries(metrics.map(m => [m.key, m]))
    expect(byKey.totalVulnerabilities.latest).toBe(4)
    expect(byKey.totalVulnerabilities.delta).toBe(3)
    expect(byKey.blockedPulls30d.latest).toBe(5)
    expect(byKey.totalDownloads30d.latest).toBe(6)
  })

  it('tolerates a null trend the same as an empty one', () => {
    expect(buildTrendMetrics(null).every(m => m.delta === null)).toBe(true)
  })
})
