/**
 * Thin wrapper around the vendored qrcode-generator library.
 *
 * Generates an SVG string for a QR code encoding arbitrary UTF-8 text.
 * ECC level M, auto version selection (handles v1–v40 including v7+ version-info blocks).
 *
 * Usage:
 *   import { qrSvg } from './qrcode.js'
 *   const svg = qrSvg('otpauth://totp/...', { size: 200 })
 */

import qrcode from './vendor/qrcode-generator.js'

/**
 * Generates a minimal SVG string for a QR code encoding `text`.
 *
 * The SVG contains only generated geometry (<svg>/<path>/<rect>/<g>) —
 * the input `text` is never reflected into the markup.
 *
 * @param {string} text - The text to encode (otpauth URI or similar).
 * @param {{ size?: number }} options
 * @returns {string} SVG markup string.
 */
export function qrSvg(text, { size = 200 } = {}) {
  const qr = qrcode(0, 'M')
  qr.addData(text, 'Byte')
  qr.make()

  const moduleCount = qr.getModuleCount()
  // 4-module quiet zone, scale cell size to fill the requested pixel size.
  const quietZone = 4
  const cellSize = size / (moduleCount + quietZone * 2)
  const margin = quietZone * cellSize

  // Build SVG with <rect> elements so the output is pure geometry with a white background.
  const rects = []
  for (let r = 0; r < moduleCount; r++) {
    for (let c = 0; c < moduleCount; c++) {
      if (qr.isDark(r, c)) {
        const x = (margin + c * cellSize).toFixed(2)
        const y = (margin + r * cellSize).toFixed(2)
        const w = cellSize.toFixed(2)
        rects.push(`<rect x="${x}" y="${y}" width="${w}" height="${w}"/>`)
      }
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" ` +
    `width="${size}" height="${size}" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="#fff"/>` +
    `<g fill="#000">${rects.join('')}</g>` +
    `</svg>`
  )
}
