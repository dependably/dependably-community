// Node exposes a native `localStorage` global that resolves to `undefined` unless the
// process is started with --localstorage-file, and it shadows the jsdom implementation —
// so neither `localStorage` nor `window.localStorage` is usable under the jsdom
// environment. Browsers always provide Web Storage, so the test environment supplies an
// in-memory implementation rather than the app code guarding against its absence.
//
// Storage is installed per test file (setup runs once per environment), so state does not
// leak between files, matching jsdom's per-window storage.

class MemoryStorage {
  #entries = new Map()

  get length() {
    return this.#entries.size
  }

  key(index) {
    return [...this.#entries.keys()][index] ?? null
  }

  getItem(key) {
    const k = String(key)
    return this.#entries.has(k) ? this.#entries.get(k) : null
  }

  setItem(key, value) {
    this.#entries.set(String(key), String(value))
  }

  removeItem(key) {
    this.#entries.delete(String(key))
  }

  clear() {
    this.#entries.clear()
  }
}

for (const name of ['localStorage', 'sessionStorage']) {
  if (typeof globalThis[name] === 'undefined') {
    Object.defineProperty(globalThis, name, {
      value: new MemoryStorage(),
      configurable: true,
      writable: true,
    })
  }
}
