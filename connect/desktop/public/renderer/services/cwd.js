import { configApi } from '../api/bridge.js'

/**
 * CWD (Current Working Directory) store.
 * Shared service — ai-tools module accesses CWD through registry, not direct import.
 */
export const cwdService = {
  _store: {},

  async load() {
    try {
      const res = await configApi.getCwd()
      if (res.success && res.cwd) this._store = res.cwd
    } catch (err) {
      console.error(`[cwd] Failed to load CWD store: ${err.message}`)
    }
  },

  get(key, fallback = '') {
    return this._store[key] || fallback
  },

  set(key, cwd) {
    this._store[key] = cwd
    configApi.saveCwd(this._store).catch(() => {})
  }
}
