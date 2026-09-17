const PREFIX = 'arm_'

/**
 * Unified localStorage wrapper. All modules use this instead of raw localStorage.
 * Provides namespaced keys (arm_*) and JSON serialization.
 */
export const storage = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(PREFIX + key)
      return raw !== null ? JSON.parse(raw) : fallback
    } catch {
      return fallback
    }
  },

  set(key, value) {
    try {
      localStorage.setItem(PREFIX + key, JSON.stringify(value))
    } catch {
      // quota exceeded or private browsing
    }
  },

  remove(key) {
    try {
      localStorage.removeItem(PREFIX + key)
    } catch {}
  }
}
