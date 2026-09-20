import { bus } from '../api/event-bus.js'

const _modules = []
const _services = new Map()

/**
 * Module registry — the framework shell.
 *
 * Modules register themselves with { name, init(reg), refresh?(), destroy?() }.
 * The registry provides shared services (i18n, storage, bus) so modules
 * never need to import each other.
 */
export const registry = {
  /** Register a shared service available to all modules */
  provide(name, service) {
    _services.set(name, service)
  },

  /** Get a shared service */
  get(name) {
    return _services.get(name)
  },

  /** Shorthand accessors for built-in services */
  get bus() { return bus },
  get i18n() { return _services.get('i18n') },
  get storage() { return _services.get('storage') },

  /** Register a module descriptor */
  register(mod) {
    _modules.push(mod)
  },

  /** Call init on all registered modules */
  async initAll() {
    for (const mod of _modules) {
      try {
        await mod.init(registry)
      } catch (e) {
        registry.bus.emit('log:append', `[Module] ${mod.name} init error: ${e.message}`)
      }
    }
  },

  /** Call refresh on all registered modules in parallel */
  async refreshAll() {
    await Promise.all(_modules.map(mod => {
      if (!mod.refresh) return Promise.resolve()
      return mod.refresh().catch(e => {
        registry.bus.emit('log:append', `[Module] ${mod.name} refresh error: ${e.message}`)
      })
    }))
  },

  /** Call destroy on all registered modules that have it (e.g. app shutdown) */
  destroyAll() {
    for (const mod of _modules) {
      if (mod.destroy) {
        try { mod.destroy() } catch {}
      }
    }
  },

  /** For modules that need to read another module's top-level state
   *  (used ONLY by the framework shell for launch orchestration) */
  getModule(name) {
    return _modules.find(m => m.name === name) || null
  }
}
