export const bus = {
  _events: {},
  on(event, fn) {
    (this._events[event] ||= []).push(fn)
  },
  off(event, fn) {
    if (!this._events[event]) return
    const idx = this._events[event].indexOf(fn)
    if (idx !== -1) this._events[event].splice(idx, 1)
  },
  emit(event, data) {
    (this._events[event] || []).forEach(fn => {
      try { fn(data) } catch (err) { console.error(`Event ${event} handler error:`, err) }
    })
  }
}
