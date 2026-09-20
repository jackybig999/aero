import { globalApi } from '../../api/bridge.js'
import { storage } from '../../core/storage.js'

function defaultLang() {
  const saved = storage.get('lang', null)
  if (saved) return saved
  try {
    const nav = (typeof navigator !== 'undefined' && (navigator.language || navigator.userLanguage)) || 'en'
    const l = String(nav).toLowerCase()
    if (l.startsWith('zh-tw') || l.startsWith('zh-hk')) return 'zh-TW'
    if (l.startsWith('zh')) return 'zh-CN'
  } catch {}
  return 'zh-CN'
}

let dict = {}
let currentLang = defaultLang()

export async function load(lang) {
  try {
    const res = await globalApi.getI18n(lang)
    if (res && Object.keys(res).length > 0) {
      dict = res
      currentLang = lang
      return
    }
    console.error(`[i18n] empty dictionary for ${lang}`)
  } catch (err) {
    console.error(`[i18n] Failed to load translations for ${lang}: ${err.message}`)
  }
}

export function t(key, vars = {}) {
  let text = dict[key] ?? key
  if (typeof text !== 'string') return key
  for (const [k, v] of Object.entries(vars)) {
    text = text.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v))
  }
  return text
}

export function getLang() {
  return currentLang
}

export function setLang(lang) {
  currentLang = lang
  storage.set('lang', lang)
}

export function getDict() {
  return dict
}
