// Global app state + device lifecycle (connect, re-enumeration, busy lock).
import { reactive, markRaw } from 'vue'
import init, { HwDevice, isSupported } from '../pkg/lsdk.js'

export const state = reactive({
  ready: false,
  supported: false,
  device: null, // HwDevice (raw)
  info: null,
  connected: false,
  reconnecting: false,
  busy: null, // label of the running operation
  progress: null, // 0..1 or null
  prompt: null, // message asking for an action on the device
  log: [],
})

let seq = 0
export function log(level, msg) {
  state.log.unshift({ id: ++seq, t: new Date(), level, msg })
  if (state.log.length > 300) state.log.length = 300
}

export function errorText(e) {
  if (!e) return 'unknown error'
  const base = e.message || String(e)
  return e.statusCode && !base.includes(e.statusCode) ? `${base} (${e.statusCode})` : base
}

function setDevice(dev) {
  const old = state.device
  state.device = dev ? markRaw(dev) : null
  state.connected = !!dev
  if (old && old !== dev) {
    try { old.free() } catch { /* already freed */ }
  }
}

export async function boot() {
  await init()
  state.supported = isSupported()
  state.ready = true
  if (!state.supported) return
  navigator.hid.addEventListener('disconnect', () => {
    if (state.device && state.device.disconnected) {
      state.connected = false
      log('warn', 'device disconnected')
    }
  })
  navigator.hid.addEventListener('connect', () => {
    if (!state.connected && !state.busy) reconnect({ quiet: true }).catch(() => {})
  })
  // Silently reuse a device authorized in a previous visit.
  if ((await HwDevice.grantedCount()) > 0) await reconnect({ timeout: 1500, quiet: true }).catch(() => {})
}

export async function connect() {
  const dev = await HwDevice.request()
  setDevice(dev)
  log('info', `connected to ${dev.productName}`)
  await refreshInfo()
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Poll until an authorized device shows up again (it re-enumerates when an
// app opens or closes, and reboots during firmware updates).
export async function reconnect({ timeout = 30000, quiet = false } = {}) {
  state.reconnecting = true
  const until = Date.now() + timeout
  try {
    await sleep(300)
    for (;;) {
      try {
        const dev = await HwDevice.reconnect()
        setDevice(dev)
        if (!quiet) log('info', `reconnected to ${dev.productName}`)
        await refreshInfo().catch(() => {})
        return dev
      } catch (e) {
        if (Date.now() > until) throw new Error('device not found, reconnect it or pick it again')
        await sleep(800)
      }
    }
  } finally {
    state.reconnecting = false
  }
}

export async function disconnect() {
  if (state.device) await state.device.close().catch(() => {})
  setDevice(null)
  state.info = null
}

export async function refreshInfo() {
  if (!state.device) return
  state.info = await state.device.info()
}

// Run one device operation at a time. Handles disconnections transparently
// by reconnecting once.
export async function run(label, fn, { retryOnDisconnect = true } = {}) {
  if (state.busy) throw new Error(`busy: ${state.busy}`)
  if (!state.device) throw new Error('no device connected')
  state.busy = label
  state.progress = null
  state.prompt = null
  try {
    try {
      return await fn(state.device)
    } catch (e) {
      if (retryOnDisconnect && (e?.kind === 'Disconnected' || state.device?.disconnected)) {
        log('warn', `${label}: device re-enumerated, reconnecting`)
        await reconnect()
        return await fn(state.device)
      }
      throw e
    }
  } catch (e) {
    log('error', `${label}: ${errorText(e)}`)
    throw e
  } finally {
    state.busy = null
    state.progress = null
    state.prompt = null
  }
}

// Callback for HSM events (genuine check, install, firmware).
export function hsmEvent(ev) {
  switch (ev.type) {
    case 'permissionRequested':
      state.prompt = 'Allow the secure connection on your device'
      break
    case 'permissionGranted':
      state.prompt = null
      log('info', 'secure connection allowed')
      break
    case 'progress':
      state.prompt = null
      state.progress = ev.total ? ev.index / ev.total : 0
      break
    case 'warning':
      log('warn', ev.message)
      break
  }
}

// Open an app, then wait for the device to come back.
export async function openApp(name) {
  await run(`open ${name}`, async (d) => {
    state.prompt = `Confirm opening ${name} on the device`
    await d.openApp(name)
  }, { retryOnDisconnect: false }).catch((e) => {
    if (e?.kind !== 'Disconnected') throw e
  })
  await reconnect()
  log('info', `${name} is open`)
}

export async function quitApp() {
  await run('quit app', (d) => d.quitApp(), { retryOnDisconnect: false }).catch((e) => {
    if (e?.kind !== 'Disconnected') throw e
  })
  await reconnect()
}

export const isDashboard = (name) => name === 'BOLOS' || name === 'OLOS\u0000'

// Make sure a given app is running (opening it if on the dashboard).
export async function ensureApp(name) {
  const cur = await run('check app', (d) => d.appAndVersion())
  if (cur.name === name) return
  if (!isDashboard(cur.name)) await quitApp()
  await openApp(name)
}
