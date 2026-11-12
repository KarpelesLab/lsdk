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
  promptDetail: null, // value to compare with what the device displays
  log: [],
  // Firmware update flow: null | 'osu' | 'reboot' | 'mcu' | 'done'
  fwPhase: null,
  // Hide the bootloader modal until the device reconnects.
  bootloaderDismissed: false,
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
  state.bootloaderDismissed = false
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
  navigator.hid.addEventListener('disconnect', (ev) => {
    // Compare with our HIDDevice directly: the transport's own listener may
    // not have run yet.
    if (state.device && (ev.device === state.device.hidDevice || state.device.disconnected)) {
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
export async function reconnect({ timeout = 30000, quiet = false, exclude = null } = {}) {
  state.reconnecting = true
  const until = Date.now() + timeout
  try {
    await sleep(300)
    for (;;) {
      // The user may have picked the device again meanwhile (Connect button),
      // e.g. when it re-enumerated under a new USB product id. `exclude` is the
      // handle we are waiting to replace (it may not be flagged as gone yet).
      const cur = state.device
      if (state.connected && cur && cur !== exclude && !cur.disconnected) return cur
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

let lockPoll = null

export async function refreshInfo() {
  if (!state.device) return
  const wasLocked = state.info?.locked
  state.info = await state.device.info()
  if (state.info?.locked) {
    if (!wasLocked) log('warn', 'device is locked: enter your PIN on the device')
    // Poll (no prompt involved) until it is unlocked.
    clearTimeout(lockPoll)
    lockPoll = setTimeout(() => {
      if (state.busy || !state.connected) return
      refreshInfo().catch(() => {})
    }, 2000)
  } else if (wasLocked) {
    log('info', 'device unlocked')
  }
}

// Run one device operation at a time. Handles disconnections transparently
// by reconnecting once.
export async function run(label, fn, { retryOnDisconnect = true } = {}) {
  if (state.busy) throw new Error(`busy: ${state.busy}`)
  if (!state.device) throw new Error('no device connected')
  state.busy = label
  state.progress = null
  state.prompt = null
  state.promptDetail = null
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
    // Locked meanwhile (screensaver): show it, and poll until unlocked.
    if (e?.kind === 'Locked') setTimeout(() => refreshInfo().catch(() => {}), 0)
    throw e
  } finally {
    state.busy = null
    state.progress = null
    state.prompt = null
    state.promptDetail = null
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

// Run an app command, opening `app` first if something else is running
// (the dashboard answers app commands with 0x6511).
export async function runInApp(app, label, fn, opts) {
  try {
    await ensureApp(app)
  } catch (e) {
    if (e?.kind === 'NotFound') {
      throw new Error(`the ${app} app is not installed: use "Open ${app}" above to install it`)
    }
    throw e
  }
  return run(label, fn, opts)
}

// Wait for the device to come back (reboot / re-enumeration).
export async function waitDevice(phase = 'reboot', timeout = 600000) {
  state.fwPhase = phase
  log('info', 'waiting for the device to restart…')
  const old = state.device
  // First see the current device go away: it can take a moment after the
  // last APDU, and reconnecting before that would pick up the dying handle.
  const gone = Date.now() + 30000
  while (old && !old.disconnected && Date.now() < gone) await sleep(250)
  if (old && !old.disconnected) {
    log('warn', 'the device did not restart, checking its state')
  } else {
    state.connected = false
  }
  await reconnect({ timeout, exclude: old && old.disconnected ? old : null })
  // A fresh read is required: decisions are taken on it.
  for (let i = 0; ; i++) {
    try {
      await refreshInfo()
      if (state.info?.version || state.info?.app || state.info?.locked) return
    } catch (e) {
      if (i >= 5) throw new Error(`cannot read the device state after restart: ${errorText(e)}`)
    }
    if (i >= 5) throw new Error('cannot read the device state after restart')
    await sleep(1000)
  }
}

// While the device sits in bootloader mode, flash what its installed firmware
// needs (MCU or bootloader), waiting for each restart.
export async function flashWhileBootloader() {
  for (let i = 0; i < 6 && state.info?.version?.isBootloader; i++) {
    state.fwPhase = 'mcu'
    const kind = await run('flash MCU', (d) => {
      state.prompt = 'Allow the secure connection on the device if asked'
      return d.repairMcu(hsmEvent)
    }, { retryOnDisconnect: false }).catch((e) => {
      if (e?.kind !== 'Disconnected') throw e
      return 'mcu'
    })
    log('ok', `${kind} flashed`)
    await waitDevice('reboot')
  }
  if (state.info?.version?.isBootloader) throw new Error('device is still in bootloader mode after several flashes')
}

// Finish an interrupted update (device found in bootloader mode).
export async function finishBootloaderUpdate() {
  try {
    await flashWhileBootloader()
    state.fwPhase = 'done'
    log('ok', `firmware is now ${state.info?.version?.seVersion ?? state.info?.app?.version ?? 'updated'}`)
  } catch (e) {
    state.fwPhase = null
    throw e
  }
}
