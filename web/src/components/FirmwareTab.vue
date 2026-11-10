<script setup>
import { ref, computed } from 'vue'
import { state, run, hsmEvent, log, errorText, reconnect, refreshInfo } from '../lib/store.js'
import { renderMarkdown } from '../lib/markdown.js'

const error = ref(null)
const update = ref(undefined) // undefined: not checked, null: up to date
const phase = ref(null) // null | 'osu' | 'reboot' | 'mcu' | 'done'
const v = computed(() => state.info?.version)
const notesHtml = computed(() => renderMarkdown(update.value?.osu?.notes))

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e); phase.value = null }
}

const check = () => guard(async () => {
  update.value = await run('check firmware', (d) => d.checkFirmware())
  log('info', update.value ? `firmware ${update.value.final.name} available` : 'firmware is up to date')
})

async function waitDevice(label, timeout = 600000) {
  phase.value = label
  log('info', 'waiting for the device to restart…')
  await reconnect({ timeout })
  await refreshInfo().catch(() => {})
}

const start = () => guard(async () => {
  const u = update.value
  if (!confirm(`Update the firmware to ${u.final.name}? Keep the device plugged in until it is done. Make sure you have your recovery phrase.`)) return
  if (!v.value?.isOsu && !v.value?.isBootloader) {
    phase.value = 'osu'
    await run('install OS updater', async (d) => {
      state.prompt = 'Allow the secure connection, then confirm the update on the device'
      await d.installOsu(u, hsmEvent)
    }, { retryOnDisconnect: false }).catch((e) => {
      if (e?.kind !== 'Disconnected') throw e
    })
    log('ok', 'OS updater installed, the device installs the firmware and restarts')
  }
  await waitDevice('reboot')
  await flashWhileBootloader()
  phase.value = 'done'
  update.value = undefined
  log('ok', `firmware is now ${state.info?.version?.seVersion ?? 'updated'}`)
})

// While the device sits in bootloader mode, flash what its installed firmware
// needs (MCU or bootloader), then wait for it to restart.
async function flashWhileBootloader() {
  for (let i = 0; i < 6 && state.info?.version?.isBootloader; i++) {
    phase.value = 'mcu'
    const kind = await run('flash MCU', (d) => d.repairMcu(hsmEvent), { retryOnDisconnect: false }).catch((e) => {
      if (e?.kind !== 'Disconnected') throw e
      return 'mcu'
    })
    log('ok', `${kind} flashed`)
    await waitDevice('reboot')
  }
}

const finish = () => guard(async () => {
  await flashWhileBootloader()
  phase.value = 'done'
  log('ok', `firmware is now ${state.info?.version?.seVersion ?? 'updated'}`)
})
</script>

<template>
  <div class="grid">
    <p v-if="error" class="error">{{ error }}</p>
    <div class="panel">
      <div class="row">
        <div>
          <h2>Firmware</h2>
          <p class="muted small-text" style="margin:0">Current: <span class="mono">{{ v?.seVersion || v?.rawVersion || 'unknown' }}</span> · MCU <span class="mono">{{ v?.mcuSephVersion || '—' }}</span></p>
        </div>
        <div class="spacer"></div>
        <button :disabled="!!state.busy || !v || v.isBootloader" @click="check">Check for updates</button>
      </div>
      <p v-if="!v" class="note">Quit the running app first (Device tab).</p>
    </div>

    <div v-if="v?.isBootloader && !phase" class="panel">
      <div class="row">
        <div>
          <h2>Device in bootloader mode</h2>
          <p class="muted small-text" style="margin:0">A firmware update is in progress (installed firmware <span class="mono">{{ v.seVersion || '?' }}</span>, bootloader <span class="mono">{{ v.mcuBootloaderVersion }}</span>). Flash the MCU to finish it.</p>
        </div>
        <div class="spacer"></div>
        <button class="primary" :disabled="!!state.busy" @click="finish">Finish update</button>
      </div>
    </div>

    <div v-if="update === null" class="panel"><span class="badge ok">✓ up to date</span></div>

    <div v-if="update" class="panel">
      <div class="row">
        <h2>{{ update.final.displayName || update.final.name }} available</h2>
        <span v-if="update.shouldFlashMcu" class="badge warn">MCU update needed</span>
        <div class="spacer"></div>
        <button class="primary" :disabled="!!state.busy || !!phase" @click="start">Update firmware</button>
      </div>
      <ol class="steps small-text">
        <li :class="{ on: phase === 'osu' }">Install the OS updater (confirm on the device)</li>
        <li :class="{ on: phase === 'reboot' }">The device installs the update and restarts; this page reconnects automatically</li>
        <li v-if="update.shouldFlashMcu" :class="{ on: phase === 'mcu' }">Flash the MCU from bootloader mode</li>
      </ol>
      <p v-if="phase === 'reboot'" class="note">
        Waiting for the device… When it restarts in bootloader mode it shows up as a new USB device the
        browser has not authorized yet: click <b>Select device</b> in the header and pick it (it may be
        listed as a "Bootloader"). The update then continues automatically.
      </p>
      <h3 v-if="update.osu.notes">Release notes</h3>
      <div v-if="update.osu.notes" class="notes md" v-html="notesHtml"></div>
    </div>

    <div v-if="phase === 'done'" class="panel"><span class="badge ok">✓ update finished</span></div>
  </div>
</template>

<style scoped>
.steps { margin: 12px 0; padding-left: 20px; color: var(--ink-2); }
.steps li { padding: 2px 0; }
.steps li.on { color: var(--accent); font-weight: 600; }
.notes { max-height: 420px; overflow: auto; background: var(--panel-2); border-radius: 8px; padding: 4px 16px; font-size: 13.5px; line-height: 1.6; }
.md :deep(h1), .md :deep(h2), .md :deep(h3) { font-size: 14px; margin: 14px 0 6px; text-transform: none; letter-spacing: 0; color: var(--ink); }
.md :deep(p) { margin: 8px 0; }
.md :deep(ul), .md :deep(ol) { margin: 6px 0; padding-left: 22px; }
.md :deep(li) { margin: 2px 0; }
.md :deep(em) { color: var(--ink-2); }
.md :deep(code) { background: var(--panel); padding: 1px 4px; border-radius: 4px; }
.md :deep(hr) { border: 0; border-top: 1px solid var(--line); margin: 12px 0; }
</style>
