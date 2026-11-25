<script setup>
import { ref, computed } from 'vue'
import { state, run, hsmEvent, log, errorText, waitDevice, flashWhileBootloader, finishBootloaderUpdate, finishFirmwareUpdate, needsFinalInstall, ENTER_BOOTLOADER, RESTART_OS } from '../lib/store.js'
import { renderMarkdown } from '../lib/markdown.js'

const error = ref(null)
const update = ref(undefined) // undefined: not checked, null: up to date
const phase = computed({ get: () => state.fwPhase, set: (v) => { state.fwPhase = v } })
const v = computed(() => state.info?.version)
const needsFinal = computed(() => needsFinalInstall(update.value))
const notesHtml = computed(() => renderMarkdown(update.value?.osu?.notes))

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e); phase.value = null }
}

const check = () => guard(async () => {
  update.value = await run('check firmware', (d) => d.checkFirmware())
  log('info', update.value ? `firmware ${update.value.final.name} available` : 'firmware is up to date')
})

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
    log('ok', 'OS updater installed, the device restarts')
    await waitDevice('reboot')
  } else if (v.value?.isOsu) {
    log('info', `the device runs the OS updater: continuing the update to ${u.final.name}`)
  }
  // Devices that enter bootloader mode by themselves; otherwise
  // finishFirmwareUpdate asks for it (Nano S).
  if (!u.shouldFlashMcu) await flashWhileBootloader(u)
  await finishFirmwareUpdate(u)
  phase.value = 'done'
  update.value = undefined
  log('ok', `firmware is now ${state.info?.version?.seVersion ?? state.info?.app?.version ?? 'updated'}`)
})

// The device restarted in bootloader mode again: its OS cannot start.
const stuck = ref(false)
const finish = (force = false) => guard(async () => {
  stuck.value = (await finishBootloaderUpdate({ force })) === 'stuck'
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
          <p class="muted small-text" style="margin:0">A firmware update may be in progress (installed firmware <span class="mono">{{ v.seVersion || '?' }}</span>, bootloader <span class="mono">{{ v.mcuBootloaderVersion }}</span>). The bootloader does not tell which MCU the firmware needs: restart the device into its OS first.</p>
        </div>
        <div class="spacer"></div>
        <button v-if="stuck" :disabled="!!state.busy" @click="finish(true)">Flash MCU</button>
        <button class="primary" :disabled="!!state.busy" @click="finish(false)">{{ stuck ? 'Restart again' : 'Restart device' }}</button>
      </div>
      <p v-if="stuck" class="note">The device restarted in bootloader mode again: its OS cannot start without an MCU update. <b>Flash MCU</b> installs the MCU this bootloader supports.</p>
    </div>

    <div v-if="phase === 'restartOs'" class="panel">
      <p class="note" style="margin:0"><b>{{ RESTART_OS }}.</b> If the page does not pick it up, click <b>Select device</b> in the header and pick it.</p>
    </div>

    <div v-if="v?.isOsu && !phase && update === undefined" class="panel">
      <p class="muted small-text" style="margin:0">The device runs the OS updater: a firmware update is in progress. <b>Check for updates</b>, then <b>Update firmware</b> to finish it.</p>
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
        <li v-if="!v?.isOsu" :class="{ on: phase === 'osu' }">Install the OS updater (confirm on the device)</li>
        <li :class="{ on: phase === 'reboot' }">The device restarts; this page reconnects automatically</li>
        <li v-if="update.shouldFlashMcu" :class="{ on: phase === 'enterBootloader' || phase === 'mcu' }">Flash the MCU from bootloader mode</li>
        <li v-if="needsFinal" :class="{ on: phase === 'final' }">Install firmware {{ update.final.name }} from the OS updater (the device shows "Update")</li>
      </ol>
      <p v-if="phase === 'enterBootloader'" class="note">
        <b>{{ ENTER_BOOTLOADER }}.</b> It shows up as a new USB device the browser has not authorized
        yet: click <b>Select device</b> in the header and pick it (it may be listed as a "Bootloader").
        If the device enters bootloader mode by itself, there is nothing to do.
      </p>
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
