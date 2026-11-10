<script setup>
// Shown on any tab when the connected device is in bootloader mode (an
// interrupted or ongoing firmware update): offers to finish it right away.
import { ref, computed } from 'vue'
import { state, finishBootloaderUpdate, errorText, connect } from '../lib/store.js'

const running = ref(false)
const done = ref(false)
const error = ref(null)

const v = computed(() => state.info?.version)
const inBootloader = computed(() => state.connected && v.value?.isBootloader)
// Another flow (Firmware tab) is already handling it.
const handledElsewhere = computed(() => !running.value && state.fwPhase && state.fwPhase !== 'done')
const visible = computed(
  () => running.value || done.value || (inBootloader.value && !state.bootloaderDismissed && !handledElsewhere.value),
)
const phaseText = computed(() => {
  if (state.fwPhase === 'reboot' || state.reconnecting) return 'Waiting for the device to restart…'
  if (state.busy) return state.busy
  return 'Working…'
})

async function repair() {
  error.value = null
  running.value = true
  try {
    await finishBootloaderUpdate()
    done.value = true
  } catch (e) {
    error.value = errorText(e)
  } finally {
    running.value = false
  }
}

// The device may come back under a USB id the browser has not authorized yet.
async function pick() {
  try { await connect() } catch (e) { if (e?.name !== 'NotFoundError') error.value = errorText(e) }
}

function close() {
  if (running.value) return
  done.value = false
  error.value = null
  if (inBootloader.value) state.bootloaderDismissed = true
}
</script>

<template>
  <div v-if="visible" class="backdrop" @click.self="close">
    <div class="modal panel" role="dialog" aria-modal="true" aria-labelledby="bl-title">
      <template v-if="done">
        <h2 id="bl-title">Update finished</h2>
        <p>Your device is running firmware <span class="mono">{{ v?.seVersion || '' }}</span>. Unlock it to continue.</p>
        <div class="row"><div class="spacer"></div><button class="primary" @click="close">Close</button></div>
      </template>
      <template v-else>
        <h2 id="bl-title">Finish the firmware update</h2>
        <p>
          Your {{ state.info?.model || 'device' }} is in <b>bootloader mode</b>: a firmware update
          (<span class="mono">{{ v?.seVersion || 'unknown' }}</span>) is waiting for its MCU to be updated.
          This takes a minute; keep the device plugged in.
        </p>
        <div v-if="running" class="progress">
          <div class="row">
            <span class="spinner"></span>
            <span>{{ phaseText }}</span>
          </div>
          <div v-if="state.prompt" class="badge accent" style="margin-top:8px">{{ state.prompt }}</div>
          <div v-if="state.progress !== null" class="bar"><div :style="{ width: (state.progress * 100).toFixed(1) + '%' }"></div></div>
          <div v-if="state.reconnecting && !state.connected" class="row note small-text" style="margin-top:10px">
            <span>If nothing happens once the device has restarted, select it again.</span>
            <button class="small" @click="pick">Select device</button>
          </div>
        </div>
        <p v-if="error" class="error">{{ error }}</p>
        <div class="row">
          <button v-if="!running" @click="close">Later</button>
          <div class="spacer"></div>
          <button class="primary" :disabled="running || !!state.busy" @click="repair">{{ error ? 'Retry' : 'Finish update' }}</button>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, .45); display: grid; place-items: center; z-index: 10; padding: 16px; }
.modal { max-width: 520px; width: 100%; box-shadow: 0 20px 60px rgba(0, 0, 0, .3); }
.modal p { margin: 8px 0 14px; }
.progress { background: var(--panel-2); border-radius: 8px; padding: 12px; margin-bottom: 14px; }
.bar { height: 6px; background: var(--panel); border-radius: 99px; margin-top: 10px; overflow: hidden; }
.bar div { height: 100%; background: var(--accent); transition: width .2s; }
.spinner { width: 14px; height: 14px; border: 2px solid var(--accent-soft); border-top-color: var(--accent); border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
