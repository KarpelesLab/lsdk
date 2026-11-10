<script setup>
// Shows which app is running and offers to open the required one.
import { ref, computed } from 'vue'
import { state, ensureApp, openApp, errorText, refreshInfo, run, hsmEvent, log } from '../../lib/store.js'

const props = defineProps({ app: { type: String, required: true } })
const error = ref(null)
const running = computed(() => state.info?.app?.name)
const ok = computed(() => running.value === props.app)

const missing = ref(false)

async function open() {
  error.value = null
  missing.value = false
  try {
    await ensureApp(props.app)
  } catch (e) {
    if (e?.kind === 'NotFound') missing.value = true
    else error.value = errorText(e)
  }
}

// The app is not on the device: install it (from the dashboard), then open it.
async function installAndOpen() {
  error.value = null
  try {
    await run(`install ${props.app}`, (d) => d.installApp(props.app, (ev) => {
      if (ev.type === 'opened') log('info', `installing ${ev.app}`)
      hsmEvent(ev)
    }))
    log('ok', `${props.app} installed`)
    missing.value = false
    await openApp(props.app)
  } catch (e) {
    error.value = errorText(e)
  }
}
async function refresh() {
  error.value = null
  try { await run('refresh', () => refreshInfo()) } catch (e) { error.value = errorText(e) }
}
</script>

<template>
  <div class="gate row">
    <span v-if="state.info?.locked" class="badge warn">device locked: enter your PIN</span>
    <span v-else class="badge" :class="ok ? 'ok' : 'warn'">{{ ok ? `${app} app open` : `running: ${running || 'unknown'}` }}</span>
    <span v-if="ok" class="muted small-text">v{{ state.info.app.version }}</span>
    <div class="spacer"></div>
    <button class="small" :disabled="!!state.busy" @click="refresh">Refresh</button>
    <button v-if="!ok" class="small primary" :disabled="!!state.busy || state.info?.locked" @click="open">Open {{ app }}</button>
    <div v-if="missing" class="missing row">
      <span>The <b>{{ app }}</b> app is not installed on your device. Install it now?</span>
      <div class="spacer"></div>
      <button class="small" :disabled="!!state.busy" @click="missing = false">Cancel</button>
      <button class="small primary" :disabled="!!state.busy" @click="installAndOpen">Install &amp; open</button>
    </div>
    <p v-if="error" class="error" style="width:100%;margin:6px 0 0">{{ error }}</p>
  </div>
</template>

<style scoped>
.gate { margin-bottom: 14px; }
.missing { width: 100%; margin-top: 8px; padding: 10px 12px; border-radius: 8px; background: var(--accent-soft); font-size: 13.5px; }
</style>
