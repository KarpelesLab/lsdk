<script setup>
import { ref, computed } from 'vue'
import { state, run, log, errorText, refreshInfo } from '../../lib/store.js'

const error = ref(null)
const current = ref(undefined) // undefined: not read, null: default screensaver
const text = ref('')
const animation = ref('classic')
const speed = ref('normal')

const v = computed(() => state.info?.version)
const recovery = computed(() => !!v.value?.flags?.isInRecoveryMode)
const supported = computed(() => ['Nano X', 'Nano S Plus'].includes(state.info?.model))
const valid = computed(() => text.value.length >= 1 && text.value.length <= 52 && /^[\x20-\x7e]*$/.test(text.value))

const animations = [
  { id: 'classic', label: 'Back and forth' },
  { id: 'circle-rl', label: 'Loop, right to left' },
  { id: 'circle-lr', label: 'Loop, left to right' },
]
const speeds = ['fast', 'normal', 'slow']

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const read = () => guard(async () => {
  current.value = await run('read screensaver', (d) => d.getScreenSaver())
  if (current.value) {
    text.value = current.value.text
    if (current.value.animation) animation.value = { classic: 'classic', circleRightToLeft: 'circle-rl', circleLeftToRight: 'circle-lr' }[current.value.animation]
    if (current.value.speed) speed.value = current.value.speed
  }
})

const save = () => guard(async () => {
  await run('set screensaver', (d) => {
    state.prompt = 'Confirm the new screensaver on the device'
    return d.setScreenSaver(text.value, animation.value, speed.value)
  })
  current.value = { text: text.value, animation: animation.value, speed: speed.value }
  log('ok', `screensaver set to "${text.value}"`)
})

const reset = () => guard(async () => {
  await run('reset screensaver', (d) => {
    state.prompt = 'Confirm restoring the default screensaver on the device'
    return d.resetScreenSaver()
  })
  current.value = null
  log('ok', 'default screensaver restored')
})

const refresh = () => guard(() => run('refresh', () => refreshInfo()))
</script>

<template>
  <div class="grid">
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="!supported" class="panel">
      <h2>Screensaver</h2>
      <p class="muted">A custom screensaver is available on the Nano X and Nano S Plus.</p>
    </div>

    <div v-else-if="!recovery" class="panel">
      <div class="row">
        <h2>Screensaver</h2>
        <div class="spacer"></div>
        <button class="small" :disabled="!!state.busy" @click="refresh">Refresh</button>
      </div>
      <p>The screensaver text can only be changed while the device is in <b>recovery mode</b>.</p>
      <p class="muted small-text">
        To enter it, hold the right button while plugging in (Nano S Plus) or powering on (Nano X) until the
        recovery menu appears, then reconnect from this page.
      </p>
    </div>

    <div v-else class="panel">
      <div class="row">
        <h2>Screensaver</h2>
        <span class="badge accent">recovery mode</span>
        <div class="spacer"></div>
        <button class="small" :disabled="!!state.busy" @click="read">Read current</button>
      </div>
      <p v-if="current === null" class="muted small-text">The device uses the default screensaver.</p>
      <p v-else-if="current" class="muted small-text">Current: <span class="mono">{{ current.text }}</span></p>

      <div class="grid cols-3" style="margin-top:8px">
        <div style="grid-column: span 3">
          <label>Text ({{ text.length }}/52, printable ASCII)</label>
          <input v-model="text" maxlength="52" placeholder="Scrolling text" class="mono" />
        </div>
        <div>
          <label>Animation</label>
          <select v-model="animation"><option v-for="a in animations" :key="a.id" :value="a.id">{{ a.label }}</option></select>
        </div>
        <div>
          <label>Speed</label>
          <select v-model="speed"><option v-for="s in speeds" :key="s" :value="s">{{ s }}</option></select>
        </div>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy || !valid" @click="save">Set screensaver</button>
        <button :disabled="!!state.busy" @click="reset">Restore default</button>
      </div>
    </div>
  </div>
</template>
