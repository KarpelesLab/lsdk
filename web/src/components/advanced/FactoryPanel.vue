<script setup>
import { ref } from 'vue'
import { state, run, errorText } from '../../lib/store.js'

const tests = [
  { p1: 0x00, label: 'Start / stop test mode' },
  { p1: 0x10, label: 'Screen test' },
  { p1: 0x20, label: 'Button test' },
  { p1: 0x30, label: 'Battery test' },
  { p1: 0xd0, label: 'Read SE serial' },
  { p1: 0xe0, label: 'Reset' },
  { p1: 0xf0, label: 'Serial number' },
  { p1: 0xf1, label: 'Backup serial number' },
  { p1: 0xf2, label: 'MCU serial number' },
]
const p1 = ref(0xd0)
const p2 = ref('00')
const data = ref('')
const out = ref([])
const error = ref(null)

async function exec(label, fn) {
  error.value = null
  try {
    out.value.unshift({ label, value: await run(label, fn) })
  } catch (e) {
    error.value = errorText(e)
  }
}
const test = () => exec(`factory test 0x${p1.value.toString(16)}`, (d) => d.factoryTest(p1.value, parseInt(p2.value, 16) || 0, data.value.trim()))
const pubkey = () => exec('device public key', (d) => d.factoryPublicKey())
const cxport = () => exec('cxport', (d) => d.factoryCxport())
</script>

<template>
  <div class="grid">
    <p class="note" style="margin:0">
      Factory commands only work on devices that were <b>not personalized</b> yet (no serial number); retail devices
      refuse them. Some write permanent data (serial numbers): don't use them unless you know what you are doing.
    </p>
    <p v-if="error" class="error">{{ error }}</p>
    <div class="panel">
      <h2>Factory test</h2>
      <div class="grid cols-3">
        <div><label>Command</label><select v-model.number="p1"><option v-for="t in tests" :key="t.p1" :value="t.p1">{{ t.label }} (0x{{ t.p1.toString(16) }})</option></select></div>
        <div><label>P2 (hex)</label><input v-model="p2" class="mono" /></div>
        <div><label>Data (hex)</label><input v-model="data" class="mono" /></div>
      </div>
      <div class="row" style="margin-top:10px">
        <button :disabled="!!state.busy" @click="test">Send</button>
        <div class="spacer"></div>
        <button class="small" :disabled="!!state.busy" @click="pubkey">Get device public key</button>
        <button class="small" :disabled="!!state.busy" @click="cxport">Get cxport</button>
      </div>
    </div>
    <div v-if="out.length" class="panel">
      <div v-for="(o, i) in out" :key="i" class="small-text" style="margin-bottom:6px"><b>{{ o.label }}</b>: <span class="mono" style="word-break:break-all">{{ o.value || '(empty)' }}</span></div>
    </div>
  </div>
</template>
