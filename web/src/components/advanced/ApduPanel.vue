<script setup>
import { ref } from 'vue'
import { state, run, errorText } from '../../lib/store.js'

const presets = [
  { label: 'Get app & version', apdu: 'b001000000' },
  { label: 'Get OS version', apdu: 'e001000000' },
  { label: 'Get device name', apdu: 'e0d2000000' },
  { label: 'Quit app', apdu: 'b0a7000000' },
]
const input = ref('b001000000')
const history = ref([])
const error = ref(null)

function decode(resp) {
  const sw = resp.slice(-4)
  const data = resp.slice(0, -4)
  let ascii = ''
  for (let i = 0; i < data.length; i += 2) {
    const c = parseInt(data.slice(i, i + 2), 16)
    ascii += c >= 32 && c < 127 ? String.fromCharCode(c) : '·'
  }
  return { sw, data, ascii }
}

async function send() {
  error.value = null
  const apdu = input.value.replace(/\s+/g, '').toLowerCase()
  try {
    const resp = await run('apdu', (d) => d.apdu(apdu), { retryOnDisconnect: false })
    history.value.unshift({ apdu, ...decode(resp), t: new Date() })
  } catch (e) {
    error.value = errorText(e)
  }
}
</script>

<template>
  <div class="grid">
    <div class="panel">
      <h2>Raw APDU</h2>
      <p class="muted small-text" style="margin-top:0">Hex encoded <code>CLA INS P1 P2 Lc data</code>. Use with care: some commands change device state.</p>
      <div class="row">
        <input v-model="input" class="mono" style="flex:1" @keydown.enter="send" />
        <button class="primary" :disabled="!!state.busy" @click="send">Send</button>
      </div>
      <div class="row" style="margin-top:8px">
        <button v-for="p in presets" :key="p.apdu" class="small" @click="input = p.apdu">{{ p.label }}</button>
      </div>
      <p v-if="error" class="error" style="margin-top:10px">{{ error }}</p>
    </div>
    <div v-if="history.length" class="panel">
      <table>
        <thead><tr><th>APDU</th><th>Response</th><th>SW</th></tr></thead>
        <tbody>
          <tr v-for="(h, i) in history" :key="i">
            <td class="mono">{{ h.apdu }}</td>
            <td class="mono" style="word-break:break-all">{{ h.data || '—' }}<div class="muted">{{ h.ascii }}</div></td>
            <td><span class="badge" :class="h.sw === '9000' ? 'ok' : 'err'">{{ h.sw }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
