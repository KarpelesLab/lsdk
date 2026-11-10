<script setup>
import { ref } from 'vue'
import { state, run, log, errorText } from '../../lib/store.js'
import { rootPublicKey } from '../../pkg/lsdk.js'

const error = ref(null)
const info = ref({})
const slot = ref(1)
const ownerKey = ref('')
const result = ref(null)

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const read = (n) => guard(async () => {
  try {
    info.value = { ...info.value, [n]: await run(`endorsement slot ${n}`, (d) => d.endorsementInfo(n)) }
  } catch (e) {
    info.value = { ...info.value, [n]: { empty: true, error: errorText(e) } }
  }
})

// Reset needs the secure channel: the CA key (if remembered) avoids the
// unknown-manager prompt.
const reset = () => guard(async () => {
  if (!confirm('Erase the endorsement keys of both slots?')) return
  let key = null
  try { key = localStorage.getItem('lsdk.caKey') } catch { /* none */ }
  await run('reset endorsement', (d) => d.secure('resetEndorsement', key, null, (ev) => {
    if (ev.type === 'permissionRequested') { state.prompt = 'Allow the manager, then confirm on the device'; state.promptDetail = ev.hostPublicKey }
    if (ev.type === 'permissionGranted') { state.prompt = null; state.promptDetail = null }
  }))
  info.value = {}
  log('ok', 'endorsement reset')
})

const setup = () => guard(async () => {
  rootPublicKey(ownerKey.value.trim()) // validates
  if (!confirm(`Create the endorsement key of slot ${slot.value}? A slot can only be set once until the device is reset.`)) return
  result.value = await run(`endorse slot ${slot.value}`, (d) => d.endorseSetup(Number(slot.value), ownerKey.value.trim()))
  log('ok', `slot ${slot.value} endorsed`)
  await read(Number(slot.value))
})
</script>

<template>
  <div class="grid">
    <p class="note" style="margin:0">
      Endorsement keys let apps prove they run on this device, certified by <b>your</b> owner key: the device creates
      the key (signed by its attestation key), you sign it (sha256(0xFE ‖ key)) and the certificate is stored in the slot.
    </p>
    <p v-if="error" class="error">{{ error }}</p>
    <div class="panel">
      <div class="row"><h2>Slots</h2><div class="spacer"></div>
        <button class="small" :disabled="!!state.busy" @click="read(1)">Read slot 1</button>
        <button class="small" :disabled="!!state.busy" @click="read(2)">Read slot 2</button>
      </div>
      <template v-for="n in [1, 2]" :key="n">
        <div v-if="info[n]" style="margin-top:10px">
          <strong>Slot {{ n }}</strong>
          <span v-if="info[n].empty" class="muted small-text"> · not set ({{ info[n].error }})</span>
          <dl v-else class="kv">
            <dt>Public key</dt><dd>{{ info[n].publicKey }}</dd>
            <dt>Certificate</dt><dd>{{ info[n].certificate }}</dd>
          </dl>
        </div>
      </template>
    </div>
    <div class="panel">
      <h2>Set up a slot</h2>
      <div class="grid cols-3">
        <div><label>Slot</label><select v-model.number="slot"><option :value="1">1</option><option :value="2">2</option></select></div>
        <div style="grid-column: span 2"><label>Owner private key (hex)</label><input v-model="ownerKey" type="password" class="mono" autocomplete="off" /></div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="primary" :disabled="!!state.busy || !ownerKey" @click="setup">Create &amp; certify</button>
        <div class="spacer"></div>
        <button class="danger" :disabled="!!state.busy" @click="reset">Reset endorsement</button>
      </div>
      <dl v-if="result" class="kv" style="margin-top:10px">
        <dt>Public key</dt><dd>{{ result.publicKey }}</dd>
        <dt>Certificate</dt><dd>{{ result.certificate }}</dd>
      </dl>
    </div>
  </div>
</template>
