<script setup>
import { ref, reactive, computed } from 'vue'
import { state, run, log, errorText, refreshInfo, reconnect } from '../lib/store.js'
import { Hw1TxSigner } from '../pkg/lsdk.js'

const error = ref(null)
const hw1 = computed(() => state.info?.hw1)
const setUp = computed(() => !!hw1.value?.setUp)

// PIN kept in memory only, sent before each operation (this device has no
// screen: the PIN is typed on the computer).
const pin = ref('')

const setup = reactive({ pin: '1111', mode: 'generate', words: '', passphrase: '', testnet: false, ack: false })
const addr = reactive({ path: "44'/0'/0'/0/0", result: null })
const msg = reactive({ path: "44'/0'/0'/0/0", text: '', signature: null, address: null })
const tx = reactive({ inputs: '', to: '', amount: '', fee: '', changePath: "44'/0'/0'/1/0", result: null, summary: null })

// Pending keyboard confirmation: { what: 'message' | 'tx', signer? }
const pending = ref(null)
const code = ref('')

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const refresh = () => guard(() => run('refresh', () => refreshInfo()))

async function unlock(d) {
  if (!pin.value) throw new Error('enter the PIN first')
  if (hw1.value?.pinAttempts !== null && hw1.value?.pinAttempts < 3) {
    if (!confirm(`Only ${hw1.value.pinAttempts} PIN attempt(s) left before the dongle erases itself. Continue?`)) throw new Error('cancelled')
  }
  await d.hw1VerifyPin(pin.value)
}

const doSetup = () => guard(async () => {
  const words = setup.mode === 'restore' ? setup.words.trim().split(/\s+/).join(' ') : null
  if (words && !setup.ack) throw new Error('acknowledge that the phrase travels in clear first')
  const typed = await run('HW.1 setup', (d) => d.hw1Setup(setup.pin, words, setup.passphrase, setup.testnet), { retryOnDisconnect: false })
  log('ok', 'HW.1 set up')
  if (typed || !words) log('warn', 'the dongle generated a seed: on the next power-ups it types it as a keyboard until the PIN is entered, have a text editor focused and back it up')
  pin.value = setup.pin
  setup.ack = false
  await refreshInfo().catch(() => {})
})

const getAddress = () => guard(async () => {
  addr.result = await run('HW.1 address', async (d) => { await unlock(d); return d.hw1Address(addr.path) }, { retryOnDisconnect: false })
  log('info', `HW.1 address ${addr.result.address}`)
})

const signMessage = () => guard(async () => {
  msg.signature = null
  const c = await run('HW.1 sign message', async (d) => {
    await unlock(d)
    msg.address = (await d.hw1Address(msg.path)).address
    return d.hw1SignMessagePrepare(msg.path, msg.text)
  }, { retryOnDisconnect: false })
  if (!c) {
    msg.signature = await run('HW.1 sign message', (d) => d.hw1SignMessageFinish(''), { retryOnDisconnect: false })
    return
  }
  if (c.kind !== 1) throw new Error('only keyboard confirmation is supported')
  pending.value = { what: 'message' }
})

function parseInputs() {
  return tx.inputs.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const m = l.match(/^([0-9a-fA-F]+):(\d+):(.+)$/)
    if (!m) throw new Error(`input line "${l.slice(0, 20)}…": expected RAW_TX_HEX:VOUT:PATH`)
    return { rawTx: m[1], vout: Number(m[2]), path: m[3] }
  })
}

let signer = null
const signTx = () => guard(async () => {
  tx.result = null
  signer = new Hw1TxSigner(parseInputs(), {
    to: tx.to.trim(), amount: Number(tx.amount), fee: Number(tx.fee), changePath: tx.changePath,
  })
  tx.summary = signer.summary()
  const r = await run('HW.1 sign transaction', async (d) => { await unlock(d); return signer.step(d) }, { retryOnDisconnect: false })
  if (r.tx) { tx.result = r.tx; return }
  if (r.confirm.kind !== 1) throw new Error('only keyboard confirmation is supported')
  pending.value = { what: 'tx' }
})

// After the power cycles: reconnect to the replugged dongle and finish.
const finish = () => guard(async () => {
  const c = code.value.trim()
  if (!c) throw new Error('enter the code the dongle typed')
  state.connected = false
  await reconnect({ timeout: 60000, exclude: state.device })
  if (pending.value.what === 'message') {
    msg.signature = await run('HW.1 sign message', (d) => d.hw1SignMessageFinish(c), { retryOnDisconnect: false })
    log('ok', 'message signed')
  } else {
    signer.setCode(c)
    const r = await run('HW.1 sign transaction', async (d) => {
      try {
        return await signer.step(d)
      } catch (e) {
        if (e?.statusCode !== '0x6982') throw e
        await d.hw1VerifyPin(pin.value)
        return signer.step(d)
      }
    }, { retryOnDisconnect: false })
    if (!r.tx) throw new Error('the dongle asked for another confirmation')
    tx.result = r.tx
    log('ok', 'transaction signed')
  }
  pending.value = null
  code.value = ''
})

const sat = (n) => `${n} sat (${(n / 1e8).toFixed(8)} BTC)`
</script>

<template>
  <div class="grid">
    <p class="note" style="margin-top:0">
      <b>Ledger HW.1 / original Nano</b> (BTChip firmware): no screen and no apps. The PIN is typed here, and
      operations are confirmed by unplugging the dongle, which then <b>types</b> a summary and a one-time code
      as a keyboard. Addresses are legacy (Base58, P2PKH).
    </p>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <div class="row"><h2 style="margin:0">Dongle</h2><div class="spacer"></div><button class="small" :disabled="!!state.busy" @click="refresh">Refresh</button></div>
      <div v-if="hw1" class="grid cols-2 small-text" style="margin-top:10px">
        <div>Firmware <b>{{ hw1.firmware.version }}</b><span v-if="hw1.firmware.loader">, loader {{ hw1.firmware.loader }}</span></div>
        <div>{{ hw1.firmware.compressedKeys ? 'compressed keys' : 'uncompressed keys' }}</div>
        <div>
          <span class="badge" :class="setUp ? 'ok' : 'warn'">{{ setUp ? 'set up' : 'not set up' }}</span>
          <span v-if="setUp" class="muted"> mode 0x{{ hw1.operationMode.toString(16).padStart(2, '0') }}</span>
        </div>
        <div v-if="hw1.pinAttempts !== null">PIN attempts left: <b>{{ hw1.pinAttempts }}</b></div>
        <div v-if="hw1.attestation">Attestation batch {{ hw1.attestation.batchId }}, key {{ hw1.attestation.derivationIndex }}</div>
      </div>
    </div>

    <div v-if="pending" class="panel confirm">
      <h2>Confirm on the dongle</h2>
      <ol class="small-text">
        <li>Unplug the dongle and open a text editor (ideally on another computer), cursor in it.</li>
        <li>Plug the dongle in: it types a summary of the {{ pending.what === 'tx' ? 'transaction' : 'message' }} and a 4-digit code. Check the summary.</li>
        <li>Plug it back into this computer and enter the code:</li>
      </ol>
      <div class="row">
        <input v-model="code" class="mono" style="max-width:8em" inputmode="numeric" autocomplete="off" placeholder="code" />
        <button class="primary" :disabled="!!state.busy" @click="finish">Continue</button>
        <button class="small" @click="pending = null">Cancel</button>
      </div>
    </div>

    <div v-if="hw1 && !setUp" class="panel">
      <h2>Set up</h2>
      <p class="muted small-text" style="margin-top:0">A new or wiped dongle (3 wrong PINs wipe it). Ledger's defaults: standard wallet mode, deterministic signatures.</p>
      <div class="grid cols-2">
        <div><label>PIN (4 to 32 characters)</label><input v-model="setup.pin" class="mono" autocomplete="off" /></div>
        <div style="align-self:end"><label class="check"><input v-model="setup.testnet" type="checkbox" /> Bitcoin testnet</label></div>
      </div>
      <div class="row" style="margin-top:10px">
        <label class="check"><input v-model="setup.mode" type="radio" value="generate" /> let the dongle generate the seed</label>
        <label class="check"><input v-model="setup.mode" type="radio" value="restore" /> restore a recovery phrase</label>
      </div>
      <p v-if="setup.mode === 'generate'" class="muted small-text">On the next power-ups the dongle types its seed as a keyboard until the PIN is entered: have a text editor focused and back it up.</p>
      <template v-else>
        <div class="danger-box small-text" style="margin-top:8px"><b>Test devices only:</b> the phrase is turned into a seed here and sent in clear over USB.</div>
        <label style="margin-top:8px">Recovery phrase</label>
        <textarea v-model="setup.words" class="mono" rows="2" spellcheck="false" autocomplete="off"></textarea>
        <label>Passphrase (optional)</label><input v-model="setup.passphrase" autocomplete="off" />
        <label class="check" style="margin-top:8px"><input v-model="setup.ack" type="checkbox" /> I understand the seed travels in clear over USB, this is a test device</label>
      </template>
      <div class="row" style="margin-top:10px"><button class="primary" :disabled="!!state.busy || (setup.mode === 'restore' && !setup.ack)" @click="doSetup">Set up</button></div>
    </div>

    <template v-if="setUp">
      <div class="panel">
        <h2>PIN</h2>
        <p class="muted small-text" style="margin-top:0">Sent before each operation. <b>3 wrong PINs erase the dongle</b>; after a wrong one, replug it.</p>
        <input v-model="pin" type="password" class="mono" style="max-width:14em" autocomplete="off" />
      </div>

      <div class="grid cols-2">
        <div class="panel">
          <h2>Address</h2>
          <label>Path</label><input v-model="addr.path" class="mono" />
          <div class="row" style="margin-top:8px"><button class="primary" :disabled="!!state.busy" @click="getAddress">Get address</button></div>
          <div v-if="addr.result" class="small-text" style="margin-top:8px">
            <div class="mono">{{ addr.result.address }}</div>
            <div class="muted mono wrap">{{ addr.result.publicKey }}</div>
          </div>
        </div>
        <div class="panel">
          <h2>Sign a message</h2>
          <label>Path</label><input v-model="msg.path" class="mono" />
          <label>Message (ASCII, up to 140 characters)</label><input v-model="msg.text" maxlength="140" />
          <div class="row" style="margin-top:8px"><button class="primary" :disabled="!!state.busy || !msg.text" @click="signMessage">Sign</button></div>
          <div v-if="msg.signature" class="small-text" style="margin-top:8px">
            <div class="mono">{{ msg.address }}</div>
            <div class="mono wrap">{{ msg.signature }}</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <h2>Sign a transaction</h2>
        <p class="muted small-text" style="margin-top:0">Legacy P2PKH: one destination, the change goes back to the change path. Nothing is broadcast.</p>
        <label>Inputs, one per line: <span class="mono">RAW_PREVIOUS_TX_HEX:VOUT:PATH</span></label>
        <textarea v-model="tx.inputs" class="mono" rows="3" spellcheck="false"></textarea>
        <div class="grid cols-2">
          <div><label>Destination (Base58)</label><input v-model="tx.to" class="mono" /></div>
          <div><label>Change path</label><input v-model="tx.changePath" class="mono" /></div>
          <div><label>Amount (sat)</label><input v-model="tx.amount" inputmode="numeric" /></div>
          <div><label>Fee (sat)</label><input v-model="tx.fee" inputmode="numeric" /></div>
        </div>
        <div class="row" style="margin-top:8px"><button class="primary" :disabled="!!state.busy || !tx.inputs || !tx.to || !tx.amount || !tx.fee" @click="signTx">Sign</button></div>
        <p v-if="tx.summary" class="small-text">Inputs {{ sat(tx.summary.total) }}, change {{ sat(tx.summary.change) }}</p>
        <div v-if="tx.result" class="small-text">
          <label>Signed transaction</label>
          <textarea class="mono" rows="4" readonly :value="tx.result"></textarea>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.confirm { border: 2px solid var(--accent); }
.danger-box { border: 1px solid var(--err); border-left-width: 4px; border-radius: 8px; padding: 8px 12px; }
.wrap { word-break: break-all; }
textarea { width: 100%; box-sizing: border-box; }
ol { padding-left: 1.4em; }
</style>
