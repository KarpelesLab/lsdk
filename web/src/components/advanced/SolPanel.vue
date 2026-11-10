<script setup>
import { ref, reactive } from 'vue'
import { state, run, log, errorText } from '../../lib/store.js'
import { jsonRpc } from '../../lib/net.js'
import AppGate from './AppGate.vue'

const clusters = [
  { id: 'mainnet', rpc: 'https://api.mainnet-beta.solana.com', explorer: '' },
  { id: 'devnet', rpc: 'https://api.devnet.solana.com', explorer: '?cluster=devnet' },
  { id: 'testnet', rpc: 'https://api.testnet.solana.com', explorer: '?cluster=testnet' },
]

const error = ref(null)
const path = ref("m/44'/501'/0'")
const cluster = ref('mainnet')
const rpc = ref(clusters[0].rpc)
const address = ref(null)
const balance = ref(null)
const config = ref(null)
const tx = reactive({ to: '', amount: '', blockhash: '' })
const signed = ref(null)
const sent = ref(null)

function onCluster() {
  rpc.value = clusters.find((c) => c.id === cluster.value).rpc
}

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const getAddress = (display) => guard(async () => {
  address.value = await run(display ? 'verify address' : 'get address', (d) => {
    if (display) state.prompt = 'Compare the address on the device'
    return d.solAddress(path.value, display)
  })
  log('info', `SOL address ${address.value}`)
  config.value = await run('app config', (d) => d.solConfig()).catch(() => null)
  refreshBalance()
})

async function refreshBalance() {
  try {
    const r = await jsonRpc(rpc.value, 'getBalance', [address.value])
    balance.value = (r.value / 1e9).toFixed(6)
  } catch (e) { balance.value = null; log('warn', `balance: ${errorText(e)}`) }
}

const fetchBlockhash = () => guard(async () => {
  const r = await jsonRpc(rpc.value, 'getLatestBlockhash', [{ commitment: 'finalized' }])
  tx.blockhash = r.value.blockhash
})

const sign = () => guard(async () => {
  signed.value = null
  sent.value = null
  if (!tx.blockhash) await fetchBlockhash()
  signed.value = await run('sign transfer', (d) => {
    state.prompt = 'Review and approve the transfer on the device'
    return d.solTransfer(path.value, tx.to.trim(), tx.amount, tx.blockhash)
  })
  log('ok', `signed ${signed.value.signature}`)
})

const broadcast = () => guard(async () => {
  sent.value = await jsonRpc(rpc.value, 'sendTransaction', [signed.value.base64, { encoding: 'base64' }])
  log('ok', `broadcast ${sent.value}`)
  tx.blockhash = ''
})

const explorer = (sig) => `https://explorer.solana.com/tx/${sig}${clusters.find((c) => c.id === cluster.value).explorer}`
</script>

<template>
  <div class="grid">
    <AppGate app="Solana" />
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Account</h2>
      <div class="grid cols-3">
        <div><label>Derivation path</label><input v-model="path" class="mono" /></div>
        <div><label>Cluster</label><select v-model="cluster" @change="onCluster"><option v-for="c in clusters" :key="c.id" :value="c.id">{{ c.id }}</option></select></div>
        <div><label>RPC URL</label><input v-model="rpc" class="mono" /></div>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy" @click="getAddress(false)">Get address</button>
        <button :disabled="!!state.busy" @click="getAddress(true)">Verify on device</button>
        <span v-if="address" class="mono">{{ address }}</span>
        <span v-if="balance !== null" class="badge">{{ balance }} SOL</span>
        <span v-if="config" class="badge">app {{ config.version }}</span>
      </div>
    </div>

    <div class="panel">
      <h2>Transfer SOL</h2>
      <div class="grid cols-2">
        <div><label>To</label><input v-model="tx.to" class="mono" /></div>
        <div><label>Amount (SOL)</label><input v-model="tx.amount" placeholder="0.0" /></div>
      </div>
      <div style="margin-top:10px">
        <label>Recent blockhash</label>
        <div class="row"><input v-model="tx.blockhash" class="mono" style="flex:1" placeholder="fetched automatically" /><button class="small" @click="fetchBlockhash">Fetch</button></div>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy || !tx.to || !tx.amount" @click="sign">Sign transfer</button>
        <button v-if="signed" :disabled="!!sent" @click="broadcast">Broadcast</button>
        <a v-if="sent" :href="explorer(sent)" target="_blank" rel="noopener">view on explorer</a>
      </div>
      <p class="muted small-text">A blockhash expires after ~60 seconds: broadcast promptly after signing.</p>
      <template v-if="signed">
        <h3>Signed transaction</h3>
        <dl class="kv"><dt>Signature</dt><dd>{{ signed.signature }}</dd></dl>
        <div class="out" style="margin-top:8px">{{ signed.base64 }}</div>
      </template>
    </div>
  </div>
</template>
