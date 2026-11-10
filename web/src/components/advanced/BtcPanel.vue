<script setup>
import { ref, reactive, computed } from 'vue'
import { state, run, log, errorText } from '../../lib/store.js'
import { Esplora, satsToBtc, btcToSats } from '../../lib/net.js'
import { btcDeriveAddresses, btcEstimateVsize } from '../../pkg/lsdk.js'
import AppGate from './AppGate.vue'

const networks = [
  { id: 'main', name: 'Bitcoin mainnet', testnet: false, api: 'https://mempool.space/api', explorer: 'https://mempool.space/tx/' },
  { id: 'testnet4', name: 'Testnet4', testnet: true, api: 'https://mempool.space/testnet4/api', explorer: 'https://mempool.space/testnet4/tx/' },
  { id: 'signet', name: 'Signet', testnet: true, api: 'https://mempool.space/signet/api', explorer: 'https://mempool.space/signet/tx/' },
]
const kinds = [
  { id: 'segwit', name: 'Native SegWit (BIP84, bc1q…)', purpose: 84 },
  { id: 'taproot', name: 'Taproot (BIP86, bc1p…)', purpose: 86 },
  { id: 'nested', name: 'Nested SegWit (BIP49, 3…)', purpose: 49 },
  { id: 'legacy', name: 'Legacy (BIP44, 1…)', purpose: 44 },
]
const DUST = 546
const GAP = 10

const error = ref(null)
const netId = ref('main')
const kind = ref('segwit')
const accountIdx = ref(0)
const apiUrl = ref(networks[0].api)
const account = ref(null)
const addrs = ref({ receive: [], change: [] })
const utxos = ref([])
const scanning = ref(false)
const send = reactive({ to: '', amount: '', feeRate: '', max: false })
const result = ref(null)
const broadcastId = ref(null)
const message = reactive({ index: 0, text: '', sig: null })
const psbt = reactive({ input: '', out: null })

const net = computed(() => networks.find((n) => n.id === netId.value))
const appName = computed(() => (net.value.testnet ? 'Bitcoin Test' : 'Bitcoin'))
const balance = computed(() => utxos.value.reduce((s, u) => s + u.value, 0))
const coin = computed(() => (net.value.testnet ? 1 : 0))
const msgPath = computed(() => `m/${kinds.find((k) => k.id === kind.value).purpose}'/${coin.value}'/${accountIdx.value}'/0/${message.index}`)

function onNet() {
  apiUrl.value = net.value.api
  account.value = null
  utxos.value = []
  addrs.value = { receive: [], change: [] }
}

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const loadAccount = () => guard(async () => {
  account.value = await run('load account', (d) => d.btcAccount(kind.value, Number(accountIdx.value), net.value.testnet))
  log('info', `account ${account.value.path}`)
  await scan()
})

async function scanChain(api, change) {
  const out = []
  let unused = 0
  for (let start = 0; unused < GAP && start < 200; start += GAP) {
    const list = btcDeriveAddresses(account.value.xpub, kind.value, net.value.testnet, change, start, GAP)
    const infos = await Promise.all(list.map((a) => api.addressInfo(a)))
    infos.forEach((info, i) => {
      const txs = info.chain_stats.tx_count + info.mempool_stats.tx_count
      const bal = info.chain_stats.funded_txo_sum - info.chain_stats.spent_txo_sum + info.mempool_stats.funded_txo_sum - info.mempool_stats.spent_txo_sum
      out.push({ index: start + i, address: list[i], txs, balance: bal })
      unused = txs ? 0 : unused + 1
    })
  }
  return out
}

const scan = () => guard(async () => {
  scanning.value = true
  try {
    const api = new Esplora(apiUrl.value)
    const [receive, change] = await Promise.all([scanChain(api, 0), scanChain(api, 1)])
    addrs.value = { receive, change }
    const found = []
    for (const [chain, list] of [[0, receive], [1, change]]) {
      for (const a of list.filter((a) => a.txs > 0)) {
        for (const u of await api.utxos(a.address)) found.push({ ...u, change: chain, index: a.index, address: a.address })
      }
    }
    utxos.value = found
    log('info', `${found.length} UTXOs, ${satsToBtc(balance.value)} BTC`)
    if (!send.feeRate) {
      const f = await api.fees().catch(() => null)
      if (f) send.feeRate = String(f.halfHourFee)
    }
  } finally {
    scanning.value = false
  }
})

const nextReceive = computed(() => addrs.value.receive.find((a) => a.txs === 0))
const nextChange = computed(() => addrs.value.change.find((a) => a.txs === 0) ?? { index: 0 })

const verify = (a, change) => guard(async () => {
  const shown = await run('verify address', (d) => {
    state.prompt = 'Compare the address on the device'
    return d.btcAddress(kind.value, Number(accountIdx.value), net.value.testnet, change, a.index, true)
  })
  if (shown !== a.address) throw new Error(`device returned ${shown}, expected ${a.address}`)
  log('ok', `address ${a.index} verified`)
})

function selectCoins(amount, rate, max) {
  const sorted = [...utxos.value].sort((a, b) => b.value - a.value)
  if (max) {
    const fee = Math.ceil(btcEstimateVsize(kind.value, sorted.length, 1) * rate)
    return { inputs: sorted, amount: balance.value - fee, fee, change: 0 }
  }
  const inputs = []
  let total = 0
  for (const u of sorted) {
    inputs.push(u)
    total += u.value
    const fee = Math.ceil(btcEstimateVsize(kind.value, inputs.length, 2) * rate)
    if (total >= amount + fee) {
      let change = total - amount - fee
      if (change < DUST) {
        return { inputs, amount, fee: total - amount, change: 0 }
      }
      return { inputs, amount, fee, change }
    }
  }
  throw new Error('insufficient funds')
}

const build = () => guard(async () => {
  result.value = null
  broadcastId.value = null
  const rate = Number(send.feeRate)
  if (!(rate > 0)) throw new Error('set a fee rate')
  const sel = selectCoins(send.max ? 0 : btcToSats(send.amount), rate, send.max)
  if (sel.amount < DUST) throw new Error('amount too small')
  const api = new Esplora(apiUrl.value)
  const needPrev = kind.value !== 'taproot'
  const inputs = await Promise.all(sel.inputs.map(async (u) => ({
    txid: u.txid, vout: u.vout, amount: u.value, change: u.change, index: u.index,
    prevTx: needPrev ? await api.txHex(u.txid) : undefined,
  })))
  const req = {
    kind: kind.value, account: Number(accountIdx.value), testnet: net.value.testnet,
    utxos: inputs, payments: [{ address: send.to.trim(), amount: sel.amount }],
    changeIndex: sel.change ? nextChange.value.index : undefined, changeAmount: sel.change || undefined,
  }
  log('info', `sending ${satsToBtc(sel.amount)} BTC, fee ${sel.fee} sat, change ${sel.change} sat`)
  result.value = { ...(await run('sign transaction', (d) => {
    state.prompt = 'Review the outputs and fee, then approve on the device'
    return d.btcSend(req)
  })), fee: sel.fee, amount: sel.amount, change: sel.change }
  log('ok', `signed ${result.value.txid}`)
})

const broadcast = () => guard(async () => {
  broadcastId.value = await new Esplora(apiUrl.value).broadcast(result.value.tx)
  log('ok', `broadcast ${broadcastId.value}`)
})

const signMessage = () => guard(async () => {
  message.sig = await run('sign message', (d) => {
    state.prompt = 'Review and sign the message on the device'
    return d.btcSignMessage(msgPath.value, message.text)
  })
})

const signPsbt = () => guard(async () => {
  psbt.out = await run('sign PSBT', (d) => {
    state.prompt = 'Review and approve on the device'
    return d.btcSignPsbt(kind.value, Number(accountIdx.value), net.value.testnet, psbt.input)
  })
})
</script>

<template>
  <div class="grid">
    <AppGate :app="appName" />
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Account</h2>
      <div class="grid cols-3">
        <div><label>Network</label><select v-model="netId" @change="onNet"><option v-for="n in networks" :key="n.id" :value="n.id">{{ n.name }}</option></select></div>
        <div><label>Address type</label><select v-model="kind" @change="account = null"><option v-for="k in kinds" :key="k.id" :value="k.id">{{ k.name }}</option></select></div>
        <div><label>Account</label><input v-model.number="accountIdx" type="number" min="0" /></div>
      </div>
      <div style="margin-top:10px"><label>Esplora API (UTXOs, fees, broadcast)</label><input v-model="apiUrl" class="mono" /></div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy || scanning" @click="loadAccount">Load account</button>
        <button v-if="account" :disabled="scanning" @click="scan">{{ scanning ? 'Scanning…' : 'Rescan' }}</button>
        <span v-if="account" class="badge accent">{{ satsToBtc(balance) }} BTC</span>
      </div>
      <dl v-if="account" class="kv" style="margin-top:12px">
        <dt>Key</dt><dd>{{ account.key }}</dd>
        <dt>Descriptor</dt><dd>{{ account.descriptor }}</dd>
      </dl>
    </div>

    <div v-if="account" class="panel">
      <div class="row"><h2>Receive</h2><div class="spacer"></div>
        <button v-if="nextReceive" class="small" :disabled="!!state.busy" @click="verify(nextReceive, false)">Verify next address on device</button>
      </div>
      <p v-if="nextReceive" class="mono">{{ nextReceive.address }} <span class="muted">(#{{ nextReceive.index }})</span></p>
      <details>
        <summary class="muted small-text">Used addresses ({{ addrs.receive.filter(a => a.txs).length + addrs.change.filter(a => a.txs).length }})</summary>
        <table>
          <thead><tr><th>Chain</th><th>#</th><th>Address</th><th>Balance</th><th></th></tr></thead>
          <tbody>
            <template v-for="(list, chain) in [addrs.receive, addrs.change]" :key="chain">
              <tr v-for="a in list.filter(a => a.txs)" :key="chain + '-' + a.index">
                <td class="muted">{{ chain ? 'change' : 'receive' }}</td><td>{{ a.index }}</td>
                <td class="mono">{{ a.address }}</td><td class="mono">{{ satsToBtc(a.balance) }}</td>
                <td><button class="small" :disabled="!!state.busy" @click="verify(a, !!chain)">Verify</button></td>
              </tr>
            </template>
          </tbody>
        </table>
      </details>
    </div>

    <div v-if="account" class="panel">
      <h2>Send</h2>
      <div class="grid cols-3">
        <div><label>To address</label><input v-model="send.to" class="mono" /></div>
        <div><label>Amount (BTC)</label><input v-model="send.amount" :disabled="send.max" placeholder="0.0" /></div>
        <div><label>Fee rate (sat/vB)</label><input v-model="send.feeRate" /></div>
      </div>
      <div class="row" style="margin-top:12px">
        <label class="check"><input type="checkbox" v-model="send.max" /> send everything</label>
        <div class="spacer"></div>
        <button class="primary" :disabled="!!state.busy || !send.to || (!send.amount && !send.max) || !utxos.length" @click="build">Build &amp; sign</button>
        <button v-if="result" :disabled="!!broadcastId" @click="broadcast">Broadcast</button>
        <a v-if="broadcastId" :href="net.explorer + broadcastId" target="_blank" rel="noopener">view on explorer</a>
      </div>
      <template v-if="result">
        <h3>Signed transaction</h3>
        <dl class="kv">
          <dt>Txid</dt><dd>{{ result.txid }}</dd>
          <dt>Amount</dt><dd>{{ satsToBtc(result.amount) }} BTC</dd>
          <dt>Fee</dt><dd>{{ result.fee }} sat</dd>
          <dt>Change</dt><dd>{{ result.change ? satsToBtc(result.change) + ' BTC' : 'none' }}</dd>
        </dl>
        <div class="out" style="margin-top:8px">{{ result.tx }}</div>
        <details style="margin-top:8px"><summary class="muted small-text">Signed PSBT</summary><div class="out">{{ result.signedPsbt }}</div></details>
      </template>
    </div>

    <div class="grid cols-2">
      <div class="panel">
        <h2>Sign message</h2>
        <label>Address index (receive chain) · <span class="mono">{{ msgPath }}</span></label>
        <input v-model.number="message.index" type="number" min="0" />
        <label style="margin-top:8px">Message</label>
        <textarea v-model="message.text" rows="3"></textarea>
        <div class="row" style="margin-top:8px"><button :disabled="!!state.busy || !message.text" @click="signMessage">Sign</button></div>
        <div v-if="message.sig" class="out" style="margin-top:8px">{{ message.sig }}</div>
      </div>
      <div class="panel">
        <h2>Sign PSBT</h2>
        <p class="muted small-text" style="margin-top:0">Base64 PSBT spending from the account above (default single-sig policy).</p>
        <textarea v-model="psbt.input" rows="4" placeholder="cHNidP8B…"></textarea>
        <div class="row" style="margin-top:8px"><button :disabled="!!state.busy || !psbt.input" @click="signPsbt">Sign</button></div>
        <template v-if="psbt.out">
          <label style="margin-top:8px">Signed PSBT</label><div class="out">{{ psbt.out.signedPsbt }}</div>
          <template v-if="psbt.out.tx"><label style="margin-top:8px">Final transaction</label><div class="out">{{ psbt.out.tx }}</div></template>
        </template>
      </div>
    </div>
  </div>
</template>
