<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { state, runInApp, log, errorText } from '../../lib/store.js'
import { jsonRpc, gweiStr } from '../../lib/net.js'
import { parseUnits } from '../../pkg/lsdk.js'
import AppGate from './AppGate.vue'

const chains = [
  { id: 1, name: 'Ethereum', rpc: 'https://ethereum-rpc.publicnode.com', explorer: 'https://etherscan.io/tx/' },
  { id: 11155111, name: 'Sepolia', rpc: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io/tx/' },
  { id: 137, name: 'Polygon', rpc: 'https://polygon-bor-rpc.publicnode.com', explorer: 'https://polygonscan.com/tx/' },
  { id: 8453, name: 'Base', rpc: 'https://base-rpc.publicnode.com', explorer: 'https://basescan.org/tx/' },
  { id: 42161, name: 'Arbitrum One', rpc: 'https://arbitrum-one-rpc.publicnode.com', explorer: 'https://arbiscan.io/tx/' },
  { id: 10, name: 'Optimism', rpc: 'https://optimism-rpc.publicnode.com', explorer: 'https://optimistic.etherscan.io/tx/' },
  { id: 56, name: 'BNB Smart Chain', rpc: 'https://bsc-rpc.publicnode.com', explorer: 'https://bscscan.com/tx/' },
]

const error = ref(null)
const path = ref("m/44'/60'/0'/0/0")
const address = ref(null)
const balance = ref(null)
const config = ref(null)
const chainSel = ref(1)
const rpc = ref(chains[0].rpc)
const tx = reactive({ to: '', value: '', token: '', decimals: 18, nonce: '', gas: '21000', maxFee: '', priorityFee: '', gasPrice: '', data: '', legacy: false })
const signed = ref(null)
const sent = ref(null)
const msg = ref('')
const msgSig = ref(null)
const typed = reactive({ domain: '', message: '', sig: null })

const chain = computed(() => chains.find((c) => c.id === Number(chainSel.value)))
const chainId = ref(1)
watch(chainSel, (id) => {
  const c = chains.find((c) => c.id === Number(id))
  if (c) { rpc.value = c.rpc; chainId.value = c.id }
})

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const getAddress = (display) => guard(async () => {
  const a = await runInApp('Ethereum', display ? 'verify address' : 'get address', (d) => {
    if (display) state.prompt = 'Compare the address on the device'
    return d.ethAddress(path.value, display)
  })
  address.value = a.address
  log('info', `ETH address ${a.address}`)
  config.value = await runInApp('Ethereum', 'app config', (d) => d.ethConfig()).catch(() => null)
})

const host = computed(() => { try { return new URL(rpc.value).host } catch { return rpc.value } })

const refreshBalance = () => guard(async () => {
  balance.value = null
  try {
    const b = await jsonRpc(rpc.value, 'eth_getBalance', [address.value, 'latest'])
    balance.value = (Number(BigInt(b)) / 1e18).toFixed(6)
  } catch (e) { balance.value = null; throw e }
})

const tokenData = () => {
  // ERC-20 transfer calldata is built in Rust when `token` is set; for gas
  // estimation, build it here too.
  const to = tx.to.toLowerCase().replace(/^0x/, '').padStart(64, '0')
  const amt = BigInt(parseUnits(tx.value || '0', Number(tx.decimals))).toString(16).padStart(64, '0')
  return '0xa9059cbb' + to + amt
}

const fill = () => guard(async () => {
  if (!address.value) throw new Error('get the address first')
  const [nonce, block, tip] = await Promise.all([
    jsonRpc(rpc.value, 'eth_getTransactionCount', [address.value, 'pending']),
    jsonRpc(rpc.value, 'eth_getBlockByNumber', ['latest', false]),
    jsonRpc(rpc.value, 'eth_maxPriorityFeePerGas', []).catch(() => '0x3b9aca00'),
  ])
  tx.nonce = String(Number(BigInt(nonce)))
  const base = BigInt(block.baseFeePerGas || '0x0')
  if (base > 0n && !tx.legacy) {
    tx.priorityFee = gweiStr(BigInt(tip))
    tx.maxFee = gweiStr(base * 2n + BigInt(tip))
  } else {
    tx.legacy = true
    tx.gasPrice = gweiStr(BigInt(await jsonRpc(rpc.value, 'eth_gasPrice', [])))
  }
  const call = tx.token
    ? { from: address.value, to: tx.token, data: tokenData() }
    : { from: address.value, to: tx.to, value: '0x' + BigInt(parseUnits(tx.value || '0', 18)).toString(16), data: tx.data || '0x' }
  try {
    const g = await jsonRpc(rpc.value, 'eth_estimateGas', [call])
    tx.gas = String(Math.ceil(Number(BigInt(g)) * 1.2))
  } catch (e) { log('warn', `gas estimate: ${errorText(e)}`) }
  log('info', `nonce ${tx.nonce}, gas ${tx.gas}`)
})

const sign = () => guard(async () => {
  signed.value = null
  sent.value = null
  const input = {
    chainId: Number(chainId.value), nonce: Number(tx.nonce), to: tx.to.trim(), value: tx.value || '0', gas: Number(tx.gas),
    data: tx.data || undefined, token: tx.token || undefined, decimals: Number(tx.decimals),
    ...(tx.legacy ? { gasPrice: tx.gasPrice } : { maxFee: tx.maxFee, priorityFee: tx.priorityFee || '0' }),
  }
  signed.value = await runInApp('Ethereum', 'sign transaction', (d) => {
    state.prompt = 'Review and approve the transaction on the device'
    return d.ethSignTx(path.value, input)
  })
  log('ok', `signed ${signed.value.hash}`)
})

const broadcast = () => guard(async () => {
  sent.value = await jsonRpc(rpc.value, 'eth_sendRawTransaction', [signed.value.raw])
  log('ok', `broadcast ${sent.value}`)
})

const signMsg = () => guard(async () => {
  msgSig.value = await runInApp('Ethereum', 'sign message', (d) => {
    state.prompt = 'Review and sign the message on the device'
    return d.ethSignMessage(path.value, msg.value)
  })
})

const signTyped = () => guard(async () => {
  typed.sig = await runInApp('Ethereum', 'sign typed data', (d) => {
    state.prompt = 'Review and sign on the device'
    return d.ethSignTypedHashes(path.value, typed.domain.trim(), typed.message.trim())
  })
})
</script>

<template>
  <div class="grid">
    <AppGate app="Ethereum" />
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Account</h2>
      <div class="grid cols-3">
        <div><label>Derivation path</label><input v-model="path" class="mono" /></div>
        <div><label>Network</label>
          <select v-model="chainSel"><option v-for="c in chains" :key="c.id" :value="c.id">{{ c.name }} ({{ c.id }})</option><option value="custom">Custom</option></select>
        </div>
        <div><label>Chain id</label><input v-model.number="chainId" :disabled="chainSel !== 'custom'" /></div>
      </div>
      <div style="margin-top:10px"><label>RPC URL (used for nonce, fees, balance and broadcast)</label><input v-model="rpc" class="mono" /></div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy" @click="getAddress(false)">Get address</button>
        <button :disabled="!!state.busy" @click="getAddress(true)">Verify on device</button>
        <span v-if="address" class="mono">{{ address }}</span>
        <button v-if="address" class="small" :disabled="!rpc" :title="`sends your address to ${host}`" @click="refreshBalance">Balance via {{ host }}</button>
        <span v-if="balance !== null" class="badge">{{ balance }}</span>
        <span v-if="config" class="badge" :class="config.blindSigningEnabled ? 'warn' : ''">app {{ config.version }} · blind signing {{ config.blindSigningEnabled ? 'on' : 'off' }}</span>
      </div>
    </div>

    <div class="panel">
      <div class="row"><h2>Send</h2><div class="spacer"></div>
        <label class="check"><input type="checkbox" v-model="tx.legacy" /> legacy gas price</label>
        <button class="small" :disabled="!address || !rpc" :title="`sends your address to ${host}`" @click="fill">Fill from {{ host }}</button>
      </div>
      <div class="grid cols-2">
        <div><label>To</label><input v-model="tx.to" class="mono" placeholder="0x…" /></div>
        <div><label>Amount ({{ tx.token ? 'tokens' : 'native coin' }})</label><input v-model="tx.value" placeholder="0.0" /></div>
        <div><label>ERC-20 token contract (optional)</label><input v-model="tx.token" class="mono" placeholder="0x… (empty for native transfer)" /></div>
        <div><label>Token decimals</label><input v-model.number="tx.decimals" :disabled="!tx.token" /></div>
      </div>
      <div class="grid cols-4" style="margin-top:10px">
        <div><label>Nonce</label><input v-model="tx.nonce" /></div>
        <div><label>Gas limit</label><input v-model="tx.gas" /></div>
        <template v-if="tx.legacy"><div><label>Gas price (gwei)</label><input v-model="tx.gasPrice" /></div></template>
        <template v-else>
          <div><label>Max fee (gwei)</label><input v-model="tx.maxFee" /></div>
          <div><label>Priority fee (gwei)</label><input v-model="tx.priorityFee" /></div>
        </template>
      </div>
      <div style="margin-top:10px" v-if="!tx.token"><label>Data (hex, optional; contract calls need blind signing or clear signing support)</label><input v-model="tx.data" class="mono" placeholder="0x" /></div>
      <div class="row" style="margin-top:12px">
        <button class="primary" :disabled="!!state.busy || !tx.to || tx.nonce === ''" @click="sign">Sign transaction</button>
        <button v-if="signed" :disabled="!rpc || !!sent" @click="broadcast">Broadcast via {{ host }}</button>
        <a v-if="sent && chain" :href="chain.explorer + sent" target="_blank" rel="noopener">view on explorer</a>
      </div>
      <template v-if="signed">
        <h3>Signed transaction</h3>
        <dl class="kv"><dt>From</dt><dd>{{ signed.from }}</dd><dt>Hash</dt><dd>{{ signed.hash }}</dd></dl>
        <div class="out" style="margin-top:8px">{{ signed.raw }}</div>
      </template>
    </div>

    <div class="grid cols-2">
      <div class="panel">
        <h2>Sign message (personal_sign)</h2>
        <textarea v-model="msg" rows="3" placeholder="Message"></textarea>
        <div class="row" style="margin-top:8px"><button :disabled="!!state.busy || !msg" @click="signMsg">Sign</button></div>
        <div v-if="msgSig" class="out" style="margin-top:8px">{{ msgSig }}</div>
      </div>
      <div class="panel">
        <h2>Sign EIP-712 (hashes)</h2>
        <label>Domain separator</label><input v-model="typed.domain" class="mono" placeholder="0x… (32 bytes)" />
        <label style="margin-top:8px">Message hash</label><input v-model="typed.message" class="mono" placeholder="0x… (32 bytes)" />
        <div class="row" style="margin-top:8px"><button :disabled="!!state.busy || !typed.domain || !typed.message" @click="signTyped">Sign</button></div>
        <div v-if="typed.sig" class="out" style="margin-top:8px">{{ typed.sig }}</div>
      </div>
    </div>
  </div>
</template>
