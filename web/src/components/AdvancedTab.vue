<script setup>
import { ref } from 'vue'
import EthPanel from './advanced/EthPanel.vue'
import BtcPanel from './advanced/BtcPanel.vue'
import SolPanel from './advanced/SolPanel.vue'
import ApduPanel from './advanced/ApduPanel.vue'

const panels = [
  { id: 'eth', label: 'Ethereum / EVM', comp: EthPanel },
  { id: 'btc', label: 'Bitcoin', comp: BtcPanel },
  { id: 'sol', label: 'Solana', comp: SolPanel },
  { id: 'apdu', label: 'Raw APDU', comp: ApduPanel },
]
const sel = ref('eth')
</script>

<template>
  <div>
    <p class="note" style="margin-top:0">
      Advanced: derive addresses, build transactions and sign them on the device. Transactions are generated locally
      (outscript); signing always requires your confirmation on the device screen. Check every field on the device before approving.
      Nothing is sent to any server unless you click a button naming it (balance, fill, scan, fetch, broadcast).
    </p>
    <nav class="tabs sub">
      <button v-for="p in panels" :key="p.id" :class="{ active: sel === p.id }" @click="sel = p.id">{{ p.label }}</button>
    </nav>
    <KeepAlive>
      <component :is="panels.find((p) => p.id === sel).comp" :key="sel" />
    </KeepAlive>
  </div>
</template>
