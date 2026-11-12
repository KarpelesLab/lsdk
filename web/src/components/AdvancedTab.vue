<script setup>
import { ref, watch } from 'vue'
import { state } from '../lib/store.js'
import EthPanel from './advanced/EthPanel.vue'
import BtcPanel from './advanced/BtcPanel.vue'
import SolPanel from './advanced/SolPanel.vue'
import ApduPanel from './advanced/ApduPanel.vue'
import ScreensaverPanel from './advanced/ScreensaverPanel.vue'
import DeveloperPanel from './advanced/DeveloperPanel.vue'
import EndorsementPanel from './advanced/EndorsementPanel.vue'
import FactoryPanel from './advanced/FactoryPanel.vue'
import RecoverPanel from './advanced/RecoverPanel.vue'
import OnboardPanel from './advanced/OnboardPanel.vue'

const panels = [
  { id: 'eth', label: 'Ethereum / EVM', comp: EthPanel },
  { id: 'btc', label: 'Bitcoin', comp: BtcPanel },
  { id: 'sol', label: 'Solana', comp: SolPanel },
  { id: 'developer', label: 'Developer', comp: DeveloperPanel },
  { id: 'screensaver', label: 'Screensaver', comp: ScreensaverPanel },
  { id: 'recover', label: 'Seed backup', comp: RecoverPanel },
  { id: 'onboard', label: 'Test onboarding', comp: OnboardPanel },
  { id: 'endorsement', label: 'Endorsement', comp: EndorsementPanel },
  { id: 'factory', label: 'Factory', comp: FactoryPanel },
  { id: 'apdu', label: 'Raw APDU', comp: ApduPanel },
]
const sel = ref('eth')
// In recovery mode, the screensaver is what can be done here (or host
// onboarding, on a wiped device).
watch(
  () => [state.info?.version?.flags?.isInRecoveryMode, state.info?.version?.flags?.isOnboarded],
  ([rec, onboarded]) => { if (rec) sel.value = onboarded === false ? 'onboard' : 'screensaver' },
  { immediate: true },
)
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
