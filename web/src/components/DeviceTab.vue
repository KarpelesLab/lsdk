<script setup>
import { ref, computed } from 'vue'
import { state, run, refreshInfo, hsmEvent, log, errorText, quitApp, isDashboard } from '../lib/store.js'

const error = ref(null)
const genuine = ref(null) // null | true | false
const battery = ref(null)
const newName = ref('')

const info = computed(() => state.info)
const v = computed(() => info.value?.version)
const onDashboard = computed(() => !info.value?.app || isDashboard(info.value.app.name))
const hasBattery = computed(() => ['Nano X', 'Stax', 'Flex', 'Nano Gen5'].includes(info.value?.model))
const hex = (n) => (n == null ? '—' : '0x' + n.toString(16).padStart(8, '0'))
const words = computed(() => v.value?.flags?.seedWordCount)

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const refresh = () => guard(() => run('refresh', () => refreshInfo()))

const checkGenuine = () => guard(async () => {
  genuine.value = null
  genuine.value = await run('genuine check', (d) => d.genuineCheck(hsmEvent))
  log(genuine.value ? 'ok' : 'error', genuine.value ? 'device is genuine' : 'genuine check FAILED')
})

const loadBattery = () => guard(async () => { battery.value = await run('battery', (d) => d.battery()) })

const rename = () => guard(async () => {
  const name = newName.value.trim()
  await run('rename', async (d) => {
    state.prompt = 'Confirm the new name on the device'
    await d.setName(name)
  })
  log('ok', `renamed to ${name}`)
  newName.value = ''
  await refreshInfo()
})

const quit = () => guard(quitApp)
</script>

<template>
  <div class="grid">
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="!onDashboard" class="panel">
      <div class="row">
        <div>
          <h2>{{ info.app.name }} {{ info.app.version }} is open</h2>
          <p class="muted small-text" style="margin:0">Firmware information and management need the dashboard.</p>
        </div>
        <div class="spacer"></div>
        <button class="primary" :disabled="!!state.busy" @click="quit">Quit app</button>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="panel">
        <div class="row">
          <h2>{{ info?.model || state.device?.productName }}</h2>
          <div class="spacer"></div>
          <button class="small" :disabled="!!state.busy" @click="refresh">Refresh</button>
        </div>
        <dl class="kv" v-if="v">
          <dt>Name</dt><dd>{{ info.name || '—' }}</dd>
          <dt>Firmware</dt><dd>{{ v.seVersion || v.rawVersion }} <span v-if="v.isOsu" class="badge warn">OS updater</span><span v-if="v.isBootloader" class="badge warn">bootloader</span></dd>
          <dt>MCU</dt><dd>{{ v.mcuSephVersion || '—' }}</dd>
          <dt>Bootloader</dt><dd>{{ v.mcuBootloaderVersion || '—' }}</dd>
          <dt>Target id</dt><dd>{{ hex(v.targetId) }}</dd>
          <dt>Hardware</dt><dd>{{ v.hwVersion }}</dd>
          <dt>Language</dt><dd>{{ v.languageId ?? '—' }}</dd>
          <dt>USB product</dt><dd>0x{{ info.productId.toString(16).padStart(4, '0') }}</dd>
        </dl>
        <p v-else class="muted">Quit the running app to read firmware details.</p>
      </div>

      <div class="panel">
        <h2>State</h2>
        <div v-if="v" class="row" style="gap:6px">
          <span class="badge" :class="v.flags.isOnboarded ? 'ok' : 'warn'">{{ v.flags.isOnboarded ? 'onboarded' : 'not onboarded' }}</span>
          <span class="badge" :class="v.flags.isPinValidated ? 'ok' : 'warn'">{{ v.flags.isPinValidated ? 'unlocked' : 'locked' }}</span>
          <span class="badge" :class="v.flags.isSecureConnectionAllowed ? 'accent' : ''">secure channel {{ v.flags.isSecureConnectionAllowed ? 'allowed' : 'not yet allowed' }}</span>
          <span v-if="words" class="badge">{{ words }}-word seed</span>
          <span v-if="v.flags.isInRecoveryMode" class="badge warn">recovery mode</span>
        </div>

        <h3>Genuine check</h3>
        <p class="muted small-text">The device proves it holds a valid attestation key to the vendor HSM. You will be asked to allow the secure connection.</p>
        <div class="row">
          <button class="primary" :disabled="!!state.busy || !onDashboard" @click="checkGenuine">Run genuine check</button>
          <span v-if="genuine === true" class="badge ok">✓ genuine</span>
          <span v-if="genuine === false" class="badge err">✗ not genuine</span>
        </div>

        <h3>Rename</h3>
        <div class="row">
          <input v-model="newName" maxlength="32" placeholder="New device name" style="flex:1" />
          <button :disabled="!!state.busy || !newName.trim() || !onDashboard" @click="rename">Rename</button>
        </div>

        <template v-if="hasBattery">
          <h3>Battery</h3>
          <div class="row">
            <button :disabled="!!state.busy" @click="loadBattery">Read battery</button>
            <span v-if="battery" class="mono small-text">{{ battery.percentage ?? '?' }}% · {{ battery.voltageMv ?? '?' }} mV · {{ battery.temperatureC ?? '?' }}°C {{ battery.charging ? '· charging' : '' }}</span>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
