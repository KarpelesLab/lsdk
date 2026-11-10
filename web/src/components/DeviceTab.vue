<script setup>
import { ref, computed } from 'vue'
import { state, run, refreshInfo, hsmEvent, log, errorText, quitApp, isDashboard } from '../lib/store.js'

const error = ref(null)
const genuine = ref(null) // null | true | false
const battery = ref(null)
const newName = ref('')
const deviceName = ref(null)

const info = computed(() => state.info)
const v = computed(() => info.value?.version)
const onDashboard = computed(() => !info.value?.locked && (!info.value?.app || isDashboard(info.value.app.name)))
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

const readName = () => guard(async () => {
  deviceName.value = await run('read name', (d) => {
    state.prompt = 'Allow reading the device name on the device'
    return d.getName()
  })
})

// Offline attestation (no network). Extra issuer keys are kept per browser.
const offline = ref(null)
const extraKeys = ref(localStorage.getItem('lsdk.issuerKeys') || '')
const checkOffline = () => guard(async () => {
  offline.value = null
  try { localStorage.setItem('lsdk.issuerKeys', extraKeys.value) } catch { /* private mode */ }
  const keys = extraKeys.value.split(/\s+/).filter(Boolean)
  offline.value = await run('offline genuine check', (d) => d.offlineGenuineCheck((ev) => {
    if (ev.type === 'permissionRequested') {
      state.prompt = 'Compare the manager key, then allow the insecure connection on the device'
      state.promptDetail = ev.hostPublicKey
    }
    if (ev.type === 'permissionGranted') { state.prompt = null; state.promptDetail = null }
    if (ev.type === 'attesting') state.prompt = 'The device is signing its attestation (a few seconds)…'
  }, keys))
  log(offline.value.genuine ? 'ok' : 'error', offline.value.genuine
    ? `offline attestation verified (${offline.value.issuer})`
    : 'offline attestation NOT verified')
})

const loadBattery = () => guard(async () => { battery.value = await run('battery', (d) => d.battery()) })

const rename = () => guard(async () => {
  const name = newName.value.trim()
  await run('rename', async (d) => {
    state.prompt = 'Confirm the new name on the device'
    await d.setName(name)
  })
  log('ok', `renamed to ${name}`)
  deviceName.value = name
  newName.value = ''
})

const quit = () => guard(quitApp)
</script>

<template>
  <div class="grid">
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="info?.locked" class="panel">
      <h2>Device locked</h2>
      <p class="muted small-text" style="margin:0">Enter your PIN on the device; this page updates once it is unlocked.</p>
    </div>

    <div v-else-if="!onDashboard" class="panel">
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
          <dt>Name</dt><dd>
            <span v-if="deviceName !== null">{{ deviceName || '—' }}</span>
            <button v-else class="small" :disabled="!!state.busy" @click="readName">Read</button>
          </dd>
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

        <h3>Offline genuine check</h3>
        <p class="muted small-text">
          Verifies the device attestation locally, without contacting the vendor: the device certificate must be
          signed by a known issuer key, and the device must sign a fresh challenge with the certified key.
          The device will warn about an <b>insecure manager connection</b>: that's expected, nothing is installed.
        </p>
        <div class="row">
          <button :disabled="!!state.busy || !onDashboard" @click="checkOffline">Run offline check</button>
          <span v-if="offline?.genuine" class="badge ok">✓ attestation verified</span>
          <span v-else-if="offline" class="badge err">✗ not verified</span>
        </div>
        <details style="margin-top:8px">
          <summary class="muted small-text">Additional trusted issuer keys</summary>
          <textarea v-model="extraKeys" rows="2" placeholder="04… (uncompressed hex, one per line)" style="margin-top:6px"></textarea>
        </details>
        <dl v-if="offline" class="kv" style="margin-top:10px">
          <dt>Issuer</dt><dd>{{ offline.issuer || 'no known issuer key matches' }}</dd>
          <dt>Manager key allowed</dt><dd>{{ offline.hostPublicKey }}</dd>
          <dt>Proof of possession</dt><dd>{{ offline.proofOfPossession ? 'valid' : 'INVALID' }}</dd>
          <dt>Device key</dt><dd>{{ offline.devicePublicKey }}</dd>
          <dt>Signer serial</dt><dd>{{ offline.signerSerial }}</dd>
          <template v-if="!offline.issuer">
            <dt>Issuer candidates</dt>
            <dd><div v-for="c in offline.issuerCandidates" :key="c">{{ c }}</div></dd>
          </template>
        </dl>

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
