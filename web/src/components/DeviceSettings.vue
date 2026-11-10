<script setup>
import { ref, computed } from 'vue'
import { state, run, log, errorText, reconnect, isDashboard } from '../lib/store.js'

const error = ref(null)
const installed = ref(null)
const available = ref(null)
const choice = ref('')
const mac = ref(null)
const limit = ref(100)

const langNames = ['English', 'French', 'Spanish', 'Portuguese (Brazil)', 'German', 'Russian', 'Turkish']
const v = computed(() => state.info?.version)
const onDashboard = computed(() => !state.info?.locked && (!state.info?.app || isDashboard(state.info.app.name)))
const ble = computed(() => ['Nano X', 'Stax', 'Flex', 'Nano Gen5'].includes(state.info?.model))
const currentLang = computed(() => (v.value?.languageId != null ? langNames[v.value.languageId] ?? `#${v.value.languageId}` : null))

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const loadLangs = () => guard(async () => {
  installed.value = await run('list language packs', (d) => d.listLanguagePacks())
  available.value = await run('language catalog', (d) => d.availableLanguagePacks())
  if (!choice.value && available.value.length) choice.value = available.value[0].language
})

const installLang = () => guard(async () => {
  await run(`install ${choice.value}`, (d) => {
    state.prompt = 'Confirm the language change on the device if asked'
    return d.installLanguagePack(choice.value, (i, n) => { state.progress = i / n })
  })
  log('ok', `${choice.value} language pack installed`)
  installed.value = await run('list language packs', (d) => d.listLanguagePacks())
})

async function installFile(e) {
  const f = e.target.files?.[0]
  if (!f) return
  const script = await f.text()
  e.target.value = ''
  await guard(async () => {
    await run(`install ${f.name}`, (d) => {
      state.prompt = 'Confirm the language change on the device if asked'
      return d.installLanguageScript(script, (i, n) => { state.progress = i / n })
    })
    log('ok', `${f.name} installed`)
    installed.value = await run('list language packs', (d) => d.listLanguagePacks())
  })
}

const removeLangs = () => guard(async () => {
  await run('remove language packs', (d) => d.removeLanguagePacks())
  installed.value = []
  log('ok', 'language packs removed (English)')
})

const readMac = () => guard(async () => { mac.value = await run('read MAC', (d) => d.getMac()) })

const setLimit = () => guard(async () => {
  await run('set charge limit', (d) => d.setChargeLimit(Number(limit.value)))
  log('ok', `charge limit set to ${limit.value}%`)
})

const reset = () => guard(async () => {
  if (!confirm('Restart the dashboard?')) return
  await run('reset', (d) => d.reset(), { retryOnDisconnect: false }).catch((e) => { if (e?.kind !== 'Disconnected') throw e })
  await reconnect().catch(() => {})
})
</script>

<template>
  <div class="panel">
    <h2>Settings</h2>
    <p v-if="error" class="error">{{ error }}</p>

    <h3>Language</h3>
    <p class="muted small-text" style="margin-top:0">Current: {{ currentLang ?? 'unknown' }}. Packs come from the vendor catalog and are signed.</p>
    <div class="row">
      <button :disabled="!!state.busy || !onDashboard" @click="loadLangs">Load packs</button>
      <template v-if="available">
        <select v-model="choice" style="max-width:200px">
          <option v-for="p in available" :key="p.language" :value="p.language">{{ p.language }} {{ p.version }}</option>
        </select>
        <button class="primary" :disabled="!!state.busy || !choice" @click="installLang">Install</button>
        <button :disabled="!!state.busy" @click="removeLangs">Back to English</button>
      </template>
      <label class="check" style="cursor:pointer" title="signed .apdu script of an official pack"><input type="file" accept=".apdu,.txt" style="display:none" :disabled="!!state.busy || !onDashboard" @change="installFile" /><span class="badge">From file…</span></label>
    </div>
    <p v-if="installed" class="small-text">
      Installed: <span v-if="!installed.length" class="muted">none (English)</span>
      <span v-for="p in installed" :key="p.id" class="badge" style="margin-right:4px">{{ langNames[p.id] ?? p.id }} · {{ p.size }} B</span>
    </p>

    <template v-if="ble">
      <h3>Bluetooth &amp; battery</h3>
      <div class="row">
        <button :disabled="!!state.busy" @click="readMac">Read MAC address</button>
        <span v-if="mac" class="mono">{{ mac }}</span>
      </div>
      <div class="row" style="margin-top:8px">
        <label style="margin:0">Charge limit</label>
        <input v-model.number="limit" type="number" min="1" max="100" style="max-width:90px" /> %
        <button :disabled="!!state.busy" @click="setLimit">Apply</button>
      </div>
    </template>

    <h3>Maintenance</h3>
    <button class="small" :disabled="!!state.busy" @click="reset">Restart dashboard</button>
  </div>
</template>
