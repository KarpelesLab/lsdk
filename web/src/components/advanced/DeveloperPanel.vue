<script setup>
import { ref, computed } from 'vue'
import { state, run, log, errorText } from '../../lib/store.js'
import { generateRootKey, rootPublicKey, appImageInfo } from '../../pkg/lsdk.js'

const STORE = 'lsdk.caKey'
const error = ref(null)
const caKey = ref('')
const remember = ref(false)
try {
  caKey.value = localStorage.getItem(STORE) || ''
  remember.value = !!caKey.value
} catch { /* storage unavailable */ }
const caName = ref('lsdk dev')
// Removal channel: the CA is installed through the Recover channel.
const useRecover = ref(true)
// Install channel: Recover unless the firmware predates it (0x650e).
const installRegular = ref(false)
const elf = ref(null) // { name, bytes, info }
const replace = ref(true)
const signApp = ref(false)
const loading = ref(null)
const mem = ref(null)
const apps = ref(null)

const recovery = computed(() => !!state.info?.version?.flags?.isInRecoveryMode)
const caPublic = computed(() => {
  try { return caKey.value.trim() ? rootPublicKey(caKey.value.trim()) : null } catch { return null }
})
const kb = (b) => (b / 1024).toFixed(1) + ' KiB'

function persist() {
  try {
    if (remember.value && caKey.value.trim()) localStorage.setItem(STORE, caKey.value.trim())
    else localStorage.removeItem(STORE)
  } catch { /* storage unavailable */ }
}

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

// Handshake events: show the key the device displays.
function scpEvent(ev) {
  if (ev.type === 'permissionRequested') {
    state.prompt = 'Allow the manager on the device (compare the key)'
    state.promptDetail = ev.hostPublicKey
  } else if (ev.type === 'permissionGranted') {
    state.prompt = null
    state.promptDetail = null
  } else if (ev.type === 'loading') {
    state.progress = ev.total ? ev.sent / ev.total : 0
    loading.value = ev
  }
}

function generate() {
  if (caKey.value && !confirm('Replace the current CA key? A device holding the old CA will only accept the new key after you install it (recovery mode).')) return
  const k = generateRootKey()
  caKey.value = k.privateKey
  persist()
  log('info', 'CA key generated: download it and keep it safe')
}

function download() {
  const blob = new Blob([caKey.value.trim() + '\n'], { type: 'text/plain' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'ca.key'
  a.click()
  URL.revokeObjectURL(a.href)
}

async function importFile(e) {
  const f = e.target.files?.[0]
  if (!f) return
  caKey.value = (await f.text()).trim()
  persist()
}

const installCa = () => guard(async () => {
  await run('install custom CA', async (d) => {
    await d.caInstall(caName.value, caPublic.value, installRegular.value, (ev) => {
      scpEvent(ev)
      if (ev.type === 'opened') state.prompt = `Confirm installing the CA "${caName.value}" on the device`
    })
  })
  log('ok', `custom CA "${caName.value}" installed`)
})

const removeCa = () => guard(async () => {
  if (!confirm('Remove the custom CA from the device?')) return
  await run('remove custom CA', (d) => d.caRemove(useRecover.value, caName.value, caPublic.value, (ev) => {
    scpEvent(ev)
    if (ev.type === 'opened') state.prompt = 'Confirm removing the CA on the device'
  }))
  log('ok', 'custom CA removed')
})

async function pickElf(e) {
  error.value = null
  const f = e.target.files?.[0]
  if (!f) return
  try {
    const bytes = new Uint8Array(await f.arrayBuffer())
    elf.value = { name: f.name, bytes, info: appImageInfo(bytes) }
  } catch (err) {
    elf.value = null
    error.value = errorText(err)
  }
}

const deviceTarget = computed(() => state.info?.version?.targetId)
const targetMismatch = computed(() => elf.value?.info?.targetId && deviceTarget.value && elf.value.info.targetId !== deviceTarget.value)

const sideload = () => guard(async () => {
  loading.value = null
  await run(`sideload ${elf.value.info.name}`, (d) => d.sideload(elf.value.bytes, caKey.value.trim(), replace.value, scpEvent, signApp.value))
  log('ok', `${elf.value.info.name} installed`)
  loading.value = null
})

const secure = (label, op, arg) => run(label, (d) => d.secure(op, caKey.value.trim() || null, arg ?? null, scpEvent))

const loadMem = () => guard(async () => { mem.value = await secure('memory info', 'memoryInfo') })
const loadApps = () => guard(async () => { apps.value = await secure('list apps', 'listApps') })
const delApp = (a) => guard(async () => {
  if (!confirm(`Delete ${a.name}?`)) return
  await secure(`delete ${a.name}`, 'deleteAppByHash', a.hash)
  apps.value = apps.value.filter((x) => x.hash !== a.hash)
  log('ok', `${a.name} deleted`)
})
const delAll = () => guard(async () => {
  if (!confirm('Delete ALL apps? (your funds are not affected, apps can be reinstalled)')) return
  await secure('delete all apps', 'deleteAllApps')
  apps.value = []
  log('ok', 'all apps deleted')
})
</script>

<template>
  <div class="grid">
    <p class="note" style="margin:0">
      Developer tools use the device's own secure channel. To sideload your apps, install a <b>custom CA</b> once
      (recovery mode), then install app ELFs through a channel authenticated with the CA key. Without a CA key, a random key is
      used and the device asks to allow an unknown manager.
    </p>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>CA key</h2>
      <p class="muted small-text" style="margin-top:0">
        The private key stays in this browser (only kept across visits if you tick "remember"). Same format as the
        CLI's <code>~/.config/lsdk/ca.key</code>.
      </p>
      <label>Private key (hex)</label>
      <input v-model="caKey" class="mono" type="password" autocomplete="off" placeholder="generate or import a key" @change="persist" />
      <div class="row" style="margin-top:8px">
        <button @click="generate">Generate</button>
        <label class="check" style="cursor:pointer"><input type="file" accept=".key,.txt" style="display:none" @change="importFile" /><span class="badge">Import file…</span></label>
        <button :disabled="!caKey" @click="download">Download</button>
        <label class="check"><input v-model="remember" type="checkbox" @change="persist" /> remember in this browser</label>
      </div>
      <p v-if="caPublic" class="small-text">Public key: <span class="mono" style="word-break:break-all">{{ caPublic }}</span></p>
      <p v-else-if="caKey" class="error small-text">Invalid private key.</p>

      <h3>Install on the device</h3>
      <p v-if="!recovery" class="muted small-text">Installing or removing the CA requires recovery mode (hold the right button while plugging in / powering on).</p>
      <div class="grid cols-2">
        <div><label>CA name (shown by the device)</label><input v-model="caName" maxlength="32" /></div>
        <div style="align-self:end"><label class="check"><input v-model="useRecover" type="checkbox" /> remove through the Recover channel</label></div>
        <div style="align-self:end"><label class="check"><input v-model="installRegular" type="checkbox" /> install through the regular channel (firmware older than Ledger Recover)</label></div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="primary" :disabled="!!state.busy || !caPublic || !recovery" @click="installCa">Install CA</button>
        <button class="danger" :disabled="!!state.busy || !recovery" @click="removeCa">Remove CA</button>
      </div>
    </div>

    <div class="panel">
      <h2>Sideload an app</h2>
      <div class="row">
        <label class="check" style="cursor:pointer"><input type="file" accept=".elf,application/octet-stream" style="display:none" @change="pickElf" /><span class="badge accent">Choose app ELF…</span></label>
        <span v-if="elf" class="mono small-text">{{ elf.name }}</span>
      </div>
      <dl v-if="elf" class="kv" style="margin-top:10px">
        <dt>App</dt><dd>{{ elf.info.name }} {{ elf.info.version || '' }}</dd>
        <dt>Flags</dt><dd>0x{{ elf.info.flags.toString(16) }}</dd>
        <dt>API level</dt><dd>{{ elf.info.apiLevel ?? '—' }}</dd>
        <dt>Target</dt><dd>{{ elf.info.targetId ? '0x' + elf.info.targetId.toString(16).padStart(8, '0') : '—' }}
          <span v-if="targetMismatch" class="badge err">not for this device</span></dd>
        <dt>Size</dt><dd>{{ kb(elf.info.imageSize) }} (data {{ elf.info.dataSize }} B)</dd>
      </dl>
      <div class="row" style="margin-top:10px">
        <label class="check"><input v-model="replace" type="checkbox" /> replace an app with the same name</label>
        <label class="check"><input v-model="signApp" type="checkbox" /> sign the app hash with the CA key</label>
        <div class="spacer"></div>
        <button class="primary" :disabled="!!state.busy || !elf || !caPublic || targetMismatch" @click="sideload">Install</button>
      </div>
      <p v-if="loading" class="mono small-text">{{ loading.sent }}/{{ loading.total }} bytes</p>
    </div>

    <div class="panel">
      <div class="row">
        <h2>Device memory &amp; apps</h2>
        <div class="spacer"></div>
        <button class="small" :disabled="!!state.busy" @click="loadMem">Memory</button>
        <button class="small" :disabled="!!state.busy" @click="loadApps">List apps</button>
        <button class="small danger" :disabled="!!state.busy" @click="delAll">Delete all apps</button>
      </div>
      <dl v-if="mem" class="kv" style="margin-top:10px">
        <dt>System</dt><dd>{{ kb(mem.systemSize) }}</dd>
        <dt>Apps</dt><dd>{{ kb(mem.applicationsSize) }}</dd>
        <dt>Free</dt><dd>{{ kb(mem.freeSize) }}</dd>
        <dt>App slots</dt><dd>{{ mem.usedAppSlots }} / {{ mem.totalAppSlots }}</dd>
      </dl>
      <table v-if="apps" style="margin-top:10px">
        <thead><tr><th>App</th><th>Flags</th><th>Hash</th><th></th></tr></thead>
        <tbody>
          <tr v-for="a in apps" :key="a.hash">
            <td><strong>{{ a.name }}</strong></td>
            <td class="mono">0x{{ a.flags.toString(16) }}</td>
            <td class="mono small-text">{{ a.hash.slice(0, 16) }}…</td>
            <td style="text-align:right"><button class="small danger" :disabled="!!state.busy" @click="delApp(a)">Delete</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
