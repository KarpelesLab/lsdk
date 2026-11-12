<script setup>
import { ref, reactive, computed } from 'vue'
import { state, run, log, errorText } from '../../lib/store.js'
import { recoverGenerateConfig } from '../../pkg/lsdk.js'

const error = ref(null)
const conf = ref(null)
const user = reactive({ first_name: '', last_name: '', birth: '', city: '' })
const backupName = ref('lsdk backup')
let storedKey = ''
try { storedKey = localStorage.getItem('lsdk.caKey') || '' } catch { /* none */ }
const caKey = ref(storedKey)
const results = ref(null)
const restoreFiles = ref([])
const deleteFiles = ref([])

const onboarded = computed(() => state.info?.version?.flags?.isOnboarded)

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

function save(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2) + '\n'], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}

const generate = () => guard(async () => {
  if (!user.first_name || !user.last_name || !user.birth) throw new Error('first name, last name and birth date are required')
  conf.value = recoverGenerateConfig({ ...user }, backupName.value)
  save('conf.json', conf.value)
  log('info', 'configuration generated and downloaded (it holds the provider keys: keep it secret)')
})

async function readJson(file) {
  return JSON.parse(await file.text())
}

const importConf = (e) => guard(async () => {
  const f = e.target.files?.[0]
  if (f) conf.value = await readJson(f)
})

function events(ev) {
  if (ev.type === 'channel') {
    const c = ev.event
    if (c.type === 'permissionRequested') { state.prompt = 'Allow the orchestrator (your CA) on the device'; state.promptDetail = c.hostPublicKey }
    if (c.type === 'permissionGranted') { state.prompt = null; state.promptDetail = null }
  } else if (ev.type === 'confirmOnDevice') {
    state.prompt = 'Check the identity shown on the device and confirm'
  } else if (ev.type === 'provider') {
    log('info', `provider ${ev.name}`)
  } else if (ev.type === 'shareVerified') {
    state.prompt = null
    log('ok', `${ev.name}: done`)
  }
}

const backup = () => guard(async () => {
  results.value = await run('seed backup', (d) => d.recoverBackup(conf.value, caKey.value.trim(), events))
  log('ok', `${results.value.length} shares created`)
})

const pickFiles = (target) => async (e) => {
  error.value = null
  try {
    target.value = await Promise.all([...(e.target.files || [])].map(readJson))
  } catch (err) {
    error.value = errorText(err)
  }
}
const pickRestore = pickFiles(restoreFiles)
const pickDelete = pickFiles(deleteFiles)

const restore = () => guard(async () => {
  await run('seed restore', (d) => d.recoverRestore(conf.value, caKey.value.trim(), restoreFiles.value, events))
  log('ok', 'seed restored')
})

const del = () => guard(async () => {
  if (!confirm('Delete these backups (the device proves each deletion)?')) return
  await run('delete backups', (d) => d.recoverDelete(conf.value, caKey.value.trim(), deleteFiles.value, events))
  log('ok', 'backups deleted')
})
</script>

<template>
  <div class="grid">
    <p class="note" style="margin:0">
      Self-hosted seed backup with the device's Recover protocol: <b>you are the backup service</b>. The seed is split
      into 3 shares (any 2 restore it), each handed to a "provider" certified by your custom CA. What is split is the
      seed encrypted with a key common to all devices, so restoring always needs a device. Requirements:
      your CA installed <b>through the Recover channel</b> (Developer tab, recovery mode). While a custom CA is
      installed, installing apps from the vendor fails: remove it when done.
    </p>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Configuration</h2>
      <p class="muted small-text" style="margin-top:0">Identity shown on the device, a backup id, and the orchestrator / provider keys (same format as the legacy <code>conf.json</code>).</p>
      <div v-if="!conf" class="grid cols-2">
        <div><label>First name</label><input v-model="user.first_name" /></div>
        <div><label>Last name</label><input v-model="user.last_name" /></div>
        <div><label>Date of birth</label><input v-model="user.birth" placeholder="12 January 1980" /></div>
        <div><label>City of birth (optional)</label><input v-model="user.city" /></div>
        <div><label>Backup name</label><input v-model="backupName" /></div>
      </div>
      <div class="row" style="margin-top:10px">
        <button v-if="!conf" class="primary" @click="generate">Generate &amp; download</button>
        <label class="check" style="cursor:pointer"><input type="file" accept=".json" style="display:none" @change="importConf" /><span class="badge">Load conf.json…</span></label>
        <span v-if="conf" class="small-text">{{ conf.user_info.first_name }} {{ conf.user_info.last_name }} · {{ conf.backup_info.backup_name }} · {{ conf.providers.length }} providers</span>
        <button v-if="conf" class="small" @click="conf = null">Change</button>
      </div>
      <label style="margin-top:10px">CA private key (hex)</label>
      <input v-model="caKey" type="password" class="mono" autocomplete="off" />
    </div>

    <div v-if="conf" class="panel">
      <h2>Backup</h2>
      <p class="muted small-text" style="margin-top:0">Device onboarded and on the dashboard.</p>
      <button class="primary" :disabled="!!state.busy || !caKey || !onboarded" @click="backup">Back up the seed</button>
      <div v-if="results" style="margin-top:10px">
        <p class="small-text">Download each provider's share and deletion key, and store them encrypted, in separate places:</p>
        <div v-for="r in results" :key="r.provider" class="row" style="margin-bottom:6px">
          <strong style="min-width:90px">{{ r.provider }}</strong>
          <button class="small" @click="save(r.provider + '.json', r.backupFile)">{{ r.provider }}.json</button>
          <button class="small" @click="save('Delete' + r.provider + '.json', r.deleteFile)">Delete{{ r.provider }}.json</button>
        </div>
      </div>
    </div>

    <div v-if="conf" class="grid cols-2">
      <div class="panel">
        <h2>Restore</h2>
        <p class="muted small-text" style="margin-top:0">On a device being set up with "restore from a backup". Select 2 or 3 share files.</p>
        <input type="file" accept=".json" multiple @change="pickRestore" />
        <div class="row" style="margin-top:8px"><button class="primary" :disabled="!!state.busy || restoreFiles.length < 2 || !caKey" @click="restore">Restore ({{ restoreFiles.length }})</button></div>
      </div>
      <div class="panel">
        <h2>Delete backups</h2>
        <p class="muted small-text" style="margin-top:0">Select DeleteBackup_N.json files: the device proves each deletion.</p>
        <input type="file" accept=".json" multiple @change="pickDelete" />
        <div class="row" style="margin-top:8px"><button class="danger" :disabled="!!state.busy || !deleteFiles.length || !caKey" @click="del">Delete ({{ deleteFiles.length }})</button></div>
      </div>
    </div>
  </div>
</template>
