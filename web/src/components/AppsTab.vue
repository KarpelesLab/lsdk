<script setup>
import { ref, computed } from 'vue'
import { state, run, hsmEvent, log, errorText } from '../lib/store.js'

const error = ref(null)
const installed = ref(null)
const catalog = ref(null)
const query = ref('')
const showDev = ref(false)

const kb = (b) => (b == null ? '' : (b / 1024).toFixed(1) + ' KB')

const installedByName = computed(() => {
  const m = new Map()
  for (const a of installed.value || []) m.set(a.installed.name.toLowerCase(), a)
  return m
})

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  return (catalog.value || [])
    .filter((a) => showDev.value || !a.isDevTools)
    .filter((a) => !q || a.versionName.toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q))
    .sort((a, b) => a.versionName.localeCompare(b.versionName))
})

function statusOf(app) {
  const inst = installedByName.value.get(app.versionName.toLowerCase())
  if (!inst) return null
  return inst.installed.hash === app.hash ? 'installed' : 'update'
}

async function guard(fn) {
  error.value = null
  try { await fn() } catch (e) { error.value = errorText(e) }
}

const loadInstalled = () => guard(async () => {
  installed.value = await run('list apps', async (d) => {
    state.prompt = 'Allow the app list on the device if asked'
    return d.listApps()
  })
  log('info', `${installed.value.length} apps installed`)
})

const loadCatalog = () => guard(async () => {
  catalog.value = await run('load catalog', (d) => d.catalog())
})

const install = (name) => guard(async () => {
  await run(`install ${name}`, (d) => d.installApp(name, (ev) => {
    if (ev.type === 'opened') log('info', `installing ${ev.app}`)
    hsmEvent(ev)
  }))
  log('ok', `${name} installed`)
  await loadInstalled()
})

// Updating = uninstall the old version, then install the new one.
const update = (name) => guard(async () => {
  await run(`uninstall ${name}`, (d) => d.uninstallApp(name, hsmEvent))
  await run(`install ${name}`, (d) => d.installApp(name, hsmEvent))
  log('ok', `${name} updated`)
  await loadInstalled()
})

const uninstall = (name) => guard(async () => {
  if (!confirm(`Uninstall ${name}? Your funds are not affected (they live on the blockchain), you can reinstall it any time.`)) return
  await run(`uninstall ${name}`, (d) => d.uninstallApp(name, hsmEvent))
  log('ok', `${name} uninstalled`)
  await loadInstalled()
})

const loadAll = async () => {
  await loadCatalog()
  if (!error.value) await loadInstalled()
}
</script>

<template>
  <div class="grid">
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <div class="row">
        <h2>Installed apps</h2>
        <div class="spacer"></div>
        <button v-if="!catalog" class="primary" :disabled="!!state.busy" @click="loadAll">Load apps</button>
        <button v-else class="small" :disabled="!!state.busy" @click="loadInstalled">Refresh</button>
      </div>
      <p v-if="!installed" class="muted small-text">Listing apps needs the dashboard, and your approval on the device unless the secure connection was already allowed.</p>
      <p v-else-if="!installed.length" class="muted">No apps installed.</p>
      <table v-else>
        <thead><tr><th>App</th><th>Version</th><th>Size</th><th></th></tr></thead>
        <tbody>
          <tr v-for="a in installed" :key="a.installed.hash">
            <td><strong>{{ a.installed.name }}</strong></td>
            <td class="mono">{{ a.catalog?.version || 'unknown' }}</td>
            <td class="mono muted">{{ kb(a.catalog?.bytes) }}</td>
            <td style="text-align:right">
              <button v-if="catalog && catalog.find(c => c.versionName.toLowerCase() === a.installed.name.toLowerCase() && c.hash !== a.installed.hash)" class="small" :disabled="!!state.busy" @click="update(a.installed.name)">Update</button>
              <button class="small danger" :disabled="!!state.busy" @click="uninstall(a.installed.name)">Uninstall</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="panel" v-if="catalog">
      <div class="row">
        <h2>Catalog</h2>
        <span class="badge">{{ filtered.length }} apps</span>
        <div class="spacer"></div>
        <label class="check"><input type="checkbox" v-model="showDev" /> developer apps</label>
        <input v-model="query" placeholder="Search…" style="max-width:240px" />
      </div>
      <table>
        <thead><tr><th>App</th><th>Version</th><th>Size</th><th></th></tr></thead>
        <tbody>
          <tr v-for="a in filtered" :key="a.versionId">
            <td>
              <strong>{{ a.versionDisplayName || a.versionName }}</strong>
              <span v-if="a.parentName" class="muted small-text"> · needs {{ a.parentName }}</span>
              <div v-if="a.warning" class="small-text" style="color:var(--warn)">{{ a.warning }}</div>
            </td>
            <td class="mono">{{ a.version }}</td>
            <td class="mono muted">{{ kb(a.bytes) }}</td>
            <td style="text-align:right">
              <span v-if="statusOf(a) === 'installed'" class="badge ok">installed</span>
              <button v-else class="small" :class="{ primary: statusOf(a) === 'update' }" :disabled="!!state.busy" @click="statusOf(a) === 'update' ? update(a.versionName) : install(a.versionName)">{{ statusOf(a) === 'update' ? 'Update' : 'Install' }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
