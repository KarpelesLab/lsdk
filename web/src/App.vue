<script setup>
import { ref, onMounted, computed } from 'vue'
import { state, boot, connect, disconnect, reconnect, log, errorText } from './lib/store.js'
import DeviceTab from './components/DeviceTab.vue'
import AppsTab from './components/AppsTab.vue'
import FirmwareTab from './components/FirmwareTab.vue'
import AdvancedTab from './components/AdvancedTab.vue'
import ActivityLog from './components/ActivityLog.vue'

const tabs = [
  { id: 'device', label: 'Device', comp: DeviceTab },
  { id: 'apps', label: 'Apps', comp: AppsTab },
  { id: 'firmware', label: 'Firmware', comp: FirmwareTab },
  { id: 'advanced', label: 'Advanced', comp: AdvancedTab },
]
const tab = ref(location.hash.slice(1) || 'device')
const current = computed(() => tabs.find((t) => t.id === tab.value) ?? tabs[0])
const error = ref(null)

function select(id) {
  tab.value = id
  history.replaceState(null, '', '#' + id)
}

async function doConnect() {
  error.value = null
  try {
    await connect()
  } catch (e) {
    if (e?.name !== 'NotFoundError') error.value = errorText(e)
  }
}

async function doReconnect() {
  error.value = null
  try { await reconnect({ timeout: 4000 }) } catch (e) { error.value = errorText(e) }
}

onMounted(() => boot().catch((e) => { error.value = errorText(e); log('error', errorText(e)) }))
</script>

<template>
  <header class="top">
    <div class="brand">
      <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true"><rect x="3" y="9" width="26" height="14" rx="3" fill="var(--accent)"/><rect x="19" y="12" width="7" height="8" rx="1.5" fill="var(--bg)"/></svg>
      <div>
        <strong>lsdk</strong>
        <span class="muted small-text">hardware wallet console</span>
      </div>
    </div>
    <div class="spacer"></div>
    <template v-if="state.ready && state.supported">
      <span v-if="state.connected" class="badge ok">● {{ state.info?.model || state.device?.productName }}</span>
      <span v-else-if="state.reconnecting" class="badge warn">reconnecting…</span>
      <span v-else class="badge">not connected</span>
      <button v-if="!state.connected" class="primary" :disabled="state.reconnecting" @click="doConnect">Connect device</button>
      <button v-if="!state.connected && state.device" :disabled="state.reconnecting" @click="doReconnect">Reconnect</button>
      <button v-if="state.connected" class="small" :disabled="!!state.busy" @click="disconnect">Disconnect</button>
    </template>
  </header>

  <main class="layout">
    <section class="content">
      <div v-if="!state.ready" class="panel muted">Loading…</div>
      <div v-else-if="!state.supported" class="panel">
        <h2>WebHID is not available</h2>
        <p>This page talks to your device over USB through WebHID. Use a Chromium based browser (Chrome, Edge, Brave, Opera) on a secure origin (https or localhost).</p>
      </div>
      <template v-else>
        <p v-if="error" class="error">{{ error }}</p>
        <div v-if="!state.device" class="panel hero">
          <h2>Connect your device</h2>
          <p class="muted">Plug it over USB, unlock it with your PIN, then click <b>Connect device</b>. Everything runs in your browser; the device talks directly to the vendor's update servers for genuine checks, app installs and firmware updates.</p>
          <button class="primary" @click="doConnect">Connect device</button>
        </div>
        <template v-else>
          <nav class="tabs">
            <button v-for="t in tabs" :key="t.id" :class="{ active: tab === t.id }" @click="select(t.id)">{{ t.label }}</button>
          </nav>
          <div v-if="state.busy" class="busy panel">
            <div class="row">
              <span class="spinner"></span>
              <strong>{{ state.busy }}</strong>
              <span v-if="state.prompt" class="badge accent">{{ state.prompt }}</span>
            </div>
            <div v-if="state.progress !== null" class="bar"><div :style="{ width: (state.progress * 100).toFixed(1) + '%' }"></div></div>
          </div>
          <KeepAlive>
            <component :is="current.comp" :key="current.id" />
          </KeepAlive>
        </template>
      </template>
    </section>
    <aside class="side">
      <ActivityLog />
    </aside>
  </main>
</template>

<style scoped>
.top { display: flex; align-items: center; gap: 10px; padding: 12px 24px; border-bottom: 1px solid var(--line); background: var(--panel); position: sticky; top: 0; z-index: 2; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; }
.brand strong { font-size: 16px; margin-right: 8px; letter-spacing: .02em; }
.layout { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 20px; padding: 20px 24px; max-width: 1400px; margin: 0 auto; }
@media (max-width: 1000px) { .layout { grid-template-columns: 1fr; padding: 16px; } }
.hero { padding: 32px; }
.hero p { max-width: 60ch; }
.busy { margin-bottom: 14px; padding: 12px 16px; border-color: var(--accent); }
.bar { height: 6px; background: var(--panel-2); border-radius: 99px; margin-top: 10px; overflow: hidden; }
.bar div { height: 100%; background: var(--accent); transition: width .2s; }
.spinner { width: 14px; height: 14px; border: 2px solid var(--accent-soft); border-top-color: var(--accent); border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.side { position: sticky; top: 76px; align-self: start; }
@media (max-width: 1000px) { .side { position: static; } }
</style>
