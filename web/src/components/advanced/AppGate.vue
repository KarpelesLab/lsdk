<script setup>
// Shows which app is running and offers to open the required one.
import { ref, computed } from 'vue'
import { state, ensureApp, errorText, refreshInfo, run } from '../../lib/store.js'

const props = defineProps({ app: { type: String, required: true } })
const error = ref(null)
const running = computed(() => state.info?.app?.name)
const ok = computed(() => running.value === props.app)

async function open() {
  error.value = null
  try { await ensureApp(props.app) } catch (e) { error.value = errorText(e) }
}
async function refresh() {
  error.value = null
  try { await run('refresh', () => refreshInfo()) } catch (e) { error.value = errorText(e) }
}
</script>

<template>
  <div class="gate row">
    <span class="badge" :class="ok ? 'ok' : 'warn'">{{ ok ? `${app} app open` : `running: ${running || 'unknown'}` }}</span>
    <span v-if="ok" class="muted small-text">v{{ state.info.app.version }}</span>
    <div class="spacer"></div>
    <button class="small" :disabled="!!state.busy" @click="refresh">Refresh</button>
    <button v-if="!ok" class="small primary" :disabled="!!state.busy" @click="open">Open {{ app }}</button>
    <p v-if="error" class="error" style="width:100%;margin:6px 0 0">{{ error }}</p>
  </div>
</template>

<style scoped>
.gate { margin-bottom: 14px; }
</style>
