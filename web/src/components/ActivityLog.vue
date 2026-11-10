<script setup>
import { state } from '../lib/store.js'
const time = (d) => d.toLocaleTimeString([], { hour12: false })
</script>

<template>
  <div class="panel log">
    <div class="row head">
      <h2>Activity</h2>
      <div class="spacer"></div>
      <button class="small" :disabled="!state.log.length" @click="state.log.splice(0)">Clear</button>
    </div>
    <p v-if="!state.log.length" class="muted small-text">Operations and device events show up here.</p>
    <ol>
      <li v-for="e in state.log" :key="e.id" :class="e.level">
        <span class="t mono">{{ time(e.t) }}</span>
        <span class="m">{{ e.msg }}</span>
      </li>
    </ol>
  </div>
</template>

<style scoped>
.log { max-height: calc(100vh - 110px); overflow: auto; padding: 14px 16px; }
.head h2 { margin: 0; }
ol { list-style: none; margin: 8px 0 0; padding: 0; }
li { display: grid; grid-template-columns: max-content 1fr; gap: 10px; padding: 5px 0; border-bottom: 1px dashed var(--line); font-size: 12.5px; }
li:last-child { border: 0; }
.t { color: var(--ink-3); font-size: 11.5px; }
.m { word-break: break-word; }
li.error .m { color: var(--err); }
li.warn .m { color: var(--warn); }
li.ok .m { color: var(--ok); }
</style>
