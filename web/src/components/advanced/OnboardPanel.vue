<script setup>
import { ref, computed } from 'vue'
import { state, run, log, errorText, refreshInfo, waitDevice } from '../../lib/store.js'

const error = ref(null)
const pin = ref('1111')
const words = ref('')
const passphrase = ref('')
const ack = ref(false)

const flags = computed(() => state.info?.version?.flags)
const wiped = computed(() => flags.value && !flags.value.isOnboarded)
const recovery = computed(() => !!flags.value?.isInRecoveryMode)

const repeat = (w, n) => Array(n).fill(w).join(' ')
const presets = [
  { label: 'Null seed, 24 words', words: `${repeat('abandon', 23)} art` },
  { label: 'Entropy 1, 24 words', words: `${repeat('abandon', 23)} diesel` },
  { label: 'Null seed, 12 words', words: `${repeat('abandon', 11)} about` },
]

const wordCount = computed(() => words.value.trim().split(/\s+/).filter(Boolean).length)
const valid = computed(() => /^\d{4,8}$/.test(pin.value) && [12, 18, 24].includes(wordCount.value))
const canRun = computed(() => valid.value && ack.value && wiped.value && recovery.value && !state.busy)

const onboard = async () => {
  error.value = null
  try {
    await run('host onboarding', (d) => {
      state.prompt = 'Onboarding: the device can show "Processing" for a few minutes, keep it plugged in'
      return d.onboard('main', pin.value, words.value.trim().split(/\s+/).join(' '), passphrase.value)
    }, { retryOnDisconnect: false }).catch(async (e) => {
      // Some models re-enumerate while deriving the seed: never resend, just check.
      if (e?.kind !== 'Disconnected') throw e
      log('warn', 'device re-enumerated during onboarding, waiting for it')
      await waitDevice('onboarding')
    })
    await refreshInfo().catch(() => {})
    if (state.info?.version?.flags?.isOnboarded) {
      log('ok', `onboarded with a ${wordCount.value}-word test phrase`)
    } else {
      log('warn', 'onboarding sent: unlock the device, then refresh to check')
    }
    ack.value = false
  } catch (e) {
    error.value = errorText(e)
  }
}
</script>

<template>
  <div class="grid">
    <div class="danger-box">
      <strong>Test devices only.</strong> Host onboarding sends the <b>PIN and recovery phrase in clear over USB</b>,
      through this browser. Any software on this computer can read them. Never use it with a phrase that holds or will
      hold real funds: use it to put known test seeds on development devices.
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Host onboarding</h2>
      <p class="muted small-text" style="margin-top:0">
        Sets the PIN and recovery phrase from the computer, with no input on the device. The device must be
        <b>wiped</b> (3 wrong PINs) and in <b>recovery mode</b>.
      </p>
      <div class="row" style="margin-bottom:10px">
        <span class="badge" :class="wiped ? 'ok' : 'warn'">{{ wiped ? 'not onboarded' : 'already onboarded: wipe it first' }}</span>
        <span class="badge" :class="recovery ? 'ok' : 'warn'">{{ recovery ? 'recovery mode' : 'not in recovery mode' }}</span>
      </div>
      <div class="grid cols-2">
        <div>
          <label>PIN (4 to 8 digits)</label>
          <input v-model="pin" class="mono" inputmode="numeric" autocomplete="off" />
        </div>
        <div>
          <label>Passphrase (optional, attached to this PIN)</label>
          <input v-model="passphrase" autocomplete="off" />
        </div>
      </div>
      <label style="margin-top:10px">Recovery phrase ({{ wordCount }} words)</label>
      <textarea v-model="words" class="mono" rows="3" autocomplete="off" spellcheck="false"></textarea>
      <div class="row" style="margin-top:6px">
        <span class="muted small-text">Test phrases:</span>
        <button v-for="p in presets" :key="p.label" class="small" @click="words = p.words">{{ p.label }}</button>
      </div>
      <label class="check" style="margin-top:12px">
        <input v-model="ack" type="checkbox" /> I understand the PIN and phrase travel in clear over USB, and this is a test device
      </label>
      <div class="row" style="margin-top:10px">
        <button class="primary" :disabled="!canRun" @click="onboard">Onboard</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.danger-box {
  border: 1px solid var(--err);
  border-left-width: 4px;
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 13.5px;
  color: var(--ink);
}
textarea { width: 100%; box-sizing: border-box; }
</style>
