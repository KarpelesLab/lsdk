// Network helpers for the advanced tab: JSON-RPC (EVM / Solana) and an
// Esplora-compatible Bitcoin API.

let rpcId = 0
export async function jsonRpc(url, method, params = []) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  })
  if (!r.ok) throw new Error(`${method}: HTTP ${r.status}`)
  const j = await r.json()
  if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`)
  return j.result
}

export const hexToBig = (h) => BigInt(h)
export const gweiStr = (wei) => {
  const s = (Number(wei) / 1e9).toFixed(3)
  return s.replace(/\.?0+$/, '') || '0'
}

// Esplora (mempool.space / blockstream) API.
export class Esplora {
  constructor(base) {
    this.base = base.replace(/\/$/, '')
  }
  async get(path, text = false) {
    const r = await fetch(this.base + path)
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`)
    return text ? r.text() : r.json()
  }
  addressInfo(a) { return this.get(`/address/${a}`) }
  utxos(a) { return this.get(`/address/${a}/utxo`) }
  txHex(txid) { return this.get(`/tx/${txid}/hex`, true) }
  fees() { return this.get('/v1/fees/recommended').catch(() => this.get('/fee-estimates').then((f) => ({ halfHourFee: Math.ceil(f['3'] || 2), fastestFee: Math.ceil(f['1'] || 3), hourFee: Math.ceil(f['6'] || 1) }))) }
  async broadcast(hex) {
    const r = await fetch(this.base + '/tx', { method: 'POST', body: hex })
    const t = await r.text()
    if (!r.ok) throw new Error(t)
    return t
  }
}

export function satsToBtc(s) {
  return (Number(s) / 1e8).toFixed(8)
}

export function btcToSats(v) {
  const [i, f = ''] = String(v).trim().split('.')
  if (!/^\d*$/.test(i) || !/^\d*$/.test(f) || f.length > 8) throw new Error(`invalid amount ${v}`)
  return Number(BigInt(i || '0') * 100000000n + BigInt((f + '00000000').slice(0, 8)))
}
