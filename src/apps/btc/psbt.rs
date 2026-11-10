//! PSBT helpers: v0 to v2 maps for the app, building, and signature insertion.
//!
//! PSBT parsing and editing is done with [`outscript::psbt::Psbt`].

use outscript::btctx::{BtcTx, BtcTxInput};
use outscript::psbt::Psbt;

use super::bip32::Xpub;
use super::varint;
use super::wallet::AddressType;
use crate::error::{Error, Result};

pub type PsbtMap = Vec<(Vec<u8>, Vec<u8>)>;

fn ps_err(e: outscript::Error) -> Error {
    Error::InvalidInput(format!("psbt: {e:?}"))
}

/// The global / input / output maps in PSBTv2 form, as the app wants them.
pub struct PsbtV2Maps {
    pub global: PsbtMap,
    pub inputs: Vec<PsbtMap>,
    pub outputs: Vec<PsbtMap>,
}

/// Convert a (v0 or v2) PSBT to v2 maps.
pub fn v2_maps(bytes: &[u8]) -> Result<PsbtV2Maps> {
    let psbt = Psbt::parse(bytes).map_err(ps_err)?;
    let collect = |m: outscript::psbt::Map<'_>| -> PsbtMap {
        m.records()
            .map(|r| (r.key.to_vec(), r.value.to_vec()))
            .collect()
    };
    let mut global = collect(psbt.global());
    let mut inputs: Vec<PsbtMap> = psbt.inputs().map(|i| collect(i.map())).collect();
    let mut outputs: Vec<PsbtMap> = psbt.outputs().map(|o| collect(o.map())).collect();
    let version = psbt
        .global()
        .get_type(0xfb)
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes);
    if version == Some(2) {
        return Ok(PsbtV2Maps {
            global,
            inputs,
            outputs,
        });
    }
    let tx = psbt.unsigned_tx();
    global.retain(|(k, _)| k.as_slice() != [0x00]);
    let push = |m: &mut PsbtMap, key: u8, v: Vec<u8>| -> Result<()> {
        if m.iter().any(|(k, _)| k.as_slice() == [key]) {
            return Err(Error::InvalidInput(format!(
                "psbt: unexpected v2 field 0x{key:02x}"
            )));
        }
        m.push((vec![key], v));
        Ok(())
    };
    push(&mut global, 0x02, tx.version().to_le_bytes().to_vec())?;
    push(&mut global, 0x03, tx.locktime().to_le_bytes().to_vec())?;
    push(&mut global, 0x04, varint::encode(tx.input_count() as u64))?;
    push(&mut global, 0x05, varint::encode(tx.output_count() as u64))?;
    push(&mut global, 0xfb, 2u32.to_le_bytes().to_vec())?;
    for (m, txin) in inputs.iter_mut().zip(tx.inputs()) {
        let mut txid = txin.txid;
        txid.reverse(); // internal byte order
        push(m, 0x0e, txid.to_vec())?;
        push(m, 0x0f, txin.vout.to_le_bytes().to_vec())?;
        push(m, 0x10, txin.sequence.to_le_bytes().to_vec())?;
    }
    for (m, txout) in outputs.iter_mut().zip(tx.outputs()) {
        push(m, 0x03, txout.amount.to_le_bytes().to_vec())?;
        push(m, 0x04, txout.script.to_vec())?;
    }
    Ok(PsbtV2Maps {
        global,
        inputs,
        outputs,
    })
}

/// A signature produced by the app for one input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", tag = "kind"))]
pub enum PartialSignature {
    /// ECDSA: compressed pubkey and DER signature (with sighash byte).
    Ecdsa {
        input: usize,
        pubkey: String,
        signature: String,
    },
    /// Schnorr (taproot): x-only key, optional leaf hash, 64/65 byte signature.
    Schnorr {
        input: usize,
        pubkey: String,
        leaf_hash: Option<String>,
        signature: String,
    },
    /// Other yielded objects (MuSig2 nonces / partial signatures), raw.
    Other { input: usize, data: String },
}

/// Parse one yielded value of `SIGN_PSBT`.
pub fn parse_yielded(data: &[u8]) -> Result<PartialSignature> {
    let (tag, n) =
        varint::decode(data).ok_or_else(|| Error::InvalidResponse("bad yield".into()))?;
    if tag == 0xffff_ffff || tag == 0xffff_fffe {
        let (input, m) =
            varint::decode(&data[n..]).ok_or_else(|| Error::InvalidResponse("bad yield".into()))?;
        return Ok(PartialSignature::Other {
            input: input as usize,
            data: hex::encode(&data[n + m..]),
        });
    }
    let input = tag as usize;
    let rest = &data[n..];
    let (&aug, rest) = rest
        .split_first()
        .ok_or_else(|| Error::InvalidResponse("bad yield".into()))?;
    let aug = aug as usize;
    if aug >= rest.len() {
        return Err(Error::InvalidResponse("bad key augment length".into()));
    }
    let (key, sig) = rest.split_at(aug);
    Ok(match aug {
        64 => PartialSignature::Schnorr {
            input,
            pubkey: hex::encode(&key[..32]),
            leaf_hash: Some(hex::encode(&key[32..])),
            signature: hex::encode(sig),
        },
        32 => PartialSignature::Schnorr {
            input,
            pubkey: hex::encode(key),
            leaf_hash: None,
            signature: hex::encode(sig),
        },
        _ => PartialSignature::Ecdsa {
            input,
            pubkey: hex::encode(key),
            signature: hex::encode(sig),
        },
    })
}

/// Insert signatures into a PSBT (`PSBT_IN_PARTIAL_SIG`, `PSBT_IN_TAP_KEY_SIG`,
/// `PSBT_IN_TAP_SCRIPT_SIG`).
pub fn insert_signatures(psbt: &[u8], sigs: &[PartialSignature]) -> Result<Vec<u8>> {
    let mut cur = psbt.to_vec();
    for s in sigs {
        let (input, key, value) = match s {
            PartialSignature::Ecdsa {
                input,
                pubkey,
                signature,
            } => {
                let mut k = vec![0x02];
                k.extend(hex::decode(pubkey).unwrap_or_default());
                (*input, k, hex::decode(signature).unwrap_or_default())
            }
            PartialSignature::Schnorr {
                input,
                pubkey,
                leaf_hash: None,
                signature,
            } => {
                let _ = pubkey;
                (
                    *input,
                    vec![0x13],
                    hex::decode(signature).unwrap_or_default(),
                )
            }
            PartialSignature::Schnorr {
                input,
                pubkey,
                leaf_hash: Some(leaf),
                signature,
            } => {
                let mut k = vec![0x14];
                k.extend(hex::decode(pubkey).unwrap_or_default());
                k.extend(hex::decode(leaf).unwrap_or_default());
                (*input, k, hex::decode(signature).unwrap_or_default())
            }
            PartialSignature::Other { .. } => continue,
        };
        cur = Psbt::parse(&cur)
            .map_err(ps_err)?
            .set_input_record_to_vec(input, &key, &value)
            .map_err(ps_err)?;
    }
    Ok(cur)
}

/// Finalize every input and extract the network transaction.
pub fn finalize_and_extract(psbt: &[u8]) -> Result<Vec<u8>> {
    let (fin, _) = Psbt::parse(psbt)
        .map_err(ps_err)?
        .finalize_to_vec()
        .map_err(ps_err)?;
    Psbt::parse(&fin)
        .map_err(ps_err)?
        .extract_tx_to_vec()
        .map_err(ps_err)
}

/// A coin to spend.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Utxo {
    /// Txid in display (big endian) hex.
    pub txid: String,
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// `0` = receive, `1` = change.
    pub change: u32,
    /// Address index.
    pub index: u32,
    /// Full previous transaction (hex), recommended for non-taproot inputs.
    #[cfg_attr(feature = "serde", serde(default))]
    pub prev_tx: Option<String>,
}

/// A payment output.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct Payment {
    pub address: String,
    pub amount: u64,
}

/// What to build.
#[derive(Clone, Debug)]
pub struct SpendRequest<'a> {
    pub kind: AddressType,
    pub testnet: bool,
    pub master_fingerprint: [u8; 4],
    /// Account path, e.g. `m/84'/0'/0'`.
    pub account_path: &'a [u32],
    /// Account xpub (at `account_path`).
    pub account_xpub: &'a Xpub,
    pub utxos: &'a [Utxo],
    pub payments: &'a [Payment],
    /// Change output `(index, amount)` on the internal chain, if any.
    pub change: Option<(u32, u64)>,
    /// Signal RBF.
    pub rbf: bool,
}

fn network(testnet: bool) -> &'static str {
    if testnet {
        "bitcoin-testnet"
    } else {
        "bitcoin"
    }
}

/// Script and address of the account key at `change/index`.
pub fn derive_script(
    xpub: &Xpub,
    kind: AddressType,
    testnet: bool,
    change: u32,
    index: u32,
) -> Result<(Vec<u8>, String, [u8; 33])> {
    let child = xpub.derive_path(&[change, index])?;
    let pk = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(&child.public_key)
        .map_err(|_| Error::App("bad derived key".into()))?;
    let s = outscript::Script::new(pk);
    let fmt = kind.script_format();
    let script = s.generate(fmt).map_err(|e| Error::App(format!("{e:?}")))?;
    let addr = s
        .address(fmt, &[network(testnet)])
        .map_err(|e| Error::App(format!("{e:?}")))?;
    Ok((script, addr, child.public_key))
}

fn derivation_value(fpr: [u8; 4], path: &[u32]) -> Vec<u8> {
    let mut v = fpr.to_vec();
    for c in path {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v
}

/// Build an unsigned PSBT (v0) with the UTXO and BIP-32 information the app needs.
pub fn build_psbt(req: &SpendRequest<'_>) -> Result<Vec<u8>> {
    if req.utxos.is_empty() {
        return Err(Error::InvalidInput("no inputs".into()));
    }
    let mut tx = BtcTx {
        version: 2,
        ..Default::default()
    };
    let sequence = if req.rbf { 0xffff_fffd } else { 0xffff_ffff };
    for u in req.utxos {
        let raw = hex::decode(&u.txid)
            .map_err(|_| Error::InvalidInput(format!("bad txid {}", u.txid)))?;
        let txid: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::InvalidInput(format!("bad txid {}", u.txid)))?;
        tx.inputs.push(BtcTxInput {
            txid,
            vout: u.vout,
            sequence,
            ..Default::default()
        });
    }
    for p in req.payments {
        tx.add_net_output(network(req.testnet), &p.address, p.amount)
            .map_err(|e| Error::InvalidInput(format!("{}: {e:?}", p.address)))?;
    }
    let change_out = match req.change {
        Some((index, amount)) => {
            let (script, addr, pk) =
                derive_script(req.account_xpub, req.kind, req.testnet, 1, index)?;
            let _ = script;
            tx.add_net_output(network(req.testnet), &addr, amount)
                .map_err(|e| Error::App(format!("{e:?}")))?;
            Some((tx.outputs.len() - 1, index, pk))
        }
        None => None,
    };
    let mut psbt = tx.to_psbt().map_err(ps_err)?;
    let is_tap = req.kind == AddressType::Taproot;
    for (i, u) in req.utxos.iter().enumerate() {
        let (script, _, pk) =
            derive_script(req.account_xpub, req.kind, req.testnet, u.change, u.index)?;
        let mut path = req.account_path.to_vec();
        path.extend_from_slice(&[u.change, u.index]);
        let p = Psbt::parse(&psbt).map_err(ps_err)?;
        psbt = if req.kind == AddressType::Legacy {
            let prev = u.prev_tx.as_deref().ok_or_else(|| {
                Error::InvalidInput("legacy inputs need the previous transaction".into())
            })?;
            let prev =
                hex::decode(prev).map_err(|_| Error::InvalidInput("bad prev tx hex".into()))?;
            p.set_input_record_to_vec(i, &[0x00], &prev)
                .map_err(ps_err)?
        } else {
            p.set_witness_utxo_to_vec(i, u.amount, &script)
                .map_err(ps_err)?
        };
        if let (false, false, Some(prev)) = (req.kind == AddressType::Legacy, is_tap, &u.prev_tx) {
            let prev =
                hex::decode(prev).map_err(|_| Error::InvalidInput("bad prev tx hex".into()))?;
            psbt = Psbt::parse(&psbt)
                .map_err(ps_err)?
                .set_input_record_to_vec(i, &[0x00], &prev)
                .map_err(ps_err)?;
        }
        let p = Psbt::parse(&psbt).map_err(ps_err)?;
        psbt = if is_tap {
            let mut key = vec![0x16];
            key.extend_from_slice(&pk[1..]);
            let mut v = varint::encode(0);
            v.extend(derivation_value(req.master_fingerprint, &path));
            let tmp = p.set_input_record_to_vec(i, &key, &v).map_err(ps_err)?;
            Psbt::parse(&tmp)
                .map_err(ps_err)?
                .set_input_record_to_vec(i, &[0x17], &pk[1..])
                .map_err(ps_err)?
        } else {
            p.add_input_bip32_derivation_to_vec(i, &pk, req.master_fingerprint, &path)
                .map_err(ps_err)?
        };
    }
    if let Some((out_idx, index, pk)) = change_out {
        let mut path = req.account_path.to_vec();
        path.extend_from_slice(&[1, index]);
        let p = Psbt::parse(&psbt).map_err(ps_err)?;
        psbt = if is_tap {
            let mut key = vec![0x07];
            key.extend_from_slice(&pk[1..]);
            let mut v = varint::encode(0);
            v.extend(derivation_value(req.master_fingerprint, &path));
            let tmp = p
                .set_output_record_to_vec(out_idx, &key, &v)
                .map_err(ps_err)?;
            Psbt::parse(&tmp)
                .map_err(ps_err)?
                .set_output_record_to_vec(out_idx, &[0x05], &pk[1..])
                .map_err(ps_err)?
        } else {
            let mut key = vec![0x02];
            key.extend_from_slice(&pk);
            p.set_output_record_to_vec(
                out_idx,
                &key,
                &derivation_value(req.master_fingerprint, &path),
            )
            .map_err(ps_err)?
        };
    }
    Ok(psbt)
}

/// Rough virtual size estimate to compute fees.
pub fn estimate_vsize(kind: AddressType, n_inputs: usize, n_outputs: usize) -> u64 {
    let (input, output) = match kind {
        AddressType::Legacy => (148.0, 34.0),
        AddressType::NestedSegwit => (91.0, 32.0),
        AddressType::NativeSegwit => (68.0, 31.0),
        AddressType::Taproot => (57.5, 43.0),
    };
    (10.5 + input * n_inputs as f64 + output * n_outputs as f64).ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPUB: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";

    #[test]
    fn build_and_convert() {
        let xpub = Xpub::parse(XPUB).unwrap();
        for kind in [
            AddressType::NativeSegwit,
            AddressType::Taproot,
            AddressType::NestedSegwit,
        ] {
            let (_, dest, _) = derive_script(&xpub, kind, false, 0, 7).unwrap();
            let utxos = [Utxo {
                txid: "11".repeat(32),
                vout: 1,
                amount: 50_000,
                change: 0,
                index: 3,
                prev_tx: None,
            }];
            let payments = [Payment {
                address: dest,
                amount: 20_000,
            }];
            let path = [84 | 0x8000_0000, 0x8000_0000, 0x8000_0000];
            let req = SpendRequest {
                kind,
                testnet: false,
                master_fingerprint: [1, 2, 3, 4],
                account_path: &path,
                account_xpub: &xpub,
                utxos: &utxos,
                payments: &payments,
                change: Some((0, 29_000)),
                rbf: true,
            };
            let psbt = build_psbt(&req).unwrap();
            let maps = v2_maps(&psbt).unwrap();
            assert_eq!(maps.inputs.len(), 1);
            assert_eq!(maps.outputs.len(), 2);
            assert!(
                maps.global
                    .iter()
                    .any(|(k, v)| k == &[0xfb] && v == &2u32.to_le_bytes())
            );
            let txid = maps.inputs[0].iter().find(|(k, _)| k == &[0x0e]).unwrap();
            assert_eq!(txid.1, vec![0x11; 32]);
            // witness utxo + derivation present
            assert!(maps.inputs[0].iter().any(|(k, _)| k == &[0x01]));
            let der = if kind == AddressType::Taproot {
                0x16
            } else {
                0x06
            };
            assert!(maps.inputs[0].iter().any(|(k, _)| k[0] == der));
            assert!(maps.outputs[1].iter().any(|(k, _)| k[0]
                == if kind == AddressType::Taproot {
                    0x07
                } else {
                    0x02
                }));
        }
    }

    #[test]
    fn yielded() {
        let mut y = vec![0x00, 33];
        y.extend_from_slice(&[2; 33]);
        y.extend_from_slice(&[0x30, 0x01, 0x01]);
        assert!(matches!(
            parse_yielded(&y).unwrap(),
            PartialSignature::Ecdsa { input: 0, .. }
        ));
        let mut y = vec![0x01, 32];
        y.extend_from_slice(&[2; 32]);
        y.extend_from_slice(&[9; 64]);
        assert!(matches!(
            parse_yielded(&y).unwrap(),
            PartialSignature::Schnorr {
                input: 1,
                leaf_hash: None,
                ..
            }
        ));
    }
}
