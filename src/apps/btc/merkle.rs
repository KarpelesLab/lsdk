//! Merkle trees and the client command interpreter of the Bitcoin app.
//!
//! The app does not receive large data structures (wallet policies, PSBT
//! maps, messages) directly: it receives commitments (merkle roots) and asks
//! the client for the pieces it needs through "client commands" sent with
//! status `0xE000`. Port of Ledger's reference client (Apache-2.0).

use purecrypto::hash::sha256;

use super::varint;
use crate::error::{Error, Result};

fn hash(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// `sha256(0x00 || data)`
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.push(0);
    v.extend_from_slice(data);
    hash(&v)
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(65);
    v.push(1);
    v.extend_from_slice(l);
    v.extend_from_slice(r);
    hash(&v)
}

/// Left subtree size: largest power of two strictly less than `n`.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut p = 1;
    while p * 2 < n {
        p *= 2;
    }
    p
}

/// A merkle tree over pre-hashed leaves.
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        let root = if leaves.is_empty() { [0u8; 32] } else { Self::root_of(&leaves) };
        Self { leaves, root }
    }

    fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let l = split(leaves.len());
        node_hash(&Self::root_of(&leaves[..l]), &Self::root_of(&leaves[l..]))
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Proof for leaf `index`, from the leaf level up.
    pub fn proof(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut out = Vec::new();
        Self::proof_of(&self.leaves, index, &mut out);
        Some(out)
    }

    fn proof_of(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
        if leaves.len() == 1 {
            return;
        }
        let l = split(leaves.len());
        if index < l {
            Self::proof_of(&leaves[..l], index, out);
            out.push(Self::root_of(&leaves[l..]));
        } else {
            Self::proof_of(&leaves[l..], index - l, out);
            out.push(Self::root_of(&leaves[..l]));
        }
    }
}

/// Commitment of a key/value map: `varint(n) || keys_root || values_root`.
pub fn map_commitment(map: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = map.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let keys = MerkleTree::new(sorted.iter().map(|(k, _)| leaf_hash(k)).collect());
    let values = MerkleTree::new(sorted.iter().map(|(_, v)| leaf_hash(v)).collect());
    let mut out = varint::encode(sorted.len() as u64);
    out.extend_from_slice(keys.root());
    out.extend_from_slice(values.root());
    out
}

const CCMD_YIELD: u8 = 0x10;
const CCMD_GET_PREIMAGE: u8 = 0x40;
const CCMD_GET_MERKLE_LEAF_PROOF: u8 = 0x41;
const CCMD_GET_MERKLE_LEAF_INDEX: u8 = 0x42;
const CCMD_GET_MORE_ELEMENTS: u8 = 0xa0;

/// Answers the client commands of the app.
#[derive(Default)]
pub struct Interpreter {
    yielded: Vec<Vec<u8>>,
    queue: Vec<Vec<u8>>,
    preimages: Vec<([u8; 32], Vec<u8>)>,
    trees: Vec<MerkleTree>,
}

fn bad(msg: &str) -> Error {
    Error::App(format!("bitcoin client command: {msg}"))
}

impl Interpreter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_preimage(&mut self, data: Vec<u8>) {
        self.preimages.push((hash(&data), data));
    }

    /// Register a list (as a merkle tree of `0x00 || element`), returns its root.
    pub fn add_list<E: AsRef<[u8]>>(&mut self, elements: &[E]) -> [u8; 32] {
        let mut leaves = Vec::with_capacity(elements.len());
        for e in elements {
            let mut pre = vec![0u8];
            pre.extend_from_slice(e.as_ref());
            let h = hash(&pre);
            self.preimages.push((h, pre));
            leaves.push(h);
        }
        let tree = MerkleTree::new(leaves);
        let root = *tree.root();
        self.trees.push(tree);
        root
    }

    /// Register a key/value map (sorted keys list + values list).
    pub fn add_map(&mut self, map: &[(Vec<u8>, Vec<u8>)]) {
        let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = map.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let keys: Vec<&[u8]> = sorted.iter().map(|(k, _)| k.as_slice()).collect();
        let values: Vec<&[u8]> = sorted.iter().map(|(_, v)| v.as_slice()).collect();
        self.add_list(&keys);
        self.add_list(&values);
    }

    /// Everything yielded by the app.
    pub fn into_yielded(self) -> Vec<Vec<u8>> {
        self.yielded
    }

    /// Execute one client command, returning the response to send back.
    pub fn execute(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        let (&code, req) = cmd.split_first().ok_or_else(|| bad("empty"))?;
        match code {
            CCMD_YIELD => {
                self.yielded.push(req.to_vec());
                Ok(Vec::new())
            }
            CCMD_GET_PREIMAGE => {
                if req.len() != 33 || req[0] != 0 {
                    return Err(bad("unsupported GET_PREIMAGE"));
                }
                let (_, pre) = self
                    .preimages
                    .iter()
                    .find(|(h, _)| h[..] == req[1..])
                    .ok_or_else(|| bad("unknown preimage"))?;
                let len = varint::encode(pre.len() as u64);
                let max = 255 - len.len() - 1;
                let n = pre.len().min(max);
                for b in &pre[n..] {
                    self.queue.push(vec![*b]);
                }
                let mut out = len;
                out.push(n as u8);
                out.extend_from_slice(&pre[..n]);
                Ok(out)
            }
            CCMD_GET_MERKLE_LEAF_PROOF => {
                if !self.queue.is_empty() {
                    return Err(bad("queue not empty"));
                }
                if req.len() < 34 {
                    return Err(bad("short GET_MERKLE_LEAF_PROOF"));
                }
                let root = &req[..32];
                let (size, n) = varint::decode(&req[32..]).ok_or_else(|| bad("bad varint"))?;
                let (index, _) = varint::decode(&req[32 + n..]).ok_or_else(|| bad("bad varint"))?;
                let tree = self.trees.iter().find(|t| t.root()[..] == *root).ok_or_else(|| bad("unknown root"))?;
                if index >= size || size != tree.len() as u64 {
                    return Err(bad("invalid index or size"));
                }
                let proof = tree.proof(index as usize).ok_or_else(|| bad("invalid index"))?;
                let mut out = tree.leaves[index as usize].to_vec();
                out.push(proof.len() as u8);
                let first = proof.len().min(6);
                out.push(first as u8);
                for p in &proof[..first] {
                    out.extend_from_slice(p);
                }
                for p in &proof[first..] {
                    self.queue.push(p.to_vec());
                }
                Ok(out)
            }
            CCMD_GET_MERKLE_LEAF_INDEX => {
                if req.len() < 64 {
                    return Err(bad("short GET_MERKLE_LEAF_INDEX"));
                }
                let tree = self.trees.iter().find(|t| t.root()[..] == req[..32]).ok_or_else(|| bad("unknown root"))?;
                let idx = tree.leaves.iter().position(|l| l[..] == req[32..64]).ok_or_else(|| bad("unknown leaf"))?;
                let mut out = vec![1u8];
                out.extend(varint::encode(idx as u64));
                Ok(out)
            }
            CCMD_GET_MORE_ELEMENTS => {
                if self.queue.is_empty() {
                    return Err(bad("queue empty"));
                }
                let el_len = self.queue[0].len();
                if self.queue.iter().any(|e| e.len() != el_len) {
                    return Err(bad("mixed element sizes"));
                }
                let n = (253 / el_len.max(1)).min(self.queue.len());
                let mut out = vec![n as u8, el_len as u8];
                for e in self.queue.drain(..n) {
                    out.extend_from_slice(&e);
                }
                Ok(out)
            }
            c => Err(bad(&format!("unknown command 0x{c:02x}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs() {
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let t = MerkleTree::new(leaves.clone());
        for i in 0..5 {
            // Recompute the root from each proof.
            let proof = t.proof(i).unwrap();
            let (mut lo, mut hi, mut idx) = (0usize, 5usize, i);
            // Walk down to compute the expected sibling sequence.
            let mut path = Vec::new();
            while hi - lo > 1 {
                let l = split(hi - lo);
                let left = idx < l;
                path.push(left);
                if left {
                    hi = lo + l;
                } else {
                    lo += l;
                    idx -= l;
                }
            }
            let mut h = leaves[i];
            for (sib, left) in proof.iter().zip(path.iter().rev()) {
                h = if *left { node_hash(&h, sib) } else { node_hash(sib, &h) };
            }
            assert_eq!(&h, t.root());
        }
    }
}
